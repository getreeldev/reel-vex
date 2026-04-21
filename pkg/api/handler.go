package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/getreeldev/reel-vex/pkg/csaf"
	"github.com/getreeldev/reel-vex/pkg/db"
	"github.com/getreeldev/reel-vex/pkg/openvex"
	"github.com/getreeldev/reel-vex/pkg/resolver"
)

// Cache-Control values for GET endpoints.
//
// VEX data only changes when the daily ingest runs, so stale-while-revalidate
// is set aggressively on per-CVE responses — browsers can serve a slightly
// stale answer for up to 24h while refreshing in the background. Stats are
// re-checked more often because the counters tick up during ingest.
const (
	cacheCVE   = "public, max-age=600, stale-while-revalidate=86400"
	cacheStats = "public, max-age=60, stale-while-revalidate=86400"
	cacheNone  = "no-cache"
)

// setCacheControl is a one-line helper to keep handlers readable and to make
// the TTL constants easy to grep / tune from a single place.
func setCacheControl(w http.ResponseWriter, value string) {
	w.Header().Set("Cache-Control", value)
}

// Server is the HTTP API server.
type Server struct {
	db       *db.DB
	resolver *resolver.Resolver
	mux      *http.ServeMux
	// handler is the mux wrapped with the request-log middleware. All non-
	// CORS-preflight requests flow through it so every handled request
	// produces one structured "api_request" slog line.
	handler http.Handler
	ingest  *IngestRunner
}

// NewServer creates a new API server.
// ingest may be nil if running without ingest support.
func NewServer(database *db.DB, ingest *IngestRunner) *Server {
	s := &Server{
		db:       database,
		resolver: resolver.New(database),
		mux:      http.NewServeMux(),
		ingest:   ingest,
	}
	s.mux.HandleFunc("GET /v1/cve/{id}", s.handleCVE)
	s.mux.HandleFunc("GET /v1/cve/{id}/summary", s.handleCVESummary)
	s.mux.HandleFunc("POST /v1/resolve", s.handleResolve)
	s.mux.HandleFunc("GET /v1/stats", s.handleStats)
	s.mux.HandleFunc("POST /v1/sbom", s.handleSBOM)
	s.mux.HandleFunc("GET /v1/ingest", s.handleIngestStatus)
	s.mux.HandleFunc("POST /v1/ingest", s.handleIngestTrigger)
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.handler = logRequest(s.mux)
	return s
}

// ServeHTTP implements http.Handler. CORS preflight is short-circuited
// before the logged handler chain so preflight noise doesn't pollute the
// request log.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	s.handler.ServeHTTP(w, r)
}

func (s *Server) handleCVE(w http.ResponseWriter, r *http.Request) {
	cve := r.PathValue("id")
	if cve == "" {
		writeError(w, http.StatusBadRequest, "missing CVE ID")
		return
	}

	stmts, err := s.db.QueryByCVE(cve)
	if err != nil {
		slog.Error("query failed", "cve", cve, "error", err)
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}

	setCacheControl(w, cacheCVE)
	writeStatements(w, stmts)
}

// cveSummary is the aggregated view of all VEX statements for a single CVE.
// Useful for scripting and dashboards that want counts instead of the full list.
type cveSummary struct {
	CVE      string         `json:"cve"`
	Total    int            `json:"total"`
	ByStatus map[string]int `json:"by_status"`
	Vendors  []string       `json:"vendors"`
}

func (s *Server) handleCVESummary(w http.ResponseWriter, r *http.Request) {
	cve := r.PathValue("id")
	if cve == "" {
		writeError(w, http.StatusBadRequest, "missing CVE ID")
		return
	}

	stmts, err := s.db.QueryByCVE(cve)
	if err != nil {
		slog.Error("summary query failed", "cve", cve, "error", err)
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}

	byStatus := make(map[string]int)
	vendorSet := make(map[string]struct{})
	for _, stmt := range stmts {
		byStatus[stmt.Status]++
		vendorSet[stmt.Vendor] = struct{}{}
	}
	vendors := make([]string, 0, len(vendorSet))
	for v := range vendorSet {
		vendors = append(vendors, v)
	}

	out := cveSummary{
		CVE:      cve,
		Total:    len(stmts),
		ByStatus: byStatus,
		Vendors:  vendors,
	}

	setCacheControl(w, cacheCVE)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

type resolveRequest struct {
	Products []string `json:"products"`
	CVEs     []string `json:"cves"`
	// SourceFormats, when non-empty, restricts matches to statements from
	// those upstream formats ("csaf", "oval"). Empty = all formats.
	SourceFormats []string `json:"source_formats,omitempty"`
	// Format selects the response shape. "" (default) returns native
	// reel-vex JSON with match_reason + source_format. "openvex" returns
	// an OpenVEX 0.2.0 document for consumers like vexctl and Trivy.
	Format string `json:"format,omitempty"`
}

const maxResolveItems = 10000

func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > 1<<20 { // 1MB
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}

	var req resolveRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if len(req.CVEs) == 0 || len(req.Products) == 0 {
		writeError(w, http.StatusBadRequest, "cves and products are required")
		return
	}
	if len(req.CVEs) > maxResolveItems || len(req.Products) > maxResolveItems {
		writeError(w, http.StatusBadRequest, "too many items (max 10000 each)")
		return
	}
	if req.Format != "" && req.Format != "openvex" {
		writeError(w, http.StatusBadRequest, `invalid format (must be "" or "openvex")`)
		return
	}

	// Normalize user-provided PURLs into base form and expand CPE variants
	// into their RedHat-documented 5-part prefix, tagging each candidate with
	// the match_reason it would carry if a statement matches. baseToInputs
	// tracks which user inputs (in base form) produced each candidate — the
	// OpenVEX emitter echoes those inputs into products[] so Trivy sees
	// PURLs it can actually match when a CPE-keyed statement is returned.
	baseToReason, baseToInputs := s.expandProducts(req.Products)
	bases := make([]string, 0, len(baseToReason))
	for b := range baseToReason {
		bases = append(bases, b)
	}

	stmts, err := s.db.QueryResolve(req.CVEs, bases, req.SourceFormats)
	if err != nil {
		slog.Error("resolve failed", "error", err)
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}

	if req.Format == "openvex" {
		// Spec requires statements: minItems 1. 204 signals "query worked,
		// no statements matched" cleanly without emitting an invalid doc.
		if len(stmts) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		doc := openvex.Encode(stmts, baseToInputs, baseToReason)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(doc); err != nil {
			slog.Error("openvex encode failed", "error", err)
		}
		return
	}

	writeStatementsWithMatch(w, stmts, baseToReason)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.db.Stats()
	if err != nil {
		slog.Error("stats failed", "error", err)
		writeError(w, http.StatusInternalServerError, "stats failed")
		return
	}

	setCacheControl(w, cacheStats)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	setCacheControl(w, cacheNone)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (s *Server) handleIngestStatus(w http.ResponseWriter, r *http.Request) {
	if s.ingest == nil {
		writeError(w, http.StatusNotFound, "ingest not configured")
		return
	}
	setCacheControl(w, cacheNone)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.ingest.Status())
}

func (s *Server) handleIngestTrigger(w http.ResponseWriter, r *http.Request) {
	if s.ingest == nil {
		writeError(w, http.StatusNotFound, "ingest not configured")
		return
	}

	if s.ingest.adminToken != "" {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+s.ingest.adminToken {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
	}

	if !s.ingest.TriggerIngest() {
		writeError(w, http.StatusConflict, "ingest already running")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

type statementsResponse struct {
	Statements []statementJSON `json:"statements"`
}

type statementJSON struct {
	Vendor        string `json:"vendor"`
	CVE           string `json:"cve"`
	ProductID     string `json:"product_id"`
	Version       string `json:"version,omitempty"`
	IDType        string `json:"id_type"`
	Status        string `json:"status"`
	Justification string `json:"justification,omitempty"`
	Updated       string `json:"updated"`
	SourceFormat  string `json:"source_format"`
	MatchReason   string `json:"match_reason,omitempty"`
}

// writeStatements serializes statements without a match_reason. Used by
// endpoints that don't do product matching (/v1/cve/{id}).
func writeStatements(w http.ResponseWriter, stmts []db.Statement) {
	writeStatementsWithMatch(w, stmts, nil)
}

// writeStatementsWithMatch serializes statements and, when baseToReason is
// non-nil, tags each row with the match_reason that caused it to be selected.
// Endpoints that do product expansion (/v1/resolve, /v1/sbom) pass the map
// they built during expansion.
func writeStatementsWithMatch(w http.ResponseWriter, stmts []db.Statement, baseToReason map[string]string) {
	out := statementsResponse{
		Statements: make([]statementJSON, len(stmts)),
	}
	for i, s := range stmts {
		row := statementJSON{
			Vendor:        s.Vendor,
			CVE:           s.CVE,
			ProductID:     s.ProductID,
			Version:       s.Version,
			IDType:        s.IDType,
			Status:        s.Status,
			Justification: s.Justification,
			Updated:       s.Updated,
			SourceFormat:  s.SourceFormat,
		}
		if baseToReason != nil {
			row.MatchReason = baseToReason[s.BaseID]
		}
		out.Statements[i] = row
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// expandProducts turns the user-supplied product list into two maps, keyed
// by candidate base identifier:
//
//   - baseToReason: match_reason that would apply if a statement's base_id
//     matches that candidate (first/stronger rule wins on collision).
//   - baseToInputs: the set of user inputs (in base form — stripped of PURL
//     qualifiers and version) that expanded to this candidate. Used by the
//     OpenVEX emitter to echo the user's PURLs into products[] so Trivy
//     can match statements keyed by a different identifier (typically CPE).
//
// Delegates expansion to resolver.Resolver so alias lookups and CPE prefix
// expansion run alongside the direct base.
func (s *Server) expandProducts(products []string) (map[string]string, map[string][]string) {
	baseToReason := make(map[string]string, len(products))
	baseToInputs := make(map[string][]string, len(products))
	seenInput := make(map[string]map[string]bool)

	for _, p := range products {
		inputBase, _ := csaf.SplitPURL(p)
		for _, cand := range s.resolver.Expand(p) {
			if _, exists := baseToReason[cand.ID]; !exists {
				baseToReason[cand.ID] = cand.MatchReason
			}
			if seenInput[cand.ID] == nil {
				seenInput[cand.ID] = make(map[string]bool)
			}
			if !seenInput[cand.ID][inputBase] {
				seenInput[cand.ID][inputBase] = true
				baseToInputs[cand.ID] = append(baseToInputs[cand.ID], inputBase)
			}
		}
	}
	return baseToReason, baseToInputs
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(errorResponse{Error: msg})
}
