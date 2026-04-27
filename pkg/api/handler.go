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
	s.mux.HandleFunc("POST /v1/statements", s.handleStatements)
	s.mux.HandleFunc("GET /v1/stats", s.handleStats)
	s.mux.HandleFunc("POST /v1/analyze", s.handleAnalyze)
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

// statementsRequest is the v0.4.0 unified VEX statement query body.
//
// CVEs is required (≥1). Every other field is an optional filter; an empty
// slice (or empty Since) means "no filter on this dimension." Filter
// semantics: AND across populated dimensions, IN within each.
//
// Products, when present, runs through the resolver — alias expansion +
// CPE-prefix matching — and the OpenVEX encoder echoes the user's input
// PURLs into products[] so Trivy can match them. Without Products the
// encoder falls back to each statement's stored product_id, which may be
// a CPE for OVAL-derived rows.
type statementsRequest struct {
	CVEs           []string `json:"cves"`
	Products       []string `json:"products,omitempty"`
	Vendors        []string `json:"vendors,omitempty"`
	SourceFormats  []string `json:"source_formats,omitempty"`
	Statuses       []string `json:"statuses,omitempty"`
	Justifications []string `json:"justifications,omitempty"`
	Since          string   `json:"since,omitempty"`
}

const maxStatementsItems = 10000

func (s *Server) handleStatements(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > 1<<20 { // 1MB
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}

	var req statementsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if len(req.CVEs) == 0 {
		writeError(w, http.StatusBadRequest, "cves is required (at least one CVE)")
		return
	}
	if len(req.CVEs) > maxStatementsItems || len(req.Products) > maxStatementsItems {
		writeError(w, http.StatusBadRequest, "too many items (max 10000 per array)")
		return
	}

	// Resolve user-supplied products into candidate base IDs only when the
	// caller provided a Products filter. With no Products, the query runs
	// without a base_id constraint and the encoder falls back to each
	// statement's own ProductID for the response's products[] field.
	var baseToReason map[string]string
	var baseToInputs map[string][]string
	var bases []string
	if len(req.Products) > 0 {
		baseToReason, baseToInputs = s.expandProducts(req.Products)
		bases = make([]string, 0, len(baseToReason))
		for b := range baseToReason {
			bases = append(bases, b)
		}
	}

	stmts, err := s.db.QueryStatements(db.QueryFilters{
		CVEs:           req.CVEs,
		ProductBaseIDs: bases,
		Vendors:        req.Vendors,
		SourceFormats:  req.SourceFormats,
		Statuses:       req.Statuses,
		Justifications: req.Justifications,
		Since:          req.Since,
	})
	if err != nil {
		slog.Error("statements query failed", "error", err)
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}

	// OpenVEX 0.2.0 schema requires statements: minItems 1. 204 on empty
	// keeps the response schema-valid.
	if len(stmts) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	doc := openvex.Encode(stmts, baseToInputs, baseToReason)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		slog.Error("openvex encode failed", "error", err)
	}
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
