package api

import (
	"encoding/json"
	"fmt"
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
	// sbomMaxBytes caps body size on SBOM-accepting endpoints
	// (/v1/analyze, /v1/statements). Default 5MB; override with
	// SetSBOMMaxBytes (wired from the -sbom-max-mb server flag).
	sbomMaxBytes int64
}

// NewServer creates a new API server.
// ingest may be nil if running without ingest support.
func NewServer(database *db.DB, ingest *IngestRunner) *Server {
	s := &Server{
		db:           database,
		resolver:     resolver.New(database),
		mux:          http.NewServeMux(),
		ingest:       ingest,
		sbomMaxBytes: 5 << 20, // 5MB default
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

// SetSBOMMaxBytes overrides the default 5MB body cap for SBOM-accepting
// endpoints (/v1/analyze, /v1/statements). Production wires this from the
// -sbom-max-mb server flag. n <= 0 is ignored, preserving the default.
func (s *Server) SetSBOMMaxBytes(n int64) {
	if n > 0 {
		s.sbomMaxBytes = n
	}
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

// statementsRequest is the unified VEX statement query body.
//
// One of CVEs or SBOM is required. Every other field is an optional filter;
// an empty slice (or empty Since) means "no filter on this dimension."
// Filter semantics: AND across populated dimensions, IN within each.
//
// Products, when present, runs through the resolver — alias expansion +
// CPE-prefix matching — and the OpenVEX encoder echoes the user's input
// PURLs into products[] so Trivy can match them. Without Products the
// encoder falls back to each statement's stored product_id, which may be
// a CPE for OVAL-derived rows.
//
// SBOM, when present, is a CycloneDX 1.4+ document inlined as JSON. The
// CVE list is derived from .vulnerabilities[].id, the product list from
// .components[].purl / .components[].cpe. SBOM-derived sets are merged
// (union) with any explicit CVEs/Products the caller also passed.
type statementsRequest struct {
	CVEs           []string        `json:"cves,omitempty"`
	Products       []string        `json:"products,omitempty"`
	SBOM           json.RawMessage `json:"sbom,omitempty"`
	Vendors        []string        `json:"vendors,omitempty"`
	SourceFormats  []string        `json:"source_formats,omitempty"`
	Statuses       []string        `json:"statuses,omitempty"`
	Justifications []string        `json:"justifications,omitempty"`
	Since          string          `json:"since,omitempty"`
}

const maxStatementsItems = 10000

func (s *Server) handleStatements(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > s.sbomMaxBytes {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("request body too large (max %dMB)", s.sbomMaxBytes>>20))
		return
	}

	var req statementsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, s.sbomMaxBytes)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// SBOM input — derive CVEs and products from CycloneDX, union with any
	// explicit fields the caller also passed.
	if len(req.SBOM) > 0 && string(req.SBOM) != "null" {
		var sbom map[string]any
		if err := json.Unmarshal(req.SBOM, &sbom); err != nil {
			writeError(w, http.StatusBadRequest, "invalid sbom JSON")
			return
		}
		components := extractComponents(sbom)
		vulns := extractVulnerabilities(sbom)
		if len(components) > maxSBOMComponents {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("too many components (max %d)", maxSBOMComponents))
			return
		}
		if len(vulns) > maxSBOMVulns {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("too many vulnerabilities (max %d)", maxSBOMVulns))
			return
		}
		cveSet := make(map[string]bool, len(req.CVEs)+len(vulns))
		for _, c := range req.CVEs {
			cveSet[c] = true
		}
		for _, c := range vulns {
			cveSet[c] = true
		}
		purlSet := make(map[string]bool, len(req.Products)+len(components)*2)
		for _, p := range req.Products {
			purlSet[p] = true
		}
		for _, ids := range components {
			for _, id := range ids {
				purlSet[id] = true
			}
		}
		req.CVEs = req.CVEs[:0]
		for c := range cveSet {
			req.CVEs = append(req.CVEs, c)
		}
		req.Products = req.Products[:0]
		for p := range purlSet {
			req.Products = append(req.Products, p)
		}
	}

	if len(req.CVEs) == 0 {
		writeError(w, http.StatusBadRequest, "one of cves or sbom (with vulnerabilities) is required")
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
