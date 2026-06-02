package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"

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
	// (/v1/analyze, /v1/statements). Default 10MB; override with
	// SetSBOMMaxBytes (wired from the -sbom-max-mb server flag).
	sbomMaxBytes int64
	// statementsMax caps the number of statements /v1/statements returns.
	// It mainly bounds broad mode (product-scoped, no CVE filter), which can
	// match tens of thousands of rows. When the cap is hit the response is
	// truncated and flagged (HTTP 200 + X-Reel-Truncated). Default 50000; 0
	// means unlimited. Wired from the -statements-max server flag.
	statementsMax int
	// version is the server build version, surfaced in /v1/stats. Set via
	// SetVersion (wired from a build-time -ldflags var); empty in dev/CI.
	version string
	// analyzeMaxCVEs caps the distinct CVEs a /v1/analyze request may query
	// before a 400. The CVE-mode query cost is ~linear in CVEs against the full
	// table, so this keeps an accepted analyze under the DB query timeout.
	// Default 500; wired from the -analyze-max-cves flag.
	analyzeMaxCVEs int
}

// NewServer creates a new API server.
// ingest may be nil if running without ingest support.
func NewServer(database *db.DB, ingest *IngestRunner) *Server {
	s := &Server{
		db:             database,
		resolver:       resolver.New(database),
		mux:            http.NewServeMux(),
		ingest:         ingest,
		sbomMaxBytes:   10 << 20, // 10MB default
		statementsMax:  50000,    // broad-mode safety ceiling; -statements-max overrides
		analyzeMaxCVEs: 500,      // analyze CVE-query ceiling; -analyze-max-cves overrides
	}
	s.mux.HandleFunc("POST /v1/statements", s.handleStatements)
	s.mux.HandleFunc("GET /v1/stats", s.handleStats)
	s.mux.HandleFunc("POST /v1/analyze", s.handleAnalyze)
	s.mux.HandleFunc("GET /v1/ingest", s.handleIngestStatus)
	s.mux.HandleFunc("POST /v1/ingest", s.handleIngestTrigger)
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	// gzip is innermost (closest to the mux) so the request-log records the
	// uncompressed payload size — a metric that stays consistent regardless of
	// the client's Accept-Encoding.
	s.handler = gzipResponse(logRequest(s.mux))
	return s
}

// SetSBOMMaxBytes overrides the default 10MB body cap for SBOM-accepting
// endpoints (/v1/analyze, /v1/statements). Production wires this from the
// -sbom-max-mb server flag. n <= 0 is ignored, preserving the default.
func (s *Server) SetSBOMMaxBytes(n int64) {
	if n > 0 {
		s.sbomMaxBytes = n
	}
}

// SetStatementsMax overrides the default 50000 cap on the number of statements
// /v1/statements returns. Production wires this from the -statements-max server
// flag. n == 0 means unlimited; negative is ignored, preserving the default.
func (s *Server) SetStatementsMax(n int) {
	if n >= 0 {
		s.statementsMax = n
	}
}

// SetAnalyzeMaxCVEs overrides the default 500 cap on distinct CVEs a
// /v1/analyze request may query. Production wires this from -analyze-max-cves.
// n <= 0 is ignored, preserving the default.
func (s *Server) SetAnalyzeMaxCVEs(n int) {
	if n > 0 {
		s.analyzeMaxCVEs = n
	}
}

// SetVersion records the server build version, surfaced in /v1/stats. Wired
// from a build-time -ldflags var; empty (omitted) when unset, e.g. dev/CI.
func (s *Server) SetVersion(v string) { s.version = v }

// ServeHTTP implements http.Handler. CORS preflight is short-circuited
// before the logged handler chain so preflight noise doesn't pollute the
// request log.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	// Custom response headers aren't readable by cross-origin JS (e.g. the
	// vex.getreel.dev playground) unless explicitly exposed — only the CORS
	// safelist is. The truncation signal is useless to a browser otherwise.
	w.Header().Set("Access-Control-Expose-Headers", "X-Reel-Truncated, X-Reel-Next-Offset, X-Reel-Converted")

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
	// Scopes opts product-scoped statements (Rancher VEX) into the result by
	// naming the product(s)/image(s) being scanned. Without it — and without an
	// SBOM whose root component supplies the scope — scoped statements are
	// withheld so a verdict scoped to one image can't suppress the same package
	// elsewhere. When an SBOM is supplied, its metadata.component scope is added
	// automatically.
	Scopes []string `json:"scopes,omitempty"`
	Since  string   `json:"since,omitempty"`
	// Limit / Offset paginate the result. Limit is clamped to the server's
	// configured ceiling (-statements-max); Offset skips that many rows. Both
	// mainly matter in broad mode, where the result set can be large.
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
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

	// rootScopes holds the scope identifiers derived from an SBOM's root
	// subject (metadata.component); populated in the SBOM block below.
	var rootScopes []string

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

		// Scope context from the SBOM's root subject (the scanned image/module)
		// — authorises product-scoped statements for this product.
		rootScopes = extractRootScopes(sbom)
	}

	// Broad mode: no CVEs but products/components present → return every vendor
	// statement touching the matched products, with no CVE filter. This is the
	// fetch-once-attach-to-every-scan path: trivy --vex does its own CVE
	// matching against the returned doc, so pre-filtering by CVE is unnecessary
	// and would break caching. CVE-scoped behaviour is unchanged when CVEs are
	// present. Only both-empty is an error.
	broadMode := len(req.CVEs) == 0 && len(req.Products) > 0
	if len(req.CVEs) == 0 && len(req.Products) == 0 {
		writeError(w, http.StatusBadRequest, "one of cves, products, or sbom (with components or vulnerabilities) is required")
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

	offset := req.Offset
	if offset < 0 {
		offset = 0
	}
	// Scope set: SBOM-derived root scope(s) plus any the caller named
	// explicitly (normalised so they match the form stored at ingest).
	scopes := rootScopes
	for _, sc := range req.Scopes {
		if n := csaf.NormalizeScope(sc); n != "" {
			scopes = append(scopes, n)
		}
	}

	filters := db.QueryFilters{
		ProductBaseIDs: bases,
		Vendors:        req.Vendors,
		SourceFormats:  req.SourceFormats,
		Statuses:       req.Statuses,
		Justifications: req.Justifications,
		Scopes:         scopes,
		Since:          req.Since,
		Offset:         offset,
	}
	// CVE filter only when not in broad mode.
	if !broadMode {
		filters.CVEs = req.CVEs
	}

	// Effective row limit: the configured ceiling, optionally lowered by an
	// explicit request limit. We fetch one extra row so we can tell whether the
	// result was truncated without a second COUNT query.
	limit := s.statementsMax
	if req.Limit > 0 && (limit == 0 || req.Limit < limit) {
		limit = req.Limit
	}
	if limit > 0 {
		filters.Limit = limit
		if limit < math.MaxInt {
			filters.Limit = limit + 1 // probe row; guard against limit+1 overflow
		}
	}

	stmts, err := s.db.QueryStatements(filters)
	if err != nil {
		slog.Error("statements query failed", "error", err)
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}

	truncated := false
	if limit > 0 && len(stmts) > limit {
		stmts = stmts[:limit]
		truncated = true
	}

	// OpenVEX 0.2.0 schema requires statements: minItems 1. 204 on empty
	// keeps the response schema-valid.
	if len(stmts) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	doc := openvex.Encode(stmts, baseToInputs, baseToReason)
	w.Header().Set("Content-Type", "application/json")
	// Truncation is signalled out-of-band via headers (not in the OpenVEX body,
	// which must stay schema-valid). Status stays 200: an unsolicited 206 with
	// no Content-Range violates RFC 7233 and can trip strict consumers/proxies
	// (incl. trivy --vex). A dropped statement is a CVE the consumer won't
	// suppress, so X-Reel-Truncated flags incompleteness and X-Reel-Next-Offset
	// lets the caller page the remainder.
	if truncated {
		w.Header().Set("X-Reel-Truncated", "true")
		w.Header().Set("X-Reel-Next-Offset", strconv.Itoa(offset+limit))
	}
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		slog.Error("openvex encode failed", "error", err)
	}
}

// statsResponse is the /v1/stats body: the cached DB counts plus the server
// build version. Embedding promotes Stats' fields, so the shape is unchanged
// except for the added (optional) version.
type statsResponse struct {
	db.Stats
	Version string `json:"version,omitempty"`
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
	json.NewEncoder(w).Encode(statsResponse{Stats: stats, Version: s.version})
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
