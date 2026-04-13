package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/getreeldev/reel-vex/pkg/db"
)

// Server is the HTTP API server.
type Server struct {
	db     *db.DB
	mux    *http.ServeMux
	ingest *IngestRunner
}

// NewServer creates a new API server.
// ingest may be nil if running without ingest support.
func NewServer(database *db.DB, ingest *IngestRunner) *Server {
	s := &Server{
		db:     database,
		mux:    http.NewServeMux(),
		ingest: ingest,
	}
	s.mux.HandleFunc("GET /v1/cve/{id}", s.handleCVE)
	s.mux.HandleFunc("POST /v1/resolve", s.handleResolve)
	s.mux.HandleFunc("GET /v1/stats", s.handleStats)
	s.mux.HandleFunc("POST /v1/sbom", s.handleSBOM)
	s.mux.HandleFunc("GET /v1/ingest", s.handleIngestStatus)
	s.mux.HandleFunc("POST /v1/ingest", s.handleIngestTrigger)
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	s.mux.ServeHTTP(w, r)
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

	writeStatements(w, stmts)
}

type resolveRequest struct {
	Products []string `json:"products"`
	CVEs     []string `json:"cves"`
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

	stmts, err := s.db.QueryResolve(req.CVEs, req.Products)
	if err != nil {
		slog.Error("resolve failed", "error", err)
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}

	writeStatements(w, stmts)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.db.Stats()
	if err != nil {
		slog.Error("stats failed", "error", err)
		writeError(w, http.StatusInternalServerError, "stats failed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (s *Server) handleIngestStatus(w http.ResponseWriter, r *http.Request) {
	if s.ingest == nil {
		writeError(w, http.StatusNotFound, "ingest not configured")
		return
	}
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
	IDType        string `json:"id_type"`
	Status        string `json:"status"`
	Justification string `json:"justification,omitempty"`
	Updated       string `json:"updated"`
}

func writeStatements(w http.ResponseWriter, stmts []db.Statement) {
	out := statementsResponse{
		Statements: make([]statementJSON, len(stmts)),
	}
	for i, s := range stmts {
		out.Statements[i] = statementJSON{
			Vendor:        s.Vendor,
			CVE:           s.CVE,
			ProductID:     s.ProductID,
			IDType:        s.IDType,
			Status:        s.Status,
			Justification: s.Justification,
			Updated:       s.Updated,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(errorResponse{Error: msg})
}
