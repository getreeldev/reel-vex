package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getreeldev/reel-vex/pkg/csaf"
	"github.com/getreeldev/reel-vex/pkg/db"
	"github.com/getreeldev/reel-vex/pkg/openvex"
)

func setupTestDB(t *testing.T) *db.DB {
	t.Helper()
	path := t.TempDir() + "/test.db"
	database, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	if err := database.UpsertVendor("testvendor", "Test Vendor"); err != nil {
		t.Fatal(err)
	}

	stmts := []db.Statement{
		{Vendor: "testvendor", CVE: "CVE-2024-1234", ProductID: "pkg:rpm/test/openssl@3.0", BaseID: "pkg:rpm/test/openssl", Version: "3.0", IDType: "purl", Status: "not_affected", Justification: "vulnerable_code_not_present", Updated: "2024-07-01T00:00:00Z"},
		{Vendor: "testvendor", CVE: "CVE-2024-1234", ProductID: "cpe:/a:test:openssl:3.0", BaseID: "cpe:/a:test:openssl:3.0", IDType: "cpe", Status: "not_affected", Justification: "vulnerable_code_not_present", Updated: "2024-07-01T00:00:00Z"},
		{Vendor: "testvendor", CVE: "CVE-2024-5678", ProductID: "pkg:rpm/test/nginx@1.25", BaseID: "pkg:rpm/test/nginx", Version: "1.25", IDType: "purl", Status: "fixed", Updated: "2024-08-01T00:00:00Z"},
	}
	if err := database.BulkInsert(stmts); err != nil {
		t.Fatal(err)
	}
	return database
}

// decodeOpenVEX is a test helper that parses an OpenVEX 0.2.0 response body
// into the encoder's Document type, failing the test on any decode error.
func decodeOpenVEX(t *testing.T, w *httptest.ResponseRecorder) openvex.Document {
	t.Helper()
	var doc openvex.Document
	if err := json.NewDecoder(w.Body).Decode(&doc); err != nil {
		t.Fatalf("decode openvex: %v (body: %s)", err, w.Body.String())
	}
	if doc.Context != openvex.Context {
		t.Fatalf("response @context: got %q, want %q", doc.Context, openvex.Context)
	}
	return doc
}

func TestHandleStatements_CVEOnly(t *testing.T) {
	database := setupTestDB(t)
	srv := NewServer(database, nil)

	t.Run("found", func(t *testing.T) {
		body, _ := json.Marshal(statementsRequest{CVEs: []string{"CVE-2024-1234"}})
		req := httptest.NewRequest("POST", "/v1/statements", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		doc := decodeOpenVEX(t, w)
		// CVE-2024-1234 has 2 seeded statements (purl + cpe variants).
		if len(doc.Statements) != 2 {
			t.Fatalf("expected 2 statements, got %d", len(doc.Statements))
		}
	})

	t.Run("not found returns 204", func(t *testing.T) {
		body, _ := json.Marshal(statementsRequest{CVEs: []string{"CVE-9999-0000"}})
		req := httptest.NewRequest("POST", "/v1/statements", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != http.StatusNoContent {
			t.Fatalf("expected 204 on empty CVE, got %d", w.Code)
		}
	})
}

func TestHandleStatements_WithProducts(t *testing.T) {
	database := setupTestDB(t)
	srv := NewServer(database, nil)

	t.Run("match", func(t *testing.T) {
		body, _ := json.Marshal(statementsRequest{
			CVEs:     []string{"CVE-2024-1234"},
			Products: []string{"pkg:rpm/test/openssl@3.0"},
		})
		req := httptest.NewRequest("POST", "/v1/statements", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		doc := decodeOpenVEX(t, w)
		if len(doc.Statements) != 1 {
			t.Fatalf("expected 1 statement, got %d", len(doc.Statements))
		}
		got := doc.Statements[0]
		if got.Status != "not_affected" {
			t.Errorf("status: got %q, want not_affected", got.Status)
		}
		// Provenance lives in status_notes for OpenVEX output.
		if !strings.Contains(got.StatusNotes, "source_format=csaf") {
			t.Errorf("status_notes should carry source_format=csaf, got %q", got.StatusNotes)
		}
		if !strings.Contains(got.StatusNotes, "match_reason=direct") {
			t.Errorf("status_notes should carry match_reason=direct for an exact-base PURL query, got %q", got.StatusNotes)
		}
	})

	t.Run("no match returns 204", func(t *testing.T) {
		body, _ := json.Marshal(statementsRequest{
			CVEs:     []string{"CVE-2024-1234"},
			Products: []string{"pkg:rpm/test/nginx@1.25"},
		})
		req := httptest.NewRequest("POST", "/v1/statements", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != http.StatusNoContent {
			t.Fatalf("expected 204 on no match, got %d", w.Code)
		}
	})
}

func TestHandleStatements_RequiresCVEs(t *testing.T) {
	database := setupTestDB(t)
	srv := NewServer(database, nil)

	t.Run("empty body", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/v1/statements", bytes.NewReader([]byte("{}")))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("products without cves", func(t *testing.T) {
		body, _ := json.Marshal(statementsRequest{Products: []string{"pkg:rpm/test/openssl"}})
		req := httptest.NewRequest("POST", "/v1/statements", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 (cves required), got %d", w.Code)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/v1/statements", bytes.NewReader([]byte("not json")))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})
}

// TestHandleStatements_OldRoutesAre404 is the explicit breaking-change
// regression guard for v0.4.0 — the three endpoints replaced by
// /v1/statements must return 404, not silently route somewhere unexpected.
func TestHandleStatements_OldRoutesAre404(t *testing.T) {
	database := setupTestDB(t)
	srv := NewServer(database, nil)

	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"GET /v1/cve/{id}", "GET", "/v1/cve/CVE-2024-1234"},
		{"GET /v1/cve/{id}/summary", "GET", "/v1/cve/CVE-2024-1234/summary"},
		{"POST /v1/resolve", "POST", "/v1/resolve"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader([]byte(`{}`)))
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)
			if w.Code != http.StatusNotFound {
				t.Fatalf("expected 404 on removed route, got %d", w.Code)
			}
		})
	}
}

// TestHandleStatements_NewFilters verifies the v0.4.0 additional filter
// dimensions (vendors, statuses, justifications, since) all narrow the
// result set as documented.
func TestHandleStatements_NewFilters(t *testing.T) {
	database := setupTestDB(t)
	// Seed extra rows so each filter has something distinguishing to do.
	if err := database.UpsertVendor("vendor2", "Vendor Two"); err != nil {
		t.Fatal(err)
	}
	if err := database.BulkInsert([]db.Statement{
		{Vendor: "vendor2", CVE: "CVE-2024-1234", ProductID: "pkg:rpm/test/openssl@3.0", BaseID: "pkg:rpm/test/openssl", Version: "3.0", IDType: "purl", Status: "affected", Updated: "2026-04-15T00:00:00Z", SourceFormat: "oval"},
	}); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(database, nil)

	post := func(t *testing.T, req statementsRequest) []openvex.Statement {
		t.Helper()
		body, _ := json.Marshal(req)
		r := httptest.NewRequest("POST", "/v1/statements", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		if w.Code == http.StatusNoContent {
			return nil
		}
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		return decodeOpenVEX(t, w).Statements
	}

	t.Run("vendors filter", func(t *testing.T) {
		stmts := post(t, statementsRequest{
			CVEs:    []string{"CVE-2024-1234"},
			Vendors: []string{"vendor2"},
		})
		if len(stmts) != 1 {
			t.Fatalf("expected 1 statement (vendor2 only), got %d", len(stmts))
		}
		if stmts[0].Supplier != "vendor2" {
			t.Errorf("supplier: got %q, want vendor2", stmts[0].Supplier)
		}
	})

	t.Run("statuses filter", func(t *testing.T) {
		stmts := post(t, statementsRequest{
			CVEs:     []string{"CVE-2024-1234"},
			Statuses: []string{"affected"},
		})
		if len(stmts) != 1 {
			t.Fatalf("expected 1 affected statement, got %d", len(stmts))
		}
		if stmts[0].Status != "affected" {
			t.Errorf("status: got %q, want affected", stmts[0].Status)
		}
	})

	t.Run("justifications filter", func(t *testing.T) {
		stmts := post(t, statementsRequest{
			CVEs:           []string{"CVE-2024-1234"},
			Justifications: []string{"vulnerable_code_not_present"},
		})
		// Both seeded testvendor not_affected rows carry that justification;
		// the vendor2 affected row has no justification → excluded.
		if len(stmts) != 2 {
			t.Fatalf("expected 2 statements with that justification, got %d", len(stmts))
		}
	})

	t.Run("since filter", func(t *testing.T) {
		stmts := post(t, statementsRequest{
			CVEs:  []string{"CVE-2024-1234"},
			Since: "2026-01-01T00:00:00Z",
		})
		// vendor2's row updated 2026-04-15 passes; testvendor seed rows from
		// 2024 are excluded.
		if len(stmts) != 1 {
			t.Fatalf("expected 1 since-filtered statement, got %d", len(stmts))
		}
		if stmts[0].Supplier != "vendor2" {
			t.Errorf("expected vendor2 row, got %q", stmts[0].Supplier)
		}
	})

	t.Run("combined filters", func(t *testing.T) {
		// vendors AND statuses combined — restricts to vendor2 + affected.
		stmts := post(t, statementsRequest{
			CVEs:     []string{"CVE-2024-1234"},
			Vendors:  []string{"vendor2"},
			Statuses: []string{"affected"},
		})
		if len(stmts) != 1 {
			t.Fatalf("expected 1 statement, got %d", len(stmts))
		}
	})

	t.Run("source_formats filter (back-compat smoke)", func(t *testing.T) {
		stmts := post(t, statementsRequest{
			CVEs:          []string{"CVE-2024-1234"},
			SourceFormats: []string{"oval"},
		})
		if len(stmts) != 1 {
			t.Fatalf("expected 1 OVAL statement, got %d", len(stmts))
		}
	})
}

func TestHandleStats(t *testing.T) {
	database := setupTestDB(t)
	srv := NewServer(database, nil)

	req := httptest.NewRequest("GET", "/v1/stats", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if hdr := w.Header().Get("Cache-Control"); hdr != cacheStats {
		t.Errorf("Cache-Control: got %q, want %q", hdr, cacheStats)
	}

	var stats db.Stats
	if err := json.NewDecoder(w.Body).Decode(&stats); err != nil {
		t.Fatal(err)
	}
	if stats.Vendors != 1 {
		t.Fatalf("expected 1 vendor, got %d", stats.Vendors)
	}
	if stats.CVEs != 2 {
		t.Fatalf("expected 2 CVEs, got %d", stats.CVEs)
	}
	if stats.Statements != 3 {
		t.Fatalf("expected 3 statements, got %d", stats.Statements)
	}
	if stats.Aliases != 0 {
		t.Fatalf("expected 0 aliases on a fresh DB, got %d", stats.Aliases)
	}
}

// TestHandleStats_WithAliases verifies the Aliases counter surfaces in the
// JSON response. Surfacing this on the stats page is what lets the website
// show "Product mappings" alongside CVEs and statements.
func TestHandleStats_WithAliases(t *testing.T) {
	database := setupTestDB(t)
	if err := database.BulkUpsertAliases([]db.Alias{
		{Vendor: "redhat", SourceNS: "repository_id", SourceID: "rhel-8-for-x86_64-appstream-rpms", TargetNS: "cpe", TargetID: "cpe:/a:redhat:enterprise_linux:8::appstream", Updated: "2024-01-05T00:00:00Z"},
		{Vendor: "redhat", SourceNS: "repository_id", SourceID: "rhel-8-for-x86_64-baseos-rpms", TargetNS: "cpe", TargetID: "cpe:/o:redhat:enterprise_linux:8::baseos", Updated: "2024-01-05T00:00:00Z"},
	}); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(database, nil)

	req := httptest.NewRequest("GET", "/v1/stats", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var stats db.Stats
	if err := json.NewDecoder(w.Body).Decode(&stats); err != nil {
		t.Fatal(err)
	}
	if stats.Aliases != 2 {
		t.Errorf("expected 2 aliases, got %d", stats.Aliases)
	}
}

func TestHandleHealth(t *testing.T) {
	database := setupTestDB(t)
	srv := NewServer(database, nil)

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if hdr := w.Header().Get("Cache-Control"); hdr != cacheNone {
		t.Errorf("Cache-Control: got %q, want %q", hdr, cacheNone)
	}
}

// TestPOSTEndpointsHaveNoCacheControl is a regression guard. POST endpoints
// (resolve, analyze, ingest trigger) must never advertise caching — their
// responses are derived from the request body or change global state.
func TestPOSTEndpointsHaveNoCacheControl(t *testing.T) {
	database := setupTestDB(t)
	runner := NewIngestRunner(func() error { return nil }, time.Hour, "")
	srv := NewServer(database, runner)

	cases := []struct {
		name string
		req  *http.Request
	}{
		{
			"POST /v1/statements",
			httptest.NewRequest("POST", "/v1/statements", bytes.NewReader([]byte(`{"cves":["CVE-2024-1234"],"products":["pkg:rpm/test/openssl"]}`))),
		},
		{
			"POST /v1/analyze",
			httptest.NewRequest("POST", "/v1/analyze", bytes.NewReader([]byte(`{"sbom":{"bomFormat":"CycloneDX","specVersion":"1.5"}}`))),
		},
		{
			"POST /v1/ingest",
			httptest.NewRequest("POST", "/v1/ingest", nil),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, tc.req)
			if hdr := w.Header().Get("Cache-Control"); hdr != "" {
				t.Errorf("Cache-Control on %s: got %q, want empty", tc.name, hdr)
			}
		})
	}
}

func TestCORS(t *testing.T) {
	database := setupTestDB(t)
	srv := NewServer(database, nil)

	req := httptest.NewRequest("OPTIONS", "/v1/stats", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("missing CORS header")
	}
}

// TestHandleAnalyze_SBOMOnly covers the analyze endpoint with only an SBOM
// in the request — the v0.3.0 successor to /v1/sbom. Output is annotated
// CycloneDX, byte-stable vs the prior /v1/sbom behaviour.
func TestHandleAnalyze_SBOMOnly(t *testing.T) {
	database := setupTestDB(t)
	srv := NewServer(database, nil)

	postSBOM := func(t *testing.T, sbom map[string]any) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"sbom": sbom})
		req := httptest.NewRequest("POST", "/v1/analyze", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		return w
	}

	t.Run("annotates matching vulnerabilities", func(t *testing.T) {
		w := postSBOM(t, map[string]any{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.5",
			"components": []any{
				map[string]any{
					"type": "library",
					"name": "openssl",
					"purl": "pkg:rpm/test/openssl@3.0",
				},
			},
			"vulnerabilities": []any{
				map[string]any{"id": "CVE-2024-1234"},
			},
		})

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}

		var result map[string]any
		if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}

		vulns := result["vulnerabilities"].([]any)
		vuln := vulns[0].(map[string]any)
		analysis, ok := vuln["analysis"].(map[string]any)
		if !ok {
			t.Fatal("expected analysis field on vulnerability")
		}
		if analysis["state"] != "not_affected" {
			t.Fatalf("expected not_affected, got %v", analysis["state"])
		}
		if analysis["justification"] != "code_not_present" {
			t.Fatalf("expected code_not_present, got %v", analysis["justification"])
		}
	})

	t.Run("no matching CVEs returns SBOM as-is", func(t *testing.T) {
		w := postSBOM(t, map[string]any{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.5",
			"components": []any{
				map[string]any{"type": "library", "name": "something", "purl": "pkg:npm/something@1.0"},
			},
			"vulnerabilities": []any{
				map[string]any{"id": "CVE-9999-0000"},
			},
		})
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var result map[string]any
		json.NewDecoder(w.Body).Decode(&result)
		vulns := result["vulnerabilities"].([]any)
		vuln := vulns[0].(map[string]any)
		if _, ok := vuln["analysis"]; ok {
			t.Fatal("expected no analysis field when no match")
		}
	})

	t.Run("no vulnerabilities returns SBOM as-is", func(t *testing.T) {
		w := postSBOM(t, map[string]any{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.5",
			"components": []any{
				map[string]any{"type": "library", "purl": "pkg:npm/foo@1.0"},
			},
		})
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("no components returns SBOM as-is", func(t *testing.T) {
		w := postSBOM(t, map[string]any{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.5",
			"vulnerabilities": []any{
				map[string]any{"id": "CVE-2024-1234"},
			},
		})
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("cpe matching works", func(t *testing.T) {
		w := postSBOM(t, map[string]any{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.5",
			"components": []any{
				map[string]any{"type": "library", "name": "openssl", "cpe": "cpe:/a:test:openssl:3.0"},
			},
			"vulnerabilities": []any{
				map[string]any{"id": "CVE-2024-1234"},
			},
		})
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var result map[string]any
		json.NewDecoder(w.Body).Decode(&result)
		vulns := result["vulnerabilities"].([]any)
		vuln := vulns[0].(map[string]any)
		if _, ok := vuln["analysis"]; !ok {
			t.Fatal("expected analysis field for CPE match")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/v1/analyze", bytes.NewReader([]byte("not json")))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("picks best status across vendors", func(t *testing.T) {
		// Add a second vendor with "affected" status for the same CVE+product.
		database.UpsertVendor("vendor2", "Vendor Two")
		database.BulkInsert([]db.Statement{
			{Vendor: "vendor2", CVE: "CVE-2024-1234", ProductID: "pkg:rpm/test/openssl@3.0", BaseID: "pkg:rpm/test/openssl", Version: "3.0", IDType: "purl", Status: "affected", Updated: "2024-07-01T00:00:00Z"},
		})

		w := postSBOM(t, map[string]any{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.5",
			"components": []any{
				map[string]any{"type": "library", "purl": "pkg:rpm/test/openssl@3.0"},
			},
			"vulnerabilities": []any{
				map[string]any{"id": "CVE-2024-1234"},
			},
		})
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var result map[string]any
		json.NewDecoder(w.Body).Decode(&result)
		vulns := result["vulnerabilities"].([]any)
		vuln := vulns[0].(map[string]any)
		analysis := vuln["analysis"].(map[string]any)

		// not_affected (priority 4) should win over affected (priority 1).
		if analysis["state"] != "not_affected" {
			t.Fatalf("expected not_affected (highest priority), got %v", analysis["state"])
		}

		detail := analysis["detail"].(string)
		if !strings.Contains(detail, "testvendor") || !strings.Contains(detail, "vendor2") {
			t.Fatalf("expected both vendors in detail, got: %s", detail)
		}
	})
}

// TestHandleAnalyze_CustomerVEXOnly covers the customer-VEX-only flow:
// inbound OpenVEX 0.2.0; outbound merged OpenVEX with from_customer_vex
// match_reason carried in status_notes. With no SBOM, no vendor data is
// queried for vendor-only base_ids — only customer-asserted base_ids.
func TestHandleAnalyze_CustomerVEXOnly(t *testing.T) {
	database := setupTestDB(t)
	srv := NewServer(database, nil)

	customerDoc := map[string]any{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"statements": []any{
			map[string]any{
				"vulnerability": map[string]any{"name": "CVE-2024-9999"},
				"products":      []any{map[string]any{"@id": "pkg:rpm/acme/widget"}},
				"status":        "affected",
				"supplier":      "acme",
				"timestamp":     "2026-04-20T00:00:00Z",
			},
		},
	}
	body, _ := json.Marshal(map[string]any{"customer_vex": []any{customerDoc}})
	req := httptest.NewRequest("POST", "/v1/analyze", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	doc := decodeOpenVEX(t, w)
	if len(doc.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(doc.Statements))
	}
	got := doc.Statements[0]
	if got.Status != "affected" {
		t.Errorf("status: got %q, want affected", got.Status)
	}
	if got.Supplier != "acme" {
		t.Errorf("supplier should flow through verbatim: got %q", got.Supplier)
	}
	if !strings.Contains(got.StatusNotes, "match_reason=from_customer_vex") {
		t.Errorf("status_notes should carry match_reason=from_customer_vex, got %q", got.StatusNotes)
	}
	if strings.Contains(got.StatusNotes, "source_format=") {
		t.Errorf("customer rows should not carry source_format= prefix, got %q", got.StatusNotes)
	}
}

// TestHandleAnalyze_CustomerOverrideInSBOM covers the headline override case:
// vendor says CVE-X is not_affected on a CPE base; customer says affected on
// a PURL base. Without the customerCVEs override gate the vendor's higher
// priority would beat the customer in the per-CVE rollup. With the gate,
// only the customer's status is reflected.
func TestHandleAnalyze_CustomerOverrideInSBOM(t *testing.T) {
	dbPath := t.TempDir() + "/override.db"
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := database.UpsertVendor("redhat", "Red Hat"); err != nil {
		t.Fatal(err)
	}
	// Vendor row: CVE-2021-44228 not_affected on the CPE (matched via alias).
	if err := database.BulkInsert([]db.Statement{{
		Vendor:        "redhat",
		CVE:           "CVE-2021-44228",
		ProductID:     "cpe:/a:redhat:enterprise_linux:8::appstream",
		BaseID:        "cpe:/a:redhat:enterprise_linux:8::appstream",
		IDType:        "cpe",
		Status:        "not_affected",
		Justification: "vulnerable_code_not_present",
		Updated:       "2024-01-05T00:00:00Z",
		SourceFormat:  "csaf",
	}}); err != nil {
		t.Fatal(err)
	}
	// Alias so the SBOM's PURL component expands to the CPE.
	if err := database.BulkUpsertAliases([]db.Alias{{
		Vendor:   "redhat",
		SourceNS: "repository_id",
		SourceID: "rhel-8-for-x86_64-appstream-rpms",
		TargetNS: "cpe",
		TargetID: "cpe:/a:redhat:enterprise_linux:8::appstream",
		Updated:  "2024-01-05T00:00:00Z",
	}}); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(database, nil)

	sbom := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"components": []any{
			map[string]any{
				"type": "library",
				"name": "log4j",
				"purl": "pkg:rpm/redhat/log4j@2.14.0?repository_id=rhel-8-for-x86_64-appstream-rpms",
			},
		},
		"vulnerabilities": []any{
			map[string]any{"id": "CVE-2021-44228"},
		},
	}
	customerDoc := map[string]any{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"statements": []any{
			map[string]any{
				"vulnerability": map[string]any{"name": "CVE-2021-44228"},
				"products":      []any{map[string]any{"@id": "pkg:rpm/redhat/log4j"}},
				"status":        "affected",
				"supplier":      "acme-internal",
				"timestamp":     "2026-04-20T00:00:00Z",
			},
		},
	}

	body, _ := json.Marshal(map[string]any{
		"sbom":         sbom,
		"customer_vex": []any{customerDoc},
	})
	req := httptest.NewRequest("POST", "/v1/analyze", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var result map[string]any
	json.NewDecoder(w.Body).Decode(&result)
	vulns := result["vulnerabilities"].([]any)
	vuln := vulns[0].(map[string]any)
	analysis, ok := vuln["analysis"].(map[string]any)
	if !ok {
		t.Fatal("expected analysis field on vulnerability")
	}
	// Customer override semantic: customer's "affected" wins despite the
	// higher-priority vendor "not_affected" sitting at a different base_id.
	if analysis["state"] != "exploitable" {
		t.Fatalf("override failed: expected exploitable (from customer affected), got %v — vendor not_affected at a different base_id should not have leaked into the rollup",
			analysis["state"])
	}
	detail := analysis["detail"].(string)
	if !strings.Contains(detail, "acme-internal") {
		t.Errorf("detail should mention customer supplier, got %q", detail)
	}
	// The vendor row should NOT appear in the rollup detail because customer
	// asserted on this CVE.
	if strings.Contains(detail, "redhat") {
		t.Errorf("detail should not mention vendor row when customer overrides on CVE, got %q", detail)
	}
}

func TestHandleAnalyze_RequiresSBOMOrCustomerVEX(t *testing.T) {
	database := setupTestDB(t)
	srv := NewServer(database, nil)

	req := httptest.NewRequest("POST", "/v1/analyze", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when neither sbom nor customer_vex given, got %d", w.Code)
	}
}

func TestHandleAnalyze_MalformedCustomerVEX(t *testing.T) {
	database := setupTestDB(t)
	srv := NewServer(database, nil)

	// Bad @context → 422 (shape violation, not limit overflow).
	bad := `{"customer_vex":[{"@context":"https://wrong.example/","statements":[]}]}`
	req := httptest.NewRequest("POST", "/v1/analyze", bytes.NewReader([]byte(bad)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for shape violation, got %d", w.Code)
	}
}

func TestHandleAnalyze_OldSBOMRouteIs404(t *testing.T) {
	database := setupTestDB(t)
	srv := NewServer(database, nil)

	// /v1/sbom is gone in v0.3.0 — explicit 404 (not silent).
	req := httptest.NewRequest("POST", "/v1/sbom", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for removed /v1/sbom route, got %d", w.Code)
	}
}

func TestHandleIngestStatus(t *testing.T) {
	database := setupTestDB(t)

	t.Run("no runner", func(t *testing.T) {
		srv := NewServer(database, nil)
		req := httptest.NewRequest("GET", "/v1/ingest", nil)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", w.Code)
		}
	})

	t.Run("with runner", func(t *testing.T) {
		runner := NewIngestRunner(func() error { return nil }, time.Hour, "")
		srv := NewServer(database, runner)

		req := httptest.NewRequest("GET", "/v1/ingest", nil)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		if hdr := w.Header().Get("Cache-Control"); hdr != cacheNone {
			t.Errorf("Cache-Control: got %q, want %q", hdr, cacheNone)
		}

		var status IngestStatus
		if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
			t.Fatal(err)
		}
		if status.Running {
			t.Fatal("expected not running")
		}
	})
}

func TestHandleIngestTrigger(t *testing.T) {
	database := setupTestDB(t)

	t.Run("no auth required", func(t *testing.T) {
		called := make(chan struct{}, 1)
		runner := NewIngestRunner(func() error {
			called <- struct{}{}
			return nil
		}, time.Hour, "")
		srv := NewServer(database, runner)

		req := httptest.NewRequest("POST", "/v1/ingest", nil)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != http.StatusAccepted {
			t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
		}

		select {
		case <-called:
		case <-time.After(2 * time.Second):
			t.Fatal("ingest function not called")
		}
	})

	t.Run("auth required and missing", func(t *testing.T) {
		runner := NewIngestRunner(func() error { return nil }, time.Hour, "secret-token")
		srv := NewServer(database, runner)

		req := httptest.NewRequest("POST", "/v1/ingest", nil)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("auth required and wrong", func(t *testing.T) {
		runner := NewIngestRunner(func() error { return nil }, time.Hour, "secret-token")
		srv := NewServer(database, runner)

		req := httptest.NewRequest("POST", "/v1/ingest", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("auth required and correct", func(t *testing.T) {
		called := make(chan struct{}, 1)
		runner := NewIngestRunner(func() error {
			called <- struct{}{}
			return nil
		}, time.Hour, "secret-token")
		srv := NewServer(database, runner)

		req := httptest.NewRequest("POST", "/v1/ingest", nil)
		req.Header.Set("Authorization", "Bearer secret-token")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != http.StatusAccepted {
			t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
		}

		select {
		case <-called:
		case <-time.After(2 * time.Second):
			t.Fatal("ingest function not called")
		}
	})

	t.Run("conflict when already running", func(t *testing.T) {
		started := make(chan struct{})
		block := make(chan struct{})
		runner := NewIngestRunner(func() error {
			close(started)
			<-block
			return nil
		}, time.Hour, "")
		srv := NewServer(database, runner)

		req := httptest.NewRequest("POST", "/v1/ingest", nil)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusAccepted {
			t.Fatalf("expected 202, got %d", w.Code)
		}

		<-started

		req2 := httptest.NewRequest("POST", "/v1/ingest", nil)
		w2 := httptest.NewRecorder()
		srv.ServeHTTP(w2, req2)
		if w2.Code != http.StatusConflict {
			t.Fatalf("expected 409, got %d", w2.Code)
		}

		close(block)
	})
}

// TestHandleStatements_SECDATA1220 exercises the CPE-prefix expansion end-to-end
// against the real Red Hat CSAF VEX document for CVE-2024-0217. The document
// emits only the base CPE (cpe:/o:redhat:enterprise_linux:8) for the unfixed
// RHEL 8 branch — no ::baseos / ::appstream variants. A scanner querying with
// a variant CPE must still match via the RedHat-documented 5-part prefix rule.
// Reference: redhat.atlassian.net/browse/SECDATA-1220 (closed "Not a bug";
// Red Hat's position is that scanners should prefix-match on the first 5 parts).
func TestHandleStatements_SECDATA1220(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "secdata-1220-cve-2024-0217.json")
	stmts, err := csaf.ExtractFromFile(path)
	if err != nil {
		t.Fatalf("extract fixture: %v", err)
	}

	const (
		baseCPE    = "cpe:/o:redhat:enterprise_linux:8"
		variantCPE = "cpe:/o:redhat:enterprise_linux:8::baseos"
	)
	var hasBase, hasVariant bool
	for _, s := range stmts {
		if s.ProductID == baseCPE {
			hasBase = true
		}
		if s.ProductID == variantCPE {
			hasVariant = true
		}
	}
	if !hasBase {
		t.Fatalf("fixture missing base CPE %q — regression-test premise broken", baseCPE)
	}
	if hasVariant {
		t.Fatalf("fixture unexpectedly contains variant CPE %q — SECDATA-1220 may have been fixed upstream; revisit", variantCPE)
	}

	dbPath := t.TempDir() + "/test.db"
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := database.UpsertVendor("redhat", "Red Hat"); err != nil {
		t.Fatal(err)
	}
	dbStmts := make([]db.Statement, 0, len(stmts))
	for _, s := range stmts {
		dbStmts = append(dbStmts, db.Statement{
			Vendor:        "redhat",
			CVE:           s.CVE,
			ProductID:     s.ProductID,
			BaseID:        s.BaseID,
			Version:       s.Version,
			IDType:        s.IDType,
			Status:        s.Status,
			Justification: s.Justification,
			Updated:       "2024-01-05T00:00:00Z",
			SourceFormat:  "csaf",
		})
	}
	if err := database.BulkInsert(dbStmts); err != nil {
		t.Fatal(err)
	}

	srv := NewServer(database, nil)
	body, _ := json.Marshal(statementsRequest{
		CVEs:     []string{"CVE-2024-0217"},
		Products: []string{variantCPE},
	})
	req := httptest.NewRequest("POST", "/v1/statements", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	doc := decodeOpenVEX(t, w)
	if len(doc.Statements) == 0 {
		t.Fatal("expected at least one statement via CPE prefix; got zero — SECDATA-1220 regression")
	}
	var viaPrefix int
	for _, s := range doc.Statements {
		if !strings.Contains(s.StatusNotes, "source_format=csaf") {
			t.Errorf("expected source_format=csaf in status_notes, got %q", s.StatusNotes)
		}
		if strings.Contains(s.StatusNotes, "match_reason=via_cpe_prefix") {
			viaPrefix++
		}
	}
	if viaPrefix == 0 {
		t.Fatalf("expected at least one statement matched via_cpe_prefix, got none")
	}
}

// TestHandleStatements_DebDistroIdentity is the end-to-end regression for a
// v0.2.4 → v0.2.5 bug. Ubuntu (and any future deb) adapter emits statements
// whose BaseID carries the `distro` qualifier (e.g.
// `pkg:deb/ubuntu/openssl?distro=ubuntu-24.04`) because the same binary name
// on different releases is a different package with different fixed
// versions — distro is identity, not a filter. A scanner's query PURL
// carries the same `distro=` qualifier (plus version + arch). Before the
// fix, splitBase stripped every qualifier uniformly, so the scanner's PURL
// normalised to `pkg:deb/ubuntu/openssl` and failed to match the stored
// distro-qualified base_id.
func TestHandleStatements_DebDistroIdentity(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := database.UpsertVendor("ubuntu", "Ubuntu"); err != nil {
		t.Fatal(err)
	}

	stmts := []db.Statement{
		{
			Vendor:       "ubuntu",
			CVE:          "CVE-2024-26130",
			ProductID:    "pkg:deb/ubuntu/python3-cryptography?distro=ubuntu-24.04",
			BaseID:       "pkg:deb/ubuntu/python3-cryptography?distro=ubuntu-24.04",
			Version:      "0:41.0.7-4ubuntu0.1",
			IDType:       "purl",
			Status:       "fixed",
			Updated:      "2026-04-23T00:00:00Z",
			SourceFormat: "oval",
		},
		{
			Vendor:       "ubuntu",
			CVE:          "CVE-2024-26130",
			ProductID:    "pkg:deb/ubuntu/python3-cryptography?distro=ubuntu-22.04",
			BaseID:       "pkg:deb/ubuntu/python3-cryptography?distro=ubuntu-22.04",
			Version:      "0:38.0.4-3ubuntu2.2",
			IDType:       "purl",
			Status:       "fixed",
			Updated:      "2026-04-23T00:00:00Z",
			SourceFormat: "oval",
		},
	}
	if err := database.BulkInsert(stmts); err != nil {
		t.Fatal(err)
	}

	srv := NewServer(database, nil)

	body, _ := json.Marshal(statementsRequest{
		CVEs:     []string{"CVE-2024-26130"},
		Products: []string{"pkg:deb/ubuntu/python3-cryptography@41.0.7-3?arch=amd64&distro=ubuntu-24.04"},
	})
	req := httptest.NewRequest("POST", "/v1/statements", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	doc := decodeOpenVEX(t, w)
	if len(doc.Statements) == 0 {
		t.Fatal("expected at least one statement for a distro-qualified deb PURL; got zero — distro-identity regression (see CHANGELOG 0.2.5)")
	}

	// Must return exactly the noble row; jammy's same-package statement
	// must not leak in. Each statement's products[] echoes the user's input
	// PURL (no @version, no arch — keeping distro qualifier).
	var gotNoble, gotJammy int
	for _, s := range doc.Statements {
		if s.Supplier != "ubuntu" {
			t.Errorf("expected supplier=ubuntu, got %q", s.Supplier)
		}
		if !strings.Contains(s.StatusNotes, "match_reason=direct") {
			t.Errorf("expected match_reason=direct, got %q", s.StatusNotes)
		}
		// The encoder emits the user's input identifier (in base form) into
		// products[]. We can detect noble/jammy by inspecting it.
		for _, p := range s.Products {
			if p.ID == "pkg:deb/ubuntu/python3-cryptography?distro=ubuntu-24.04" {
				gotNoble++
			}
			if p.ID == "pkg:deb/ubuntu/python3-cryptography?distro=ubuntu-22.04" {
				gotJammy++
			}
		}
	}
	if gotNoble == 0 {
		t.Errorf("expected at least one noble statement, got 0")
	}
	if gotJammy != 0 {
		t.Errorf("expected 0 jammy statements (different distro identity), got %d", gotJammy)
	}
}

// TestHandleStatements_AliasExpansion drives the Phase 3 translation layer
// end-to-end. The scanner query carries a PURL with
// `?repository_id=rhel-8-for-x86_64-appstream-rpms` (no direct CPE or bare
// PURL match); the stored statement is keyed on the CPE
// `cpe:/a:redhat:enterprise_linux:8::appstream`. The resolver must consult
// product_aliases to translate the repository_id into the CPE, then match.
func TestHandleStatements_AliasExpansion(t *testing.T) {
	dbPath := t.TempDir() + "/alias-test.db"
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := database.UpsertVendor("redhat", "Red Hat"); err != nil {
		t.Fatal(err)
	}

	if err := database.BulkInsert([]db.Statement{{
		Vendor:       "redhat",
		CVE:          "CVE-2024-9999",
		ProductID:    "cpe:/a:redhat:enterprise_linux:8::appstream",
		BaseID:       "cpe:/a:redhat:enterprise_linux:8::appstream",
		IDType:       "cpe",
		Status:       "affected",
		Updated:      "2024-01-05T00:00:00Z",
		SourceFormat: "csaf",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := database.BulkUpsertAliases([]db.Alias{{
		Vendor:   "redhat",
		SourceNS: "repository_id",
		SourceID: "rhel-8-for-x86_64-appstream-rpms",
		TargetNS: "cpe",
		TargetID: "cpe:/a:redhat:enterprise_linux:8::appstream",
		Updated:  "2024-01-05T00:00:00Z",
	}}); err != nil {
		t.Fatal(err)
	}

	srv := NewServer(database, nil)
	body, _ := json.Marshal(statementsRequest{
		CVEs:     []string{"CVE-2024-9999"},
		Products: []string{"pkg:rpm/redhat/openssl@3.0?arch=x86_64&repository_id=rhel-8-for-x86_64-appstream-rpms"},
	})
	req := httptest.NewRequest("POST", "/v1/statements", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	doc := decodeOpenVEX(t, w)
	if len(doc.Statements) != 1 {
		t.Fatalf("expected 1 statement via alias, got %d", len(doc.Statements))
	}
	got := doc.Statements[0]
	if !strings.Contains(got.StatusNotes, "match_reason=via_alias") {
		t.Errorf("status_notes should contain match_reason=via_alias, got %q", got.StatusNotes)
	}
}

// TestHandleStatements_SourceFormatsFilter confirms that /v1/resolve's
// source_formats request field restricts which upstream formats are
// returned. Filter input is unchanged from prior versions; consumers
// inspect the source_format= prefix in OpenVEX status_notes to see which
// feed each row came from.
func TestHandleStatements_SourceFormatsFilter(t *testing.T) {
	database := setupTestDB(t)
	if err := database.BulkInsert([]db.Statement{{
		Vendor:       "testvendor",
		CVE:          "CVE-2024-1234",
		ProductID:    "pkg:rpm/test/openssl@3.0",
		BaseID:       "pkg:rpm/test/openssl",
		Version:      "3.0",
		IDType:       "purl",
		Status:       "fixed",
		Updated:      "2024-07-02T00:00:00Z",
		SourceFormat: "oval",
	}}); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(database, nil)

	run := func(t *testing.T, filter []string, wantFormats map[string]bool) {
		t.Helper()
		body, _ := json.Marshal(statementsRequest{
			CVEs:          []string{"CVE-2024-1234"},
			Products:      []string{"pkg:rpm/test/openssl@3.0"},
			SourceFormats: filter,
		})
		req := httptest.NewRequest("POST", "/v1/statements", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		doc := decodeOpenVEX(t, w)
		gotFormats := map[string]bool{}
		for _, s := range doc.Statements {
			if strings.Contains(s.StatusNotes, "source_format=csaf") {
				gotFormats["csaf"] = true
			}
			if strings.Contains(s.StatusNotes, "source_format=oval") {
				gotFormats["oval"] = true
			}
		}
		if len(gotFormats) != len(wantFormats) {
			t.Errorf("formats: got %v, want %v", gotFormats, wantFormats)
			return
		}
		for f := range wantFormats {
			if !gotFormats[f] {
				t.Errorf("expected source_format %q in response, got %v", f, gotFormats)
			}
		}
	}

	t.Run("no filter returns both", func(t *testing.T) {
		run(t, nil, map[string]bool{"csaf": true, "oval": true})
	})
	t.Run("csaf only", func(t *testing.T) {
		run(t, []string{"csaf"}, map[string]bool{"csaf": true})
	})
	t.Run("oval only", func(t *testing.T) {
		run(t, []string{"oval"}, map[string]bool{"oval": true})
	})
	t.Run("both explicitly", func(t *testing.T) {
		run(t, []string{"csaf", "oval"}, map[string]bool{"csaf": true, "oval": true})
	})
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
