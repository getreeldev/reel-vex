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

func TestHandleCVE(t *testing.T) {
	database := setupTestDB(t)
	srv := NewServer(database, nil)

	t.Run("found", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/v1/cve/CVE-2024-1234", nil)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		if got := w.Header().Get("Cache-Control"); got != cacheCVE {
			t.Errorf("Cache-Control: got %q, want %q", got, cacheCVE)
		}

		var resp statementsResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatal(err)
		}
		if len(resp.Statements) != 2 {
			t.Fatalf("expected 2 statements, got %d", len(resp.Statements))
		}
	})

	t.Run("not found", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/v1/cve/CVE-9999-0000", nil)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var resp statementsResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatal(err)
		}
		if len(resp.Statements) != 0 {
			t.Fatalf("expected 0 statements, got %d", len(resp.Statements))
		}
	})
}

func TestHandleCVESummary(t *testing.T) {
	database := setupTestDB(t)
	srv := NewServer(database, nil)

	t.Run("found", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/v1/cve/CVE-2024-1234/summary", nil)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		if hdr := w.Header().Get("Cache-Control"); hdr != cacheCVE {
			t.Errorf("Cache-Control: got %q, want %q", hdr, cacheCVE)
		}

		var got struct {
			CVE      string         `json:"cve"`
			Total    int            `json:"total"`
			ByStatus map[string]int `json:"by_status"`
			Vendors  []string       `json:"vendors"`
		}
		if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.CVE != "CVE-2024-1234" {
			t.Fatalf("cve: got %q, want CVE-2024-1234", got.CVE)
		}
		if got.Total != 2 {
			t.Fatalf("total: got %d, want 2", got.Total)
		}
		if got.ByStatus["not_affected"] != 2 {
			t.Fatalf("not_affected: got %d, want 2", got.ByStatus["not_affected"])
		}
		if len(got.Vendors) != 1 || got.Vendors[0] != "testvendor" {
			t.Fatalf("vendors: got %v, want [testvendor]", got.Vendors)
		}
	})

	t.Run("not found returns zero totals", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/v1/cve/CVE-9999-0000/summary", nil)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var got struct {
			Total    int            `json:"total"`
			ByStatus map[string]int `json:"by_status"`
		}
		if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.Total != 0 {
			t.Fatalf("expected 0 total for missing CVE, got %d", got.Total)
		}
	})
}

func TestHandleResolve(t *testing.T) {
	database := setupTestDB(t)
	srv := NewServer(database, nil)

	t.Run("match", func(t *testing.T) {
		body, _ := json.Marshal(resolveRequest{
			CVEs:     []string{"CVE-2024-1234"},
			Products: []string{"pkg:rpm/test/openssl@3.0"},
		})
		req := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}

		var resp statementsResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatal(err)
		}
		if len(resp.Statements) != 1 {
			t.Fatalf("expected 1 statement, got %d", len(resp.Statements))
		}
		if resp.Statements[0].Status != "not_affected" {
			t.Fatalf("expected not_affected, got %s", resp.Statements[0].Status)
		}
		if resp.Statements[0].SourceFormat != "csaf" {
			t.Fatalf("expected source_format=csaf, got %q", resp.Statements[0].SourceFormat)
		}
		if resp.Statements[0].MatchReason != "direct" {
			t.Fatalf("expected match_reason=direct for an exact-base PURL query, got %q", resp.Statements[0].MatchReason)
		}
	})

	t.Run("no match", func(t *testing.T) {
		body, _ := json.Marshal(resolveRequest{
			CVEs:     []string{"CVE-2024-1234"},
			Products: []string{"pkg:rpm/test/nginx@1.25"},
		})
		req := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var resp statementsResponse
		json.NewDecoder(w.Body).Decode(&resp)
		if len(resp.Statements) != 0 {
			t.Fatalf("expected 0 statements, got %d", len(resp.Statements))
		}
	})

	t.Run("missing fields", func(t *testing.T) {
		body, _ := json.Marshal(resolveRequest{CVEs: []string{"CVE-2024-1234"}})
		req := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader([]byte("not json")))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
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
// (resolve, sbom, ingest trigger) must never advertise caching — their
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
			"POST /v1/resolve",
			httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader([]byte(`{"cves":["CVE-2024-1234"],"products":["pkg:rpm/test/openssl"]}`))),
		},
		{
			"POST /v1/sbom",
			httptest.NewRequest("POST", "/v1/sbom", bytes.NewReader([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5"}`))),
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

func TestHandleSBOM(t *testing.T) {
	database := setupTestDB(t)
	srv := NewServer(database, nil)

	t.Run("annotates matching vulnerabilities", func(t *testing.T) {
		sbom := map[string]any{
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
				map[string]any{
					"id": "CVE-2024-1234",
				},
			},
		}
		body, _ := json.Marshal(sbom)
		req := httptest.NewRequest("POST", "/v1/sbom", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

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
		sbom := map[string]any{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.5",
			"components": []any{
				map[string]any{
					"type": "library",
					"name": "something",
					"purl": "pkg:npm/something@1.0",
				},
			},
			"vulnerabilities": []any{
				map[string]any{
					"id": "CVE-9999-0000",
				},
			},
		}
		body, _ := json.Marshal(sbom)
		req := httptest.NewRequest("POST", "/v1/sbom", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

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
		sbom := map[string]any{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.5",
			"components": []any{
				map[string]any{"type": "library", "purl": "pkg:npm/foo@1.0"},
			},
		}
		body, _ := json.Marshal(sbom)
		req := httptest.NewRequest("POST", "/v1/sbom", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("no components returns SBOM as-is", func(t *testing.T) {
		sbom := map[string]any{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.5",
			"vulnerabilities": []any{
				map[string]any{"id": "CVE-2024-1234"},
			},
		}
		body, _ := json.Marshal(sbom)
		req := httptest.NewRequest("POST", "/v1/sbom", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("cpe matching works", func(t *testing.T) {
		sbom := map[string]any{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.5",
			"components": []any{
				map[string]any{
					"type": "library",
					"name": "openssl",
					"cpe":  "cpe:/a:test:openssl:3.0",
				},
			},
			"vulnerabilities": []any{
				map[string]any{"id": "CVE-2024-1234"},
			},
		}
		body, _ := json.Marshal(sbom)
		req := httptest.NewRequest("POST", "/v1/sbom", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

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
		req := httptest.NewRequest("POST", "/v1/sbom", bytes.NewReader([]byte("not json")))
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

		sbom := map[string]any{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.5",
			"components": []any{
				map[string]any{"type": "library", "purl": "pkg:rpm/test/openssl@3.0"},
			},
			"vulnerabilities": []any{
				map[string]any{"id": "CVE-2024-1234"},
			},
		}
		body, _ := json.Marshal(sbom)
		req := httptest.NewRequest("POST", "/v1/sbom", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

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

		// Detail should mention both vendors.
		detail := analysis["detail"].(string)
		if !strings.Contains(detail, "testvendor") || !strings.Contains(detail, "vendor2") {
			t.Fatalf("expected both vendors in detail, got: %s", detail)
		}
	})
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

		// Wait for ingest goroutine to run.
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
			<-block // Block until test releases.
			return nil
		}, time.Hour, "")
		srv := NewServer(database, runner)

		// First trigger.
		req := httptest.NewRequest("POST", "/v1/ingest", nil)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusAccepted {
			t.Fatalf("expected 202, got %d", w.Code)
		}

		// Wait for ingest to start.
		<-started

		// Second trigger while first is running.
		req2 := httptest.NewRequest("POST", "/v1/ingest", nil)
		w2 := httptest.NewRecorder()
		srv.ServeHTTP(w2, req2)
		if w2.Code != http.StatusConflict {
			t.Fatalf("expected 409, got %d", w2.Code)
		}

		close(block)
	})
}

// TestHandleResolve_SECDATA1220 exercises the CPE-prefix expansion end-to-end
// against the real Red Hat CSAF VEX document for CVE-2024-0217. The document
// emits only the base CPE (cpe:/o:redhat:enterprise_linux:8) for the unfixed
// RHEL 8 branch — no ::baseos / ::appstream variants. A scanner querying with
// a variant CPE must still match via the RedHat-documented 5-part prefix rule.
// Reference: redhat.atlassian.net/browse/SECDATA-1220 (closed "Not a bug";
// Red Hat's position is that scanners should prefix-match on the first 5 parts).
func TestHandleResolve_SECDATA1220(t *testing.T) {
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
	body, _ := json.Marshal(resolveRequest{
		CVEs:     []string{"CVE-2024-0217"},
		Products: []string{variantCPE},
	})
	req := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp statementsResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Statements) == 0 {
		t.Fatal("expected at least one statement via CPE prefix; got zero — SECDATA-1220 regression")
	}
	var viaPrefix int
	for _, s := range resp.Statements {
		if s.SourceFormat != "csaf" {
			t.Errorf("expected source_format=csaf, got %q", s.SourceFormat)
		}
		if s.ProductID == baseCPE && s.MatchReason != "via_cpe_prefix" {
			t.Errorf("expected match_reason=via_cpe_prefix for base-CPE statement, got %q", s.MatchReason)
		}
		if s.MatchReason == "via_cpe_prefix" {
			viaPrefix++
		}
	}
	if viaPrefix == 0 {
		t.Fatalf("expected at least one statement matched via_cpe_prefix, got none")
	}
}

// TestHandleResolve_AliasExpansion drives the Phase 3 translation layer
// end-to-end. The scanner query carries a PURL with
// `?repository_id=rhel-8-for-x86_64-appstream-rpms` (no direct CPE or bare
// PURL match); the stored statement is keyed on the CPE
// `cpe:/a:redhat:enterprise_linux:8::appstream`. The resolver must consult
// product_aliases to translate the repository_id into the CPE, then match.
func TestHandleResolve_AliasExpansion(t *testing.T) {
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
	body, _ := json.Marshal(resolveRequest{
		CVEs:     []string{"CVE-2024-9999"},
		Products: []string{"pkg:rpm/redhat/openssl@3.0?arch=x86_64&repository_id=rhel-8-for-x86_64-appstream-rpms"},
	})
	req := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp statementsResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Statements) != 1 {
		t.Fatalf("expected 1 statement via alias, got %d: %+v", len(resp.Statements), resp.Statements)
	}
	got := resp.Statements[0]
	if got.MatchReason != "via_alias" {
		t.Errorf("match_reason: got %q, want via_alias", got.MatchReason)
	}
	if got.ProductID != "cpe:/a:redhat:enterprise_linux:8::appstream" {
		t.Errorf("product_id: got %q", got.ProductID)
	}
}

// TestHandleResolve_SourceFormatsFilter confirms that /v1/resolve's
// source_formats request field restricts which upstream formats are
// returned. With OVAL joining CSAF for Red Hat, consumers that want only
// VEX-shaped statements (not OVAL-derived ones), or vice versa, can
// filter cleanly.
func TestHandleResolve_SourceFormatsFilter(t *testing.T) {
	database := setupTestDB(t)
	// setupTestDB already inserted a CSAF statement for CVE-2024-1234
	// against pkg:rpm/test/openssl@3.0 (vendor=testvendor). Add an OVAL
	// statement for the same CVE+product so the filter has something to
	// distinguish.
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
		body, _ := json.Marshal(resolveRequest{
			CVEs:          []string{"CVE-2024-1234"},
			Products:      []string{"pkg:rpm/test/openssl@3.0"},
			SourceFormats: filter,
		})
		req := httptest.NewRequest("POST", "/v1/resolve", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		var resp statementsResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatal(err)
		}
		gotFormats := map[string]bool{}
		for _, s := range resp.Statements {
			gotFormats[s.SourceFormat] = true
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
