package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

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

	if err := database.UpsertVendor("testvendor", "Test Vendor", "https://example.com/feed"); err != nil {
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
		database.UpsertVendor("vendor2", "Vendor Two", "https://example.com/feed2")
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

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
