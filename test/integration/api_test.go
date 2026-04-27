//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getreeldev/reel-vex/pkg/db"
)

var serverURL string

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

// runTests does setup / m.Run / teardown so deferred cleanup runs before
// os.Exit. Without this, the spawned server process leaks, and Go's test
// runner blocks ~60s waiting for the child's stdout to drain before
// reporting a spurious non-zero exit.
func runTests(m *testing.M) int {
	binPath := filepath.Join(os.TempDir(), "reel-vex-test")
	build := exec.Command("go", "build", "-o", binPath, "./cmd/server")
	build.Dir = findRepoRoot()
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %s\n%s", err, out)
		os.Exit(1)
	}
	defer os.Remove(binPath)

	dbPath := filepath.Join(os.TempDir(), "reel-vex-test.db")
	if err := seedDB(dbPath); err != nil {
		fmt.Fprintf(os.Stderr, "seed db: %s\n", err)
		os.Exit(1)
	}
	defer os.Remove(dbPath)

	port := freePort()
	serverURL = fmt.Sprintf("http://127.0.0.1:%d", port)

	configPath := filepath.Join(os.TempDir(), "reel-vex-test-config.yaml")
	os.WriteFile(configPath, []byte(`adapters:
  - type: csaf
    id: test
    url: https://example.invalid/metadata.json
`), 0644)
	defer os.Remove(configPath)

	cmd := exec.Command(binPath,
		"-db", dbPath,
		"-addr", fmt.Sprintf(":%d", port),
		"-config", configPath,
		"-ingest-interval", "999h",
		"-admin-token", "test-token",
		"serve",
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.WaitDelay = 3 * time.Second
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "start server: %s\n", err)
		os.Exit(1)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	if err := waitForServer(serverURL+"/healthz", 5*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "server not ready: %s\n", err)
		cmd.Process.Kill()
		os.Exit(1)
	}

	return m.Run()
}

func seedDB(path string) error {
	database, err := db.Open(path)
	if err != nil {
		return err
	}
	defer database.Close()

	if err := database.UpsertVendor("redhat", "Red Hat"); err != nil {
		return err
	}
	if err := database.UpsertVendor("suse", "SUSE"); err != nil {
		return err
	}

	stmts := []db.Statement{
		// CVE-2024-1234: Red Hat, openssl, not_affected
		{Vendor: "redhat", CVE: "CVE-2024-1234", ProductID: "pkg:rpm/redhat/openssl@3.0.7-27.el9", BaseID: "pkg:rpm/redhat/openssl", Version: "3.0.7-27.el9", IDType: "purl", Status: "not_affected", Justification: "vulnerable_code_not_present", Updated: "2024-07-01T00:00:00Z", SourceFormat: "csaf"},
		{Vendor: "redhat", CVE: "CVE-2024-1234", ProductID: "cpe:/a:redhat:enterprise_linux:9::appstream", BaseID: "cpe:/a:redhat:enterprise_linux:9::appstream", IDType: "cpe", Status: "not_affected", Justification: "vulnerable_code_not_present", Updated: "2024-07-01T00:00:00Z", SourceFormat: "csaf"},

		// CVE-2024-5678: Red Hat fixed, SUSE affected
		{Vendor: "redhat", CVE: "CVE-2024-5678", ProductID: "pkg:rpm/redhat/nginx@1.22.1-4.el9", BaseID: "pkg:rpm/redhat/nginx", Version: "1.22.1-4.el9", IDType: "purl", Status: "fixed", Updated: "2024-08-01T00:00:00Z", SourceFormat: "csaf"},
		{Vendor: "suse", CVE: "CVE-2024-5678", ProductID: "cpe:/a:suse:sles:15:sp5", BaseID: "cpe:/a:suse:sles:15:sp5", IDType: "cpe", Status: "affected", Updated: "2024-08-15T00:00:00Z", SourceFormat: "csaf"},

		// CVE-2024-9999: SUSE only, under_investigation, no justification
		{Vendor: "suse", CVE: "CVE-2024-9999", ProductID: "pkg:rpm/suse/curl@8.0.1-150400.5.41.1", BaseID: "pkg:rpm/suse/curl", Version: "8.0.1-150400.5.41.1", IDType: "purl", Status: "under_investigation", Updated: "2024-09-01T00:00:00Z", SourceFormat: "csaf"},

		// CVE-2024-1111: Red Hat fixed
		{Vendor: "redhat", CVE: "CVE-2024-1111", ProductID: "pkg:rpm/redhat/kernel@5.14.0-362.24.1.el9_3", BaseID: "pkg:rpm/redhat/kernel", Version: "5.14.0-362.24.1.el9_3", IDType: "purl", Status: "fixed", Updated: "2024-06-20T00:00:00Z", SourceFormat: "csaf"},

		// CVE-2024-2222: SUSE not_affected with component_not_present justification
		{Vendor: "suse", CVE: "CVE-2024-2222", ProductID: "cpe:/a:suse:sle-module-basesystem:15:sp5", BaseID: "cpe:/a:suse:sle-module-basesystem:15:sp5", IDType: "cpe", Status: "not_affected", Justification: "component_not_present", Updated: "2024-07-15T00:00:00Z", SourceFormat: "csaf"},

		// CVE-2024-3333: Red Hat, affected, no justification
		{Vendor: "redhat", CVE: "CVE-2024-3333", ProductID: "pkg:rpm/redhat/httpd@2.4.57-5.el9", BaseID: "pkg:rpm/redhat/httpd", Version: "2.4.57-5.el9", IDType: "purl", Status: "affected", Updated: "2024-10-01T00:00:00Z", SourceFormat: "csaf"},
	}

	return database.BulkInsert(stmts)
}

// --- /v1/statements (unified query endpoint, v0.4.0) ---

func TestStatements_CVEOnly(t *testing.T) {
	resp := post(t, "/v1/statements", map[string]any{
		"cves": []string{"CVE-2024-1234"},
	})
	expectStatus(t, resp, 200)

	stmts := decodeOpenVEXStatements(t, resp)
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(stmts))
	}
	for _, s := range stmts {
		if s.Supplier != "redhat" {
			t.Errorf("expected supplier=redhat, got %q", s.Supplier)
		}
		if s.Vulnerability.Name != "CVE-2024-1234" {
			t.Errorf("expected vulnerability.name=CVE-2024-1234, got %q", s.Vulnerability.Name)
		}
		if s.Status != "not_affected" {
			t.Errorf("expected status=not_affected, got %q", s.Status)
		}
		if s.Justification != "vulnerable_code_not_present" {
			t.Errorf("expected justification=vulnerable_code_not_present, got %q", s.Justification)
		}
	}
}

func TestStatements_CVEOnly_NotFound(t *testing.T) {
	resp := post(t, "/v1/statements", map[string]any{
		"cves": []string{"CVE-9999-0000"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("expected 204 on empty CVE, got %d", resp.StatusCode)
	}
}

func TestStatements_MultipleVendors(t *testing.T) {
	resp := post(t, "/v1/statements", map[string]any{
		"cves": []string{"CVE-2024-5678"},
	})
	expectStatus(t, resp, 200)

	stmts := decodeOpenVEXStatements(t, resp)
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(stmts))
	}

	suppliers := map[string]bool{}
	for _, s := range stmts {
		suppliers[s.Supplier] = true
	}
	if !suppliers["redhat"] || !suppliers["suse"] {
		t.Fatalf("expected both redhat and suse suppliers, got %v", suppliers)
	}
}

func TestStatements_WithProducts_Match(t *testing.T) {
	resp := post(t, "/v1/statements", map[string]any{
		"cves":     []string{"CVE-2024-1234"},
		"products": []string{"pkg:rpm/redhat/openssl@3.0.7-27.el9"},
	})
	expectStatus(t, resp, 200)

	stmts := decodeOpenVEXStatements(t, resp)
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(stmts))
	}
	if stmts[0].Status != "not_affected" {
		t.Errorf("expected status=not_affected, got %q", stmts[0].Status)
	}
}

func TestStatements_WithProducts_NoOverlap(t *testing.T) {
	resp := post(t, "/v1/statements", map[string]any{
		"cves":     []string{"CVE-2024-1234"},
		"products": []string{"pkg:rpm/redhat/nginx@1.22.1-4.el9"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("expected 204 on no match, got %d", resp.StatusCode)
	}
}

func TestStatements_MultipleCVEs(t *testing.T) {
	resp := post(t, "/v1/statements", map[string]any{
		"cves":     []string{"CVE-2024-1234", "CVE-2024-5678"},
		"products": []string{"pkg:rpm/redhat/openssl@3.0.7-27.el9", "pkg:rpm/redhat/nginx@1.22.1-4.el9"},
	})
	expectStatus(t, resp, 200)

	stmts := decodeOpenVEXStatements(t, resp)
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(stmts))
	}

	cves := map[string]bool{}
	for _, s := range stmts {
		cves[s.Vulnerability.Name] = true
	}
	if !cves["CVE-2024-1234"] || !cves["CVE-2024-5678"] {
		t.Fatalf("expected both CVEs, got %v", cves)
	}
}

func TestStatements_PURLAndCPE(t *testing.T) {
	resp := post(t, "/v1/statements", map[string]any{
		"cves":     []string{"CVE-2024-1234"},
		"products": []string{"pkg:rpm/redhat/openssl@3.0.7-27.el9", "cpe:/a:redhat:enterprise_linux:9::appstream"},
	})
	expectStatus(t, resp, 200)

	stmts := decodeOpenVEXStatements(t, resp)
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements (purl + cpe), got %d", len(stmts))
	}

	hasPURL, hasCPE := false, false
	for _, s := range stmts {
		for _, p := range s.Products {
			if p.Identifiers != nil && p.Identifiers.PURL != "" {
				hasPURL = true
			}
			if p.Identifiers != nil && p.Identifiers.CPE23 != "" {
				hasCPE = true
			}
		}
	}
	if !hasPURL || !hasCPE {
		t.Fatalf("expected both purl and cpe identifiers; got purl=%v cpe=%v", hasPURL, hasCPE)
	}
}

func TestStatements_RequiresCVEs(t *testing.T) {
	// products without cves → 400
	resp := post(t, "/v1/statements", map[string]any{
		"products": []string{"pkg:rpm/redhat/openssl@3.0.7-27.el9"},
	})
	expectStatus(t, resp, 400)

	// empty body → 400
	resp = post(t, "/v1/statements", map[string]any{})
	expectStatus(t, resp, 400)
}

func TestStatements_InvalidJSON(t *testing.T) {
	req, _ := http.NewRequest("POST", serverURL+"/v1/statements", bytes.NewReader([]byte("{not json")))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestStatements_OversizedBody(t *testing.T) {
	big := strings.Repeat("x", 2*1024*1024)
	req, _ := http.NewRequest("POST", serverURL+"/v1/statements", bytes.NewReader([]byte(big)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 413 && resp.StatusCode != 400 {
		t.Fatalf("expected 413 or 400, got %d", resp.StatusCode)
	}
}

// TestStatements_OldRoutesAre404 is the breaking-change regression guard.
// /v1/cve/{id}, /v1/cve/{id}/summary, and /v1/resolve were all replaced by
// /v1/statements in v0.4.0. They must 404 explicitly.
func TestStatements_OldRoutesAre404(t *testing.T) {
	cases := []struct {
		method string
		path   string
	}{
		{"GET", "/v1/cve/CVE-2024-1234"},
		{"GET", "/v1/cve/CVE-2024-1234/summary"},
		{"POST", "/v1/resolve"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, serverURL+tc.path, bytes.NewReader([]byte(`{}`)))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 404 {
				t.Fatalf("expected 404, got %d", resp.StatusCode)
			}
		})
	}
}

// --- Stats endpoint ---

func TestStats(t *testing.T) {
	resp := get(t, "/v1/stats")
	expectStatus(t, resp, 200)

	var stats map[string]int
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err := json.Unmarshal(body, &stats); err != nil {
		t.Fatalf("decode stats: %s\nbody: %s", err, body)
	}

	if stats["vendors"] != 2 {
		t.Fatalf("expected 2 vendors, got %d", stats["vendors"])
	}
	if stats["cves"] != 6 {
		t.Fatalf("expected 6 CVEs, got %d", stats["cves"])
	}
	if stats["statements"] != 8 {
		t.Fatalf("expected 8 statements, got %d", stats["statements"])
	}
}

// --- Health endpoint ---

func TestHealth(t *testing.T) {
	resp := get(t, "/healthz")
	expectStatus(t, resp, 200)

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("expected 'ok', got %q", body)
	}
}

// --- CORS ---

func TestCORS_Preflight(t *testing.T) {
	req, _ := http.NewRequest("OPTIONS", serverURL+"/v1/stats", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("missing Access-Control-Allow-Origin")
	}
	if resp.Header.Get("Access-Control-Allow-Methods") == "" {
		t.Fatal("missing Access-Control-Allow-Methods")
	}
}

func TestCORS_Headers(t *testing.T) {
	resp := get(t, "/v1/stats")
	expectStatus(t, resp, 200)

	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("missing Access-Control-Allow-Origin on regular response")
	}
	resp.Body.Close()
}

// --- Analyze endpoint (replaces /v1/sbom in v0.3.0) ---

func TestAnalyze_SBOMOnly_Annotates(t *testing.T) {
	sbom := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"components": []any{
			map[string]any{
				"type": "library",
				"name": "openssl",
				"purl": "pkg:rpm/redhat/openssl@3.0.7-27.el9",
			},
		},
		"vulnerabilities": []any{
			map[string]any{"id": "CVE-2024-1234"},
		},
	}
	resp := post(t, "/v1/analyze", map[string]any{"sbom": sbom})
	expectStatus(t, resp, 200)

	var result map[string]any
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(body, &result)

	vulns := result["vulnerabilities"].([]any)
	vuln := vulns[0].(map[string]any)
	analysis, ok := vuln["analysis"].(map[string]any)
	if !ok {
		t.Fatal("expected analysis field")
	}
	if analysis["state"] != "not_affected" {
		t.Fatalf("expected not_affected, got %v", analysis["state"])
	}
	if analysis["justification"] != "code_not_present" {
		t.Fatalf("expected code_not_present, got %v", analysis["justification"])
	}
	detail := analysis["detail"].(string)
	if !strings.Contains(detail, "redhat") {
		t.Fatalf("expected redhat in detail, got: %s", detail)
	}
}

func TestAnalyze_SBOMOnly_NoMatchReturnsAsIs(t *testing.T) {
	sbom := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"components": []any{
			map[string]any{"type": "library", "purl": "pkg:npm/unknown@1.0"},
		},
		"vulnerabilities": []any{
			map[string]any{"id": "CVE-9999-0000"},
		},
	}
	resp := post(t, "/v1/analyze", map[string]any{"sbom": sbom})
	expectStatus(t, resp, 200)

	var result map[string]any
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(body, &result)

	vulns := result["vulnerabilities"].([]any)
	vuln := vulns[0].(map[string]any)
	if _, ok := vuln["analysis"]; ok {
		t.Fatal("expected no analysis for unmatched CVE")
	}
}

// TestAnalyze_CustomerVEXOnly_Override exercises the customer-VEX-only flow:
// the customer asserts a status that contradicts the seeded vendor row;
// the merged OpenVEX response carries the customer's claim with
// match_reason=from_customer_vex in status_notes.
func TestAnalyze_CustomerVEXOnly_Override(t *testing.T) {
	customerDoc := map[string]any{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"statements": []any{
			map[string]any{
				"vulnerability": map[string]any{"name": "CVE-2024-1234"},
				"products":      []any{map[string]any{"@id": "pkg:rpm/redhat/openssl"}},
				"status":        "affected",
				"supplier":      "acme-internal",
				"timestamp":     "2026-04-20T00:00:00Z",
			},
		},
	}
	resp := post(t, "/v1/analyze", map[string]any{"customer_vex": []any{customerDoc}})
	expectStatus(t, resp, 200)

	stmts := decodeOpenVEXStatements(t, resp)
	if len(stmts) == 0 {
		t.Fatal("expected at least the customer statement in the merged set")
	}
	var foundCustomer bool
	for _, s := range stmts {
		if s.Supplier == "acme-internal" && s.Status == "affected" {
			foundCustomer = true
			if !strings.Contains(s.StatusNotes, "match_reason=from_customer_vex") {
				t.Errorf("customer row should carry match_reason=from_customer_vex, got status_notes=%q", s.StatusNotes)
			}
			if strings.Contains(s.StatusNotes, "source_format=") {
				t.Errorf("customer row should not carry source_format prefix, got status_notes=%q", s.StatusNotes)
			}
		}
		// The colliding vendor row (redhat / not_affected on
		// pkg:rpm/redhat/openssl base) must have been dropped by the override.
		if s.Supplier == "redhat" && s.Status == "not_affected" {
			for _, p := range s.Products {
				if p.ID == "pkg:rpm/redhat/openssl" || (p.Identifiers != nil && p.Identifiers.PURL == "pkg:rpm/redhat/openssl") {
					t.Errorf("vendor row at colliding base_id was not dropped: %+v", s)
				}
			}
		}
	}
	if !foundCustomer {
		t.Errorf("merged response did not include the customer statement; got %+v", stmts)
	}
}

// TestAnalyze_BothInputs_OverrideInRollup is the headline override scenario.
// Vendor not_affected at one base_id (CPE) collides with customer affected at
// a different base_id (PURL) for the same CVE. Without the customerCVEs
// override, statusPriority would let the vendor's not_affected (priority 4)
// outrank the customer's affected (priority 1). With the override, the
// customer's claim wins absolutely on the per-CVE annotation rollup.
func TestAnalyze_BothInputs_OverrideInRollup(t *testing.T) {
	sbom := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"components": []any{
			map[string]any{
				"type": "library",
				"name": "openssl",
				"purl": "pkg:rpm/redhat/openssl@3.0.7-27.el9",
			},
		},
		"vulnerabilities": []any{
			map[string]any{"id": "CVE-2024-1234"},
		},
	}
	customerDoc := map[string]any{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"statements": []any{
			map[string]any{
				"vulnerability": map[string]any{"name": "CVE-2024-1234"},
				"products":      []any{map[string]any{"@id": "pkg:rpm/redhat/openssl"}},
				"status":        "affected",
				"supplier":      "acme-internal",
				"timestamp":     "2026-04-20T00:00:00Z",
			},
		},
	}
	resp := post(t, "/v1/analyze", map[string]any{
		"sbom":         sbom,
		"customer_vex": []any{customerDoc},
	})
	expectStatus(t, resp, 200)

	var result map[string]any
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(body, &result)

	vulns := result["vulnerabilities"].([]any)
	vuln := vulns[0].(map[string]any)
	analysis := vuln["analysis"].(map[string]any)

	if analysis["state"] != "exploitable" {
		t.Fatalf("override failed: expected exploitable (from customer affected), got %v — vendor not_affected on a different base_id should not have leaked into the rollup",
			analysis["state"])
	}
	detail := analysis["detail"].(string)
	if !strings.Contains(detail, "acme-internal") {
		t.Errorf("detail should mention customer supplier, got %q", detail)
	}
}

func TestAnalyze_RequiresAtLeastOneInput(t *testing.T) {
	resp := post(t, "/v1/analyze", map[string]any{})
	expectStatus(t, resp, 400)
}

func TestAnalyze_MalformedCustomerVEX(t *testing.T) {
	resp := post(t, "/v1/analyze", map[string]any{
		"customer_vex": []any{
			map[string]any{
				"@context":   "https://wrong.example/",
				"statements": []any{},
			},
		},
	})
	expectStatus(t, resp, 422)
}

func TestAnalyze_OldSBOMRouteIs404(t *testing.T) {
	resp := post(t, "/v1/sbom", map[string]any{"bomFormat": "CycloneDX"})
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404 on removed /v1/sbom route, got %d", resp.StatusCode)
	}
}

// --- Ingest endpoint ---

func TestIngest_StatusEndpoint(t *testing.T) {
	resp := get(t, "/v1/ingest")
	expectStatus(t, resp, 200)

	var status map[string]any
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(body, &status)

	if _, ok := status["running"].(bool); !ok {
		t.Fatalf("expected running field as bool, got %T", status["running"])
	}
}

func TestIngest_TriggerWithoutAuth(t *testing.T) {
	req, _ := http.NewRequest("POST", serverURL+"/v1/ingest", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Fatalf("expected 401 without token, got %d", resp.StatusCode)
	}
}

func TestIngest_TriggerWithAuth(t *testing.T) {
	req, _ := http.NewRequest("POST", serverURL+"/v1/ingest", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 202 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 202, got %d: %s", resp.StatusCode, body)
	}
}

// --- vexctl interop ---

// TestVexctl_AcceptsStatementsOutput verifies that the OpenVEX 0.2.0 doc
// emitted by /v1/statements passes through `vexctl merge` cleanly. This is
// the canonical interchange surface — if vexctl rejects our output, every
// downstream pipeline that relies on it (Trivy, Grype, custom OPA gates)
// falls over too. Skips cleanly when vexctl isn't installed.
func TestVexctl_AcceptsStatementsOutput(t *testing.T) {
	if _, err := exec.LookPath("vexctl"); err != nil {
		t.Skip("vexctl not installed; skipping interop check")
	}

	resp := post(t, "/v1/statements", map[string]any{
		"cves":     []string{"CVE-2024-1234"},
		"products": []string{"pkg:rpm/redhat/openssl@3.0.7-27.el9"},
	})
	expectStatus(t, resp, 200)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	f, err := os.CreateTemp("", "vexctl-statements-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(body); err != nil {
		t.Fatal(err)
	}
	f.Close()

	out, err := exec.Command("vexctl", "merge", f.Name()).CombinedOutput()
	if err != nil {
		t.Fatalf("vexctl merge rejected /v1/statements output: %v\noutput: %s", err, out)
	}
}

// TestVexctl_AcceptsAnalyzeCustomerVEXOutput is the new-feature variant of
// the interop check: the customer-VEX-only flow on /v1/analyze emits a
// merged OpenVEX doc with from_customer_vex match_reason. vexctl must
// accept it identically — the merge semantic is internal to reel-vex; the
// wire format is plain OpenVEX 0.2.0.
func TestVexctl_AcceptsAnalyzeCustomerVEXOutput(t *testing.T) {
	if _, err := exec.LookPath("vexctl"); err != nil {
		t.Skip("vexctl not installed; skipping interop check")
	}

	customerDoc := map[string]any{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"statements": []any{
			map[string]any{
				"vulnerability": map[string]any{"name": "CVE-2024-1234"},
				"products":      []any{map[string]any{"@id": "pkg:rpm/redhat/openssl"}},
				"status":        "affected",
				"supplier":      "acme-internal",
				"timestamp":     "2026-04-20T00:00:00Z",
			},
		},
	}
	resp := post(t, "/v1/analyze", map[string]any{"customer_vex": []any{customerDoc}})
	expectStatus(t, resp, 200)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	f, err := os.CreateTemp("", "vexctl-analyze-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(body); err != nil {
		t.Fatal(err)
	}
	f.Close()

	out, err := exec.Command("vexctl", "merge", f.Name()).CombinedOutput()
	if err != nil {
		t.Fatalf("vexctl merge rejected /v1/analyze output: %v\noutput: %s", err, out)
	}
}

// --- Method not allowed ---

func TestMethodNotAllowed(t *testing.T) {
	// /v1/stats is registered as GET-only; POST should yield 405.
	req, _ := http.NewRequest("POST", serverURL+"/v1/stats", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 405 {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

// --- helpers ---

func get(t *testing.T, path string) *http.Response {
	t.Helper()
	resp, err := http.Get(serverURL + path)
	if err != nil {
		t.Fatalf("GET %s: %s", path, err)
	}
	return resp
}

func post(t *testing.T, path string, body any) *http.Response {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(serverURL+path, "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("POST %s: %s", path, err)
	}
	return resp
}

func expectStatus(t *testing.T, resp *http.Response, code int) {
	t.Helper()
	if resp.StatusCode != code {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected %d, got %d: %s", code, resp.StatusCode, body)
	}
}

// openVEXStatement mirrors the OpenVEX 0.2.0 statement shape closely enough
// to drive integration assertions without importing the full pkg/openvex
// type tree (the test binary stays focused on JSON shape, not Go types).
type openVEXStatement struct {
	Vulnerability struct {
		Name string `json:"name"`
	} `json:"vulnerability"`
	Products []struct {
		ID          string `json:"@id,omitempty"`
		Identifiers *struct {
			PURL  string `json:"purl,omitempty"`
			CPE22 string `json:"cpe22,omitempty"`
			CPE23 string `json:"cpe23,omitempty"`
		} `json:"identifiers,omitempty"`
	} `json:"products"`
	Status        string `json:"status"`
	StatusNotes   string `json:"status_notes,omitempty"`
	Justification string `json:"justification,omitempty"`
	Supplier      string `json:"supplier,omitempty"`
}

// decodeOpenVEXStatements parses an OpenVEX 0.2.0 response body and returns
// just the statements array. Closes the body. Fails the test on any decode
// error.
func decodeOpenVEXStatements(t *testing.T, resp *http.Response) []openVEXStatement {
	t.Helper()
	defer resp.Body.Close()

	var doc struct {
		Context    string             `json:"@context"`
		Statements []openVEXStatement `json:"statements"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode openvex: %s\nbody: %s", err, body)
	}
	if doc.Context != "https://openvex.dev/ns/v0.2.0" {
		t.Fatalf("expected OpenVEX 0.2.0 @context, got %q", doc.Context)
	}
	return doc.Statements
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func waitForServer(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("server not ready after %s", timeout)
}

func findRepoRoot() string {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic("could not find repo root")
		}
		dir = parent
	}
}
