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
	// Build binary
	binPath := filepath.Join(os.TempDir(), "reel-vex-test")
	build := exec.Command("go", "build", "-o", binPath, "./cmd/server")
	build.Dir = findRepoRoot()
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %s\n%s", err, out)
		os.Exit(1)
	}
	defer os.Remove(binPath)

	// Seed database
	dbPath := filepath.Join(os.TempDir(), "reel-vex-test.db")
	if err := seedDB(dbPath); err != nil {
		fmt.Fprintf(os.Stderr, "seed db: %s\n", err)
		os.Exit(1)
	}
	defer os.Remove(dbPath)

	// Pick a free port
	port := freePort()
	serverURL = fmt.Sprintf("http://127.0.0.1:%d", port)

	// Start server
	cmd := exec.Command(binPath, "-db", dbPath, "-addr", fmt.Sprintf(":%d", port), "serve")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "start server: %s\n", err)
		os.Exit(1)
	}
	defer func() {
		cmd.Process.Signal(os.Interrupt)
		cmd.Wait()
	}()

	// Wait for server to be ready
	if err := waitForServer(serverURL+"/healthz", 5*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "server not ready: %s\n", err)
		cmd.Process.Kill()
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func seedDB(path string) error {
	database, err := db.Open(path)
	if err != nil {
		return err
	}
	defer database.Close()

	if err := database.UpsertVendor("redhat", "Red Hat", "https://example.com/redhat/feed"); err != nil {
		return err
	}
	if err := database.UpsertVendor("suse", "SUSE", "https://example.com/suse/feed"); err != nil {
		return err
	}

	stmts := []db.Statement{
		// CVE-2024-1234: Red Hat, 2 products (PURL + CPE), not_affected with justification
		{Vendor: "redhat", CVE: "CVE-2024-1234", ProductID: "pkg:rpm/redhat/openssl@3.0.7-27.el9", IDType: "purl", Status: "not_affected", Justification: "vulnerable_code_not_present", Updated: "2024-07-01T00:00:00Z"},
		{Vendor: "redhat", CVE: "CVE-2024-1234", ProductID: "cpe:/a:redhat:enterprise_linux:9::appstream", IDType: "cpe", Status: "not_affected", Justification: "vulnerable_code_not_present", Updated: "2024-07-01T00:00:00Z"},

		// CVE-2024-5678: both vendors, different statuses
		{Vendor: "redhat", CVE: "CVE-2024-5678", ProductID: "pkg:rpm/redhat/nginx@1.22.1-4.el9", IDType: "purl", Status: "fixed", Updated: "2024-08-15T00:00:00Z"},
		{Vendor: "suse", CVE: "CVE-2024-5678", ProductID: "cpe:/a:suse:sles:15:sp5", IDType: "cpe", Status: "affected", Updated: "2024-08-10T00:00:00Z"},

		// CVE-2024-9999: SUSE only, under_investigation, no justification
		{Vendor: "suse", CVE: "CVE-2024-9999", ProductID: "pkg:rpm/suse/curl@8.0.1-150400.5.41.1", IDType: "purl", Status: "under_investigation", Updated: "2024-09-01T00:00:00Z"},

		// CVE-2024-1111: Red Hat, fixed, PURL only
		{Vendor: "redhat", CVE: "CVE-2024-1111", ProductID: "pkg:rpm/redhat/kernel@5.14.0-362.24.1.el9_3", IDType: "purl", Status: "fixed", Updated: "2024-06-20T00:00:00Z"},

		// CVE-2024-2222: SUSE, not_affected with justification, CPE
		{Vendor: "suse", CVE: "CVE-2024-2222", ProductID: "cpe:/a:suse:sle-module-basesystem:15:sp5", IDType: "cpe", Status: "not_affected", Justification: "component_not_present", Updated: "2024-07-15T00:00:00Z"},

		// CVE-2024-3333: Red Hat, affected, no justification
		{Vendor: "redhat", CVE: "CVE-2024-3333", ProductID: "pkg:rpm/redhat/httpd@2.4.57-5.el9", IDType: "purl", Status: "affected", Updated: "2024-10-01T00:00:00Z"},
	}

	return database.BulkInsert(stmts)
}

// --- CVE endpoint ---

func TestCVE_Found(t *testing.T) {
	resp := get(t, "/v1/cve/CVE-2024-1234")
	expectStatus(t, resp, 200)

	stmts := decodeStatements(t, resp)
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(stmts))
	}
	for _, s := range stmts {
		expectField(t, s, "vendor", "redhat")
		expectField(t, s, "cve", "CVE-2024-1234")
		expectField(t, s, "status", "not_affected")
		expectField(t, s, "justification", "vulnerable_code_not_present")
		if s["id_type"] != "purl" && s["id_type"] != "cpe" {
			t.Fatalf("unexpected id_type: %s", s["id_type"])
		}
	}
}

func TestCVE_NotFound(t *testing.T) {
	resp := get(t, "/v1/cve/CVE-9999-0000")
	expectStatus(t, resp, 200)

	stmts := decodeStatements(t, resp)
	if len(stmts) != 0 {
		t.Fatalf("expected 0 statements, got %d", len(stmts))
	}
}

func TestCVE_MultipleVendors(t *testing.T) {
	resp := get(t, "/v1/cve/CVE-2024-5678")
	expectStatus(t, resp, 200)

	stmts := decodeStatements(t, resp)
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(stmts))
	}

	vendors := map[string]bool{}
	for _, s := range stmts {
		vendors[s["vendor"].(string)] = true
	}
	if !vendors["redhat"] || !vendors["suse"] {
		t.Fatalf("expected both redhat and suse, got %v", vendors)
	}
}

// --- Resolve endpoint ---

func TestResolve_Match(t *testing.T) {
	resp := post(t, "/v1/resolve", map[string]any{
		"cves":     []string{"CVE-2024-1234"},
		"products": []string{"pkg:rpm/redhat/openssl@3.0.7-27.el9"},
	})
	expectStatus(t, resp, 200)

	stmts := decodeStatements(t, resp)
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(stmts))
	}
	expectField(t, stmts[0], "status", "not_affected")
	expectField(t, stmts[0], "product_id", "pkg:rpm/redhat/openssl@3.0.7-27.el9")
}

func TestResolve_NoOverlap(t *testing.T) {
	resp := post(t, "/v1/resolve", map[string]any{
		"cves":     []string{"CVE-2024-1234"},
		"products": []string{"pkg:rpm/redhat/nginx@1.22.1-4.el9"}, // nginx is CVE-2024-5678, not 1234
	})
	expectStatus(t, resp, 200)

	stmts := decodeStatements(t, resp)
	if len(stmts) != 0 {
		t.Fatalf("expected 0 statements, got %d", len(stmts))
	}
}

func TestResolve_MultipleCVEs(t *testing.T) {
	resp := post(t, "/v1/resolve", map[string]any{
		"cves":     []string{"CVE-2024-1234", "CVE-2024-5678"},
		"products": []string{"pkg:rpm/redhat/openssl@3.0.7-27.el9", "pkg:rpm/redhat/nginx@1.22.1-4.el9"},
	})
	expectStatus(t, resp, 200)

	stmts := decodeStatements(t, resp)
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(stmts))
	}

	cves := map[string]bool{}
	for _, s := range stmts {
		cves[s["cve"].(string)] = true
	}
	if !cves["CVE-2024-1234"] || !cves["CVE-2024-5678"] {
		t.Fatalf("expected both CVEs, got %v", cves)
	}
}

func TestResolve_PURLAndCPE(t *testing.T) {
	resp := post(t, "/v1/resolve", map[string]any{
		"cves":     []string{"CVE-2024-1234"},
		"products": []string{"pkg:rpm/redhat/openssl@3.0.7-27.el9", "cpe:/a:redhat:enterprise_linux:9::appstream"},
	})
	expectStatus(t, resp, 200)

	stmts := decodeStatements(t, resp)
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements (purl + cpe), got %d", len(stmts))
	}

	types := map[string]bool{}
	for _, s := range stmts {
		types[s["id_type"].(string)] = true
	}
	if !types["purl"] || !types["cpe"] {
		t.Fatalf("expected both purl and cpe, got %v", types)
	}
}

func TestResolve_EmptyFields(t *testing.T) {
	// Missing products
	resp := post(t, "/v1/resolve", map[string]any{
		"cves": []string{"CVE-2024-1234"},
	})
	expectStatus(t, resp, 400)

	// Missing cves
	resp = post(t, "/v1/resolve", map[string]any{
		"products": []string{"pkg:rpm/redhat/openssl@3.0.7-27.el9"},
	})
	expectStatus(t, resp, 400)
}

func TestResolve_InvalidJSON(t *testing.T) {
	req, _ := http.NewRequest("POST", serverURL+"/v1/resolve", bytes.NewReader([]byte("{not json")))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestResolve_OversizedBody(t *testing.T) {
	// 2MB of garbage
	big := strings.Repeat("x", 2*1024*1024)
	req, _ := http.NewRequest("POST", serverURL+"/v1/resolve", bytes.NewReader([]byte(big)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Either 413 (ContentLength check) or 400 (MaxBytesReader)
	if resp.StatusCode != 413 && resp.StatusCode != 400 {
		t.Fatalf("expected 413 or 400, got %d", resp.StatusCode)
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

// --- Method not allowed ---

func TestMethodNotAllowed(t *testing.T) {
	req, _ := http.NewRequest("POST", serverURL+"/v1/cve/CVE-2024-1234", nil)
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

func expectField(t *testing.T, stmt map[string]any, key, want string) {
	t.Helper()
	got, ok := stmt[key].(string)
	if !ok || got != want {
		t.Fatalf("expected %s=%q, got %q", key, want, got)
	}
}

func decodeStatements(t *testing.T, resp *http.Response) []map[string]any {
	t.Helper()
	defer resp.Body.Close()

	var result struct {
		Statements []map[string]any `json:"statements"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode: %s\nbody: %s", err, body)
	}
	return result.Statements
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
