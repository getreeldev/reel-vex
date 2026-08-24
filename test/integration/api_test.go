//go:build integration

package integration

import (
	"bytes"
	"compress/gzip"
	"context"
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

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/getreeldev/reel-vex/pkg/db"
	"github.com/getreeldev/reel-vex/pkg/db/postgres"
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
	// reel-vex is Postgres-only; the integration test needs a real database.
	// In CI a `postgres` service supplies it; locally set REEL_VEX_TEST_PG_DSN.
	// Absent, skip the whole suite (so `go test -tags integration` stays green
	// without a DB).
	dsn := os.Getenv("REEL_VEX_TEST_PG_DSN")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "REEL_VEX_TEST_PG_DSN not set; skipping integration tests")
		return 0
	}

	binPath := filepath.Join(os.TempDir(), "reel-vex-test")
	build := exec.Command("go", "build", "-o", binPath, "./cmd/server")
	build.Dir = findRepoRoot()
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %s\n%s", err, out)
		os.Exit(1)
	}
	defer os.Remove(binPath)

	if err := seedDB(dsn); err != nil {
		fmt.Fprintf(os.Stderr, "seed db: %s\n", err)
		os.Exit(1)
	}

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
		"-db", dsn,
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

	// Wait for the startup ingest cycle to finish so TestIngest_TriggerWithAuth
	// doesn't race it. The server fires an immediate ingest at boot against
	// the placeholder example.invalid adapter; on slow CI runners (DNS NXDOMAIN
	// retries) it can still be running when the trigger test runs. Without
	// this wait, that test sometimes gets 409 "ingest already running" instead
	// of the expected 202.
	if err := waitForIngestQuiet(serverURL+"/v1/ingest", 30*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "startup ingest didn't quiesce: %s\n", err)
		cmd.Process.Kill()
		os.Exit(1)
	}

	return m.Run()
}

func seedDB(dsn string) error {
	database, err := postgres.Open(dsn)
	if err != nil {
		return err
	}
	defer database.Close()

	// Clean slate — the CI Postgres service (and a local dev DB) can be reused
	// across reruns. TRUNCATE after Open so the schema exists.
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	_, truncErr := pool.Exec(ctx, "TRUNCATE statements, vendors, product_aliases, adapter_state")
	pool.Close()
	if truncErr != nil {
		return truncErr
	}

	if err := database.UpsertVendor("redhat", "Red Hat"); err != nil {
		return err
	}
	if err := database.UpsertVendor("suse", "SUSE"); err != nil {
		return err
	}
	if err := database.UpsertVendor("rancher", "SUSE Rancher (OpenVEX)"); err != nil {
		return err
	}
	if err := database.UpsertVendor("ubuntu", "Canonical Ubuntu"); err != nil {
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

		// CVE-2024-7777: Rancher VEX (product-scoped, openvex). The verdict for
		// this Go module is scoped to the longhorn-engine image; the scope gate
		// must withhold it unless that image is named (statements) or is the
		// SBOM root (analyze). See the scope-gate tests below.
		{Vendor: "rancher", CVE: "CVE-2024-7777", ProductID: "pkg:golang/golang.org/x/net@v0.17.0", BaseID: "pkg:golang/golang.org/x/net", Version: "v0.17.0", IDType: "purl", Status: "not_affected", Justification: "vulnerable_code_not_present", Updated: "2024-09-10T00:00:00Z", SourceFormat: "openvex", Scope: "pkg:oci/longhorn-engine?repository_url=registry.suse.com/rancher/longhorn-engine"},

		// CVE-2024-8888: one Ubuntu assertion fanned out across architectures,
		// the shape strict_arch exists for. Same base_id, so without narrowing
		// all five rows echo the caller's identifier identically.
		{Vendor: "ubuntu", CVE: "CVE-2024-8888", ProductID: "pkg:deb/ubuntu/tar@1.34-1?arch=amd64&distro=ubuntu-22.04", BaseID: "pkg:deb/ubuntu/tar?distro=ubuntu-22.04", Version: "1.34-1", IDType: "purl", Status: "not_affected", Justification: "vulnerable_code_not_present", Updated: "2024-05-01T00:00:00Z", SourceFormat: "openvex"},
		{Vendor: "ubuntu", CVE: "CVE-2024-8888", ProductID: "pkg:deb/ubuntu/tar@1.34-1?arch=arm64&distro=ubuntu-22.04", BaseID: "pkg:deb/ubuntu/tar?distro=ubuntu-22.04", Version: "1.34-1", IDType: "purl", Status: "not_affected", Justification: "vulnerable_code_not_present", Updated: "2024-05-01T00:00:00Z", SourceFormat: "openvex"},
		{Vendor: "ubuntu", CVE: "CVE-2024-8888", ProductID: "pkg:deb/ubuntu/tar@1.34-1?arch=s390x&distro=ubuntu-22.04", BaseID: "pkg:deb/ubuntu/tar?distro=ubuntu-22.04", Version: "1.34-1", IDType: "purl", Status: "not_affected", Justification: "vulnerable_code_not_present", Updated: "2024-05-01T00:00:00Z", SourceFormat: "openvex"},
		{Vendor: "ubuntu", CVE: "CVE-2024-8888", ProductID: "pkg:deb/ubuntu/tar@1.34-1?arch=source&distro=ubuntu-22.04", BaseID: "pkg:deb/ubuntu/tar?distro=ubuntu-22.04", Version: "1.34-1", IDType: "purl", Status: "not_affected", Justification: "vulnerable_code_not_present", Updated: "2024-05-01T00:00:00Z", SourceFormat: "openvex"},
		{Vendor: "ubuntu", CVE: "CVE-2024-8888", ProductID: "pkg:deb/ubuntu/tar@1.34-1?distro=ubuntu-22.04", BaseID: "pkg:deb/ubuntu/tar?distro=ubuntu-22.04", Version: "1.34-1", IDType: "purl", Status: "not_affected", Justification: "vulnerable_code_not_present", Updated: "2024-05-01T00:00:00Z", SourceFormat: "openvex"},
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
	// Two seeded rows (purl + cpe) of one Red Hat assertion; they agree on
	// every statement-level field, so the encoder groups them into one
	// statement naming both products.
	if len(stmts) != 1 {
		t.Fatalf("expected 1 grouped statement, got %d", len(stmts))
	}
	if got := len(stmts[0].Products); got != 2 {
		t.Fatalf("expected 2 products on the grouped statement, got %d", got)
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
	// One assertion, both identifiers echoed into its products[].
	if len(stmts) != 1 {
		t.Fatalf("expected 1 grouped statement (purl + cpe), got %d", len(stmts))
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

func TestStatements_RequiresCVEsOrProducts(t *testing.T) {
	// neither cves nor products → 400
	resp := post(t, "/v1/statements", map[string]any{})
	expectStatus(t, resp, 400)

	// products without cves is now valid (broad mode) — see
	// TestStatements_BroadMode for the full assertion.
	resp = post(t, "/v1/statements", map[string]any{
		"products": []string{"pkg:rpm/redhat/openssl@3.0.7-27.el9"},
	})
	expectStatus(t, resp, 200)
}

// TestStatements_BroadMode: products-only query returns every statement
// touching the matched products, across multiple CVEs, with no CVE filter.
func TestStatements_BroadMode(t *testing.T) {
	resp := post(t, "/v1/statements", map[string]any{
		"products": []string{
			"pkg:rpm/redhat/openssl@3.0.7-27.el9",
			"pkg:rpm/redhat/nginx@1.22.1-4.el9",
		},
	})
	expectStatus(t, resp, 200)
	stmts := decodeOpenVEXStatements(t, resp)
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements across 2 CVEs, got %d", len(stmts))
	}
	cves := map[string]bool{}
	for _, s := range stmts {
		cves[s.Vulnerability.Name] = true
	}
	if !cves["CVE-2024-1234"] || !cves["CVE-2024-5678"] {
		t.Fatalf("expected CVE-2024-1234 and CVE-2024-5678, got %v", cves)
	}
}

// TestStatements_Truncation: hitting the cap (forced low via request limit)
// returns 206 + X-Reel-Truncated, and the next-offset header pages the rest.
func TestStatements_Truncation(t *testing.T) {
	// CVE-2024-1234 has 2 statements; limit=1 forces truncation.
	resp := post(t, "/v1/statements", map[string]any{
		"cves":  []string{"CVE-2024-1234"},
		"limit": 1,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 (truncation signalled via header, not 206), got %d: %s", resp.StatusCode, body)
	}
	if resp.Header.Get("X-Reel-Truncated") != "true" {
		t.Errorf("expected X-Reel-Truncated: true, got %q", resp.Header.Get("X-Reel-Truncated"))
	}
	if resp.Header.Get("X-Reel-Next-Offset") != "1" {
		t.Errorf("expected X-Reel-Next-Offset: 1, got %q", resp.Header.Get("X-Reel-Next-Offset"))
	}

	// Second page: offset 1, limit 1 returns the last row, no truncation.
	resp2 := post(t, "/v1/statements", map[string]any{
		"cves":   []string{"CVE-2024-1234"},
		"limit":  1,
		"offset": 1,
	})
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on last page, got %d", resp2.StatusCode)
	}
	if resp2.Header.Get("X-Reel-Truncated") != "" {
		t.Errorf("last page should not be truncated, got X-Reel-Truncated=%q", resp2.Header.Get("X-Reel-Truncated"))
	}
}

// TestStatements_Gzip: an explicit Accept-Encoding: gzip yields a compressed,
// decodable body. (Set manually so Go's transport doesn't transparently
// decompress, which it does when it adds the header itself.)
func TestStatements_Gzip(t *testing.T) {
	data, _ := json.Marshal(map[string]any{"cves": []string{"CVE-2024-1234"}})
	req, _ := http.NewRequest("POST", serverURL+"/v1/statements", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("expected Content-Encoding: gzip, got %q", resp.Header.Get("Content-Encoding"))
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gz.Close()
	var doc struct {
		Statements []openVEXStatement `json:"statements"`
	}
	if err := json.NewDecoder(gz).Decode(&doc); err != nil {
		t.Fatalf("decode gzipped openvex: %v", err)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("expected 1 grouped statement, got %d", len(doc.Statements))
	}
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
	// Default sbom-max-mb is 5MB; send 6MB to exceed the cap.
	big := strings.Repeat("x", 6*1024*1024)
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

func TestStatements_AcceptsSBOMInput(t *testing.T) {
	// SBOM as the source of CVEs and products. The seeded RH statement for
	// CVE-2024-1234 + openssl should match. Regression test for v0.5.0.
	sbom := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"components": []any{
			map[string]any{
				"type": "library",
				"purl": "pkg:rpm/redhat/openssl@3.0.7-27.el9",
			},
		},
		"vulnerabilities": []any{
			map[string]any{"id": "CVE-2024-1234"},
		},
	}
	resp := post(t, "/v1/statements", map[string]any{"sbom": sbom})
	expectStatus(t, resp, 200)

	stmts := decodeOpenVEXStatements(t, resp)
	if len(stmts) == 0 {
		t.Fatal("expected statements derived from SBOM input; got none")
	}
	if stmts[0].Status != "not_affected" {
		t.Errorf("expected not_affected, got %q", stmts[0].Status)
	}
}

func TestStatements_SBOMUnionWithExplicitCVEs(t *testing.T) {
	// SBOM provides CVE-2024-1234; explicit cves[] adds CVE-2024-5678. Union
	// of both should appear in the response (subject to the products filter
	// — both seeded statements have matching products via the SBOM-derived
	// component set).
	sbom := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"components": []any{
			map[string]any{"type": "library", "purl": "pkg:rpm/redhat/openssl@3.0.7-27.el9"},
			map[string]any{"type": "library", "purl": "pkg:rpm/redhat/nginx@1.22.1-4.el9"},
		},
		"vulnerabilities": []any{
			map[string]any{"id": "CVE-2024-1234"},
		},
	}
	resp := post(t, "/v1/statements", map[string]any{
		"sbom": sbom,
		"cves": []string{"CVE-2024-5678"},
	})
	expectStatus(t, resp, 200)

	stmts := decodeOpenVEXStatements(t, resp)
	cves := make(map[string]bool)
	for _, s := range stmts {
		cves[s.Vulnerability.Name] = true
	}
	if !cves["CVE-2024-1234"] {
		t.Errorf("expected CVE-2024-1234 (from SBOM) in result, got %v", cves)
	}
	if !cves["CVE-2024-5678"] {
		t.Errorf("expected CVE-2024-5678 (from explicit cves) in result, got %v", cves)
	}
}

func TestStatements_MalformedSBOM(t *testing.T) {
	resp := post(t, "/v1/statements", map[string]any{
		"sbom": "not-a-cyclonedx-object",
	})
	expectStatus(t, resp, 400)
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

	// Typed decode: counts are ints, version is a string (added in 0.6.5). The
	// old map[string]int target choked on the string version field.
	var stats struct {
		Vendors    int    `json:"vendors"`
		CVEs       int    `json:"cves"`
		Statements int    `json:"statements"`
		Version    string `json:"version"`
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err := json.Unmarshal(body, &stats); err != nil {
		t.Fatalf("decode stats: %s\nbody: %s", err, body)
	}

	if stats.Vendors != 4 {
		t.Fatalf("expected 4 vendors, got %d", stats.Vendors)
	}
	if stats.CVEs != 8 {
		t.Fatalf("expected 8 CVEs, got %d", stats.CVEs)
	}
	if stats.Statements != 14 {
		t.Fatalf("expected 14 statements, got %d", stats.Statements)
	}
	if stats.Version == "" {
		t.Fatalf("expected /v1/stats to carry a version field; body: %s", body)
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

// --- /v1/analyze broad-mode synthesis (empty-vulns path, v0.5.1) ---

// --- product-scoped statements (Rancher VEX) + scope gate ---

const longhornImage = "pkg:oci/longhorn-engine?repository_url=registry.suse.com/rancher/longhorn-engine"

// A product-scoped not_affected is withheld when the caller names no scope —
// it must never suppress findings for an image it wasn't asserted about.
func TestStatements_ScopeWithheldByDefault(t *testing.T) {
	resp := post(t, "/v1/statements", map[string]any{
		"cves": []string{"CVE-2024-7777"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("expected 204 (scoped row withheld without scope), got %d", resp.StatusCode)
	}
}

// Naming the matching scope surfaces the row, with scope= disclosed in status_notes.
func TestStatements_ScopeMatched(t *testing.T) {
	resp := post(t, "/v1/statements", map[string]any{
		"cves":   []string{"CVE-2024-7777"},
		"scopes": []string{longhornImage},
	})
	expectStatus(t, resp, 200)
	stmts := decodeOpenVEXStatements(t, resp)
	if len(stmts) != 1 {
		t.Fatalf("expected 1 scoped statement, got %d", len(stmts))
	}
	if stmts[0].Supplier != "rancher" || stmts[0].Status != "not_affected" {
		t.Errorf("unexpected statement: supplier=%q status=%q", stmts[0].Supplier, stmts[0].Status)
	}
	if !strings.Contains(stmts[0].StatusNotes, "scope="+longhornImage) {
		t.Errorf("status_notes should disclose scope, got %q", stmts[0].StatusNotes)
	}
}

// A non-matching scope does not surface the row.
func TestStatements_ScopeMismatch(t *testing.T) {
	resp := post(t, "/v1/statements", map[string]any{
		"cves":   []string{"CVE-2024-7777"},
		"scopes": []string{"pkg:oci/other?repository_url=r.io/x/other"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("expected 204 (non-matching scope), got %d", resp.StatusCode)
	}
}

// /v1/analyze derives the scope from the SBOM's root component: scanning the
// longhorn image applies the scoped not_affected to its bundled Go module.
func TestAnalyze_ScopeGateAppliesForMatchingImage(t *testing.T) {
	result := analyzeSBOM(t, map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"metadata": map[string]any{
			"component": map[string]any{
				"type": "container",
				"name": "longhorn-engine",
				"purl": "pkg:oci/longhorn-engine@sha256:deadbeef?repository_url=registry.suse.com/rancher/longhorn-engine",
			},
		},
		"components": []any{
			map[string]any{"type": "library", "name": "x/net", "purl": "pkg:golang/golang.org/x/net@v0.17.0", "bom-ref": "c1"},
		},
	})
	vulns, ok := result["vulnerabilities"].([]any)
	if !ok {
		t.Fatalf("expected synthesised vulnerabilities[], got %v", result["vulnerabilities"])
	}
	var found bool
	for _, raw := range vulns {
		v := raw.(map[string]any)
		if v["id"] == "CVE-2024-7777" {
			found = true
			a, ok := v["analysis"].(map[string]any)
			if !ok || a["state"] != "not_affected" {
				t.Fatalf("expected not_affected analysis on scoped CVE, got %v", v["analysis"])
			}
		}
	}
	if !found {
		t.Fatal("scoped CVE-2024-7777 should be applied when scanning its image")
	}
}

// Scanning a DIFFERENT image must NOT apply the longhorn-scoped verdict, even
// though the same Go module is present — the over-suppression guard.
func TestAnalyze_ScopeGateWithheldForOtherImage(t *testing.T) {
	result := analyzeSBOM(t, map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"metadata": map[string]any{
			"component": map[string]any{
				"type": "container",
				"name": "unrelated",
				"purl": "pkg:oci/unrelated@sha256:cafe?repository_url=registry.example.com/foo/unrelated",
			},
		},
		"components": []any{
			map[string]any{"type": "library", "name": "x/net", "purl": "pkg:golang/golang.org/x/net@v0.17.0", "bom-ref": "c1"},
		},
	})
	if v, ok := result["vulnerabilities"].([]any); ok {
		for _, raw := range v {
			if raw.(map[string]any)["id"] == "CVE-2024-7777" {
				t.Fatal("longhorn-scoped CVE leaked onto an unrelated image scan")
			}
		}
	}
}

func analyzeSBOM(t *testing.T, sbom map[string]any) map[string]any {
	t.Helper()
	resp := post(t, "/v1/analyze", map[string]any{"sbom": sbom})
	expectStatus(t, resp, 200)
	var result map[string]any
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode analyze response: %s\nbody: %s", err, body)
	}
	return result
}

// Components-only SBOM (no vulnerabilities[]) → /v1/analyze queries broad mode
// and synthesises a vulnerabilities[] entry per matched CVE, annotated.
func TestAnalyze_EmptyVulnsBroadModeSynthesises(t *testing.T) {
	result := analyzeSBOM(t, map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"components": []any{
			map[string]any{"type": "library", "name": "openssl", "purl": "pkg:rpm/redhat/openssl@3.0.7-27.el9", "bom-ref": "c1"},
		},
	})
	vulns, ok := result["vulnerabilities"].([]any)
	if !ok || len(vulns) == 0 {
		t.Fatalf("expected synthesised vulnerabilities[], got %v", result["vulnerabilities"])
	}
	var found bool
	for _, raw := range vulns {
		v := raw.(map[string]any)
		if v["id"] == "CVE-2024-1234" {
			found = true
			analysis, ok := v["analysis"].(map[string]any)
			if !ok || analysis["state"] != "not_affected" {
				t.Fatalf("expected not_affected analysis on synthesised CVE, got %v", v["analysis"])
			}
		}
	}
	if !found {
		t.Fatal("expected synthesised CVE-2024-1234 from broad-mode lookup")
	}
}

// Components-only SBOM with no vendor match → no synthesised vulns.
func TestAnalyze_EmptyVulnsNoBroadMatchReturnsSBOMUnchanged(t *testing.T) {
	result := analyzeSBOM(t, map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"components": []any{
			map[string]any{"type": "library", "name": "unknown", "purl": "pkg:npm/unknown@1.0"},
		},
	})
	if v, ok := result["vulnerabilities"]; ok {
		if arr, _ := v.([]any); len(arr) != 0 {
			t.Fatalf("expected no synthesised vulnerabilities, got %v", v)
		}
	}
}

// Non-empty vulnerabilities[] → annotate only; broad-mode CVEs on the same
// components must NOT be added (httpd's CVE-2024-3333 here).
func TestAnalyze_NonEmptyVulnsBroadModeDoesNotAdd(t *testing.T) {
	result := analyzeSBOM(t, map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"components": []any{
			map[string]any{"type": "library", "name": "openssl", "purl": "pkg:rpm/redhat/openssl@3.0.7-27.el9"},
			map[string]any{"type": "library", "name": "httpd", "purl": "pkg:rpm/redhat/httpd@2.4.57-5.el9"},
		},
		"vulnerabilities": []any{
			map[string]any{"id": "CVE-2024-1234"},
		},
	})
	vulns := result["vulnerabilities"].([]any)
	if len(vulns) != 1 {
		t.Fatalf("expected exactly 1 vuln (annotate-only), got %d — broad-mode CVEs must not be added", len(vulns))
	}
	if vulns[0].(map[string]any)["id"] != "CVE-2024-1234" {
		t.Fatalf("unexpected vuln %v", vulns[0])
	}
}

// Synthesised affects[].ref is rewritten to BOM-Link form.
func TestAnalyze_BomLinkRefsOnSynthesisedEntries(t *testing.T) {
	result := analyzeSBOM(t, map[string]any{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.5",
		"serialNumber": "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		"version":      float64(1),
		"components": []any{
			map[string]any{"type": "library", "name": "openssl", "purl": "pkg:rpm/redhat/openssl@3.0.7-27.el9", "bom-ref": "pkg:openssl"},
		},
	})
	vulns := result["vulnerabilities"].([]any)
	var ref string
	for _, raw := range vulns {
		v := raw.(map[string]any)
		if v["id"] == "CVE-2024-1234" {
			ref = v["affects"].([]any)[0].(map[string]any)["ref"].(string)
		}
	}
	want := "urn:cdx:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/1#pkg:openssl"
	if ref != want {
		t.Fatalf("synthesised affects ref: got %q, want %q", ref, want)
	}
}

// TestAnalyze_UserVEXOnly_Override exercises the user-VEX-only flow:
// the user asserts a status that contradicts the seeded vendor row;
// the merged OpenVEX response carries the user's claim with
// match_reason=from_user_vex in status_notes.
func TestAnalyze_UserVEXOnly_Override(t *testing.T) {
	userDoc := map[string]any{
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
	resp := post(t, "/v1/analyze", map[string]any{"user_vex": []any{userDoc}})
	expectStatus(t, resp, 200)

	stmts := decodeOpenVEXStatements(t, resp)
	if len(stmts) == 0 {
		t.Fatal("expected at least the user statement in the merged set")
	}
	var foundUser bool
	for _, s := range stmts {
		if s.Supplier == "acme-internal" && s.Status == "affected" {
			foundUser = true
			if !strings.Contains(s.StatusNotes, "match_reason=from_user_vex") {
				t.Errorf("user row should carry match_reason=from_user_vex, got status_notes=%q", s.StatusNotes)
			}
			if strings.Contains(s.StatusNotes, "source_format=") {
				t.Errorf("user row should not carry source_format prefix, got status_notes=%q", s.StatusNotes)
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
	if !foundUser {
		t.Errorf("merged response did not include the user statement; got %+v", stmts)
	}
}

// TestAnalyze_BothInputs_OverrideInRollup is the headline override scenario.
// Vendor not_affected at one base_id (CPE) collides with user affected at
// a different base_id (PURL) for the same CVE. Without the userCVEs
// override, statusPriority would let the vendor's not_affected (priority 4)
// outrank the user's affected (priority 1). With the override, the
// user's claim wins absolutely on the per-CVE annotation rollup.
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
	userDoc := map[string]any{
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
		"sbom":     sbom,
		"user_vex": []any{userDoc},
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
		t.Fatalf("override failed: expected exploitable (from user affected), got %v — vendor not_affected on a different base_id should not have leaked into the rollup",
			analysis["state"])
	}
	detail := analysis["detail"].(string)
	if !strings.Contains(detail, "acme-internal") {
		t.Errorf("detail should mention user supplier, got %q", detail)
	}
}

func TestAnalyze_AnnotatesTrivyShapeRPMSBOM(t *testing.T) {
	// Trivy emits RPM PURLs with ?arch=...&distro=redhat-X.Y&epoch=N qualifiers.
	// The seeded RH statement (CVE-2024-1234, openssl) uses the bare PURL form
	// that mainstream RH CSAF publishes. The resolver must bridge these shapes
	// or realistic Trivy SBOMs come back unannotated. Regression test for
	// v0.4.3 — TestAnalyze_SBOMOnly_Annotates uses a clean PURL and missed this.
	sbom := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"components": []any{
			map[string]any{
				"type": "library",
				"name": "openssl",
				"purl": "pkg:rpm/redhat/openssl@3.0.7-25.el9_3?arch=x86_64&distro=redhat-9.3&epoch=1",
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
		t.Fatal("expected analysis field on Trivy-shape RPM PURL; got passthrough")
	}
	if analysis["state"] != "not_affected" {
		t.Fatalf("expected not_affected, got %v", analysis["state"])
	}
	if analysis["justification"] != "code_not_present" {
		t.Fatalf("expected code_not_present, got %v", analysis["justification"])
	}
}

func TestStatements_ResolvesTrivyShapeRPMToBareStored(t *testing.T) {
	// Same coverage as TestAnalyze_AnnotatesTrivyShapeRPMSBOM but at the
	// /v1/statements query API. A scanner-shape RPM PURL with ?distro= must
	// resolve against the bare stored RH form. Without the resolver's
	// distro-stripped candidate, this returns 0 statements / 204.
	resp := post(t, "/v1/statements", map[string]any{
		"cves":     []string{"CVE-2024-1234"},
		"products": []string{"pkg:rpm/redhat/openssl@3.0.7-25.el9_3?arch=x86_64&distro=redhat-9.3&epoch=1"},
	})
	expectStatus(t, resp, 200)
	stmts := decodeOpenVEXStatements(t, resp)
	if len(stmts) == 0 {
		t.Fatal("expected statements for Trivy-shape RPM PURL; resolver didn't bridge to bare stored shape")
	}
	if stmts[0].Status != "not_affected" {
		t.Errorf("expected not_affected, got %q", stmts[0].Status)
	}
}

func TestAnalyze_EmitsBOMLinkRefsInAnnotatedSBOM(t *testing.T) {
	// Trivy --vex matches CycloneDX VEX statements to scan findings via
	// BOM-Link in affects[].ref. /v1/analyze must rewrite raw PURL refs to
	// BOM-Link form so the response is consumable by the scanner without
	// "WARN [vex] Unable to parse BOM-Link" complaints. Regression test for
	// v0.4.4.
	sbom := map[string]any{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.5",
		"serialNumber": "urn:uuid:test-1234-bomlink",
		"version":      1,
		"components": []any{
			map[string]any{
				"type":    "library",
				"name":    "openssl",
				"bom-ref": "comp-openssl",
				"purl":    "pkg:rpm/redhat/openssl@3.0.7-25.el9_3?arch=x86_64&distro=redhat-9.3&epoch=1",
			},
		},
		"vulnerabilities": []any{
			map[string]any{
				"id": "CVE-2024-1234",
				"affects": []any{
					map[string]any{
						"ref": "pkg:rpm/redhat/openssl@3.0.7-25.el9_3?arch=x86_64&distro=redhat-9.3&epoch=1",
					},
				},
			},
		},
	}
	resp := post(t, "/v1/analyze", map[string]any{"sbom": sbom})
	expectStatus(t, resp, 200)

	var result map[string]any
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(body, &result)

	affects := result["vulnerabilities"].([]any)[0].(map[string]any)["affects"].([]any)
	ref := affects[0].(map[string]any)["ref"].(string)
	want := "urn:cdx:test-1234-bomlink/1#comp-openssl"
	if ref != want {
		t.Fatalf("ref: got %q, want %q", ref, want)
	}
	// And the analysis block from the seeded RH not_affected statement should
	// also be present — the BOM-Link rewrite is in addition to annotation,
	// not instead of it.
	vuln := result["vulnerabilities"].([]any)[0].(map[string]any)
	analysis, ok := vuln["analysis"].(map[string]any)
	if !ok {
		t.Fatal("expected analysis field alongside BOM-Link rewrite")
	}
	if analysis["state"] != "not_affected" {
		t.Errorf("expected analysis.state=not_affected, got %v", analysis["state"])
	}
}

func TestAnalyze_RequiresAtLeastOneInput(t *testing.T) {
	resp := post(t, "/v1/analyze", map[string]any{})
	expectStatus(t, resp, 400)
}

func TestAnalyze_MalformedUserVEX(t *testing.T) {
	resp := post(t, "/v1/analyze", map[string]any{
		"user_vex": []any{
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

// TestVexctl_AcceptsAnalyzeUserVEXOutput is the new-feature variant of
// the interop check: the user-VEX-only flow on /v1/analyze emits a
// merged OpenVEX doc with from_user_vex match_reason. vexctl must
// accept it identically — the merge semantic is internal to reel-vex; the
// wire format is plain OpenVEX 0.2.0.
func TestVexctl_AcceptsAnalyzeUserVEXOutput(t *testing.T) {
	if _, err := exec.LookPath("vexctl"); err != nil {
		t.Skip("vexctl not installed; skipping interop check")
	}

	userDoc := map[string]any{
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
	resp := post(t, "/v1/analyze", map[string]any{"user_vex": []any{userDoc}})
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

// waitForIngestQuiet polls /v1/ingest until the running flag drops to false.
// Used by TestMain to wait for the startup ingest cycle (against the
// placeholder example.invalid adapter) to finish before any test that might
// race it.
func waitForIngestQuiet(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			var status struct {
				Running bool `json:"running"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&status)
			resp.Body.Close()
			if !status.Running {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("ingest still running after %s", timeout)
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

// TestStatements_StrictArch exercises the arch narrowing against real
// Postgres, not the in-memory fake — the SQL superset predicate and the Go
// exact pass have to agree, and a Fake/Postgres divergence in
// QueryStatements is a mistake this codebase has made before.
func TestStatements_StrictArch(t *testing.T) {
	const amd64 = "pkg:deb/ubuntu/tar@1.34-1?arch=amd64&distro=ubuntu-22.04"

	t.Run("off by default", func(t *testing.T) {
		resp := post(t, "/v1/statements", map[string]any{
			"cves":     []string{"CVE-2024-8888"},
			"products": []string{amd64},
		})
		expectStatus(t, resp, 200)
		if got := resp.Header.Get("X-Reel-Statements"); got != "5" {
			t.Errorf("X-Reel-Statements: got %q, want 5", got)
		}
		if got := resp.Header.Get("X-Reel-Arch"); got != "" {
			t.Errorf("X-Reel-Arch should be absent, got %q", got)
		}
	})

	t.Run("narrows to the caller's arch plus the independents", func(t *testing.T) {
		resp := post(t, "/v1/statements", map[string]any{
			"cves":        []string{"CVE-2024-8888"},
			"products":    []string{amd64},
			"strict_arch": true,
		})
		expectStatus(t, resp, 200)
		// amd64 + source + the unqualified row; arm64 and s390x dropped.
		if got := resp.Header.Get("X-Reel-Statements"); got != "3" {
			t.Errorf("X-Reel-Statements: got %q, want 3", got)
		}
		if got := resp.Header.Get("X-Reel-Arch"); got != "amd64" {
			t.Errorf("X-Reel-Arch: got %q, want amd64", got)
		}
		stmts := decodeOpenVEXStatements(t, resp)
		if len(stmts) != 1 {
			t.Fatalf("the surviving rows are one assertion; expected 1 statement, got %d", len(stmts))
		}
	})
}

// TestStatements_GroupedResponseIsUnique guards the schema rule that made
// grouping necessary: OpenVEX 0.2.0 declares statements with uniqueItems, and
// a products-bearing query used to emit byte-identical duplicates.
func TestStatements_GroupedResponseIsUnique(t *testing.T) {
	resp := post(t, "/v1/statements", map[string]any{
		"cves":     []string{"CVE-2024-8888"},
		"products": []string{"pkg:deb/ubuntu/tar@1.34-1?arch=amd64&distro=ubuntu-22.04"},
	})
	expectStatus(t, resp, 200)
	stmts := decodeOpenVEXStatements(t, resp)

	seen := make(map[string]bool, len(stmts))
	for _, s := range stmts {
		raw, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("marshal statement: %v", err)
		}
		if seen[string(raw)] {
			t.Fatalf("duplicate statement in response (violates uniqueItems): %s", raw)
		}
		seen[string(raw)] = true
	}
}
