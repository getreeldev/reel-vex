package ranchervex

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestAdapter_RealSample runs the adapter over a trimmed real-feed fixture
// (testdata/rancher-sample.openvex.json) carved from Rancher's published
// statements. It guards against upstream restructuring: the real
// shapes — golang product+subcomponent, stdlib@version subcomponents, the
// repository_url-qualified OCI product, and the non-CVE (SUSE-SU / GHSA) tail
// we skip — exercise the parser as published, not just hand-authored fixtures.
func TestAdapter_RealSample(t *testing.T) {
	payload, err := os.ReadFile("testdata/rancher-sample.openvex.json")
	if err != nil {
		t.Fatal(err)
	}
	// Serve the trimmed real-feed fixture as a single per-package file behind a
	// one-entry index in a snapshot — exercises the snapshot path against real
	// shapes.
	server, _ := serveRepo(t, snapEntry{"pkg/sample/scan.openvex.json", payload})
	defer server.Close()
	stmts, res, err := syncAll(t, newAdapter(t, server), time.Time{})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !res.Complete {
		t.Error("the real sample parsed whole; want Complete")
	}

	// The 4 CVE-named statements (one subcomponent each) make 3 rows: the two
	// kube-api-auth statements state one verdict for two versions of one
	// module, so they are one exact-list row. The SUSE-SU and GHSA statements
	// are skipped.
	if len(stmts) != 3 {
		t.Fatalf("emitted %d rows, want 3: %+v", len(stmts), stmts)
	}

	var sawHarvester, sawStdlib, sawKubeAPIAuth bool
	for _, s := range stmts {
		if !strings.HasPrefix(s.CVE, "CVE-") {
			t.Errorf("emitted a non-CVE row: %q", s.CVE)
		}
		if s.Scope == "" {
			t.Errorf("emitted an unscoped row: %+v", s)
		}
		if s.IDType != "purl" || !strings.HasPrefix(s.ProductID, "pkg:") {
			t.Errorf("unexpected identifier shape: %+v", s)
		}
		if strings.Contains(s.BaseID, "@") {
			t.Errorf("base_id should be version-stripped: %q", s.BaseID)
		}
		// The OCI/SUSE-SU product must never leak through as a scope (its
		// statement is non-CVE-named and skipped).
		if strings.HasPrefix(s.CVE, "SUSE-SU") || strings.HasPrefix(s.CVE, "GHSA") {
			t.Errorf("a skipped statement class leaked: %q", s.CVE)
		}

		// Concrete mappings from the real data: subcomponent → product_id/base_id,
		// product @id → scope.
		if s.Scope == "pkg:golang/github.com/harvester/harvester" {
			sawHarvester = true
			if s.BaseID != "pkg:golang/github.com/rancher/rancher" {
				t.Errorf("harvester-scoped base_id: got %q", s.BaseID)
			}
			if len(s.Versions) != 1 || !strings.HasPrefix(s.Versions[0], "v0.0.0") {
				t.Errorf("harvester-scoped versions: got %v", s.Versions)
			}
		}
		if s.BaseID == "pkg:golang/stdlib" {
			sawStdlib = true
			if strings.Join(s.Versions, ",") != "v1.19.2" {
				t.Errorf("stdlib versions: got %v", s.Versions)
			}
		}
		if s.Scope == "pkg:golang/github.com/rancher/kube-api-auth" {
			sawKubeAPIAuth = true
			if len(s.Versions) != 2 {
				t.Errorf("kube-api-auth: want one row carrying both versions, got %v", s.Versions)
			}
		}
		if s.VersionKind != "exact" || s.Version != "" {
			t.Errorf("want an exact-list row with no single Version: %+v", s)
		}
	}
	if !sawKubeAPIAuth {
		t.Error("expected the kube-api-auth row")
	}
	if !sawHarvester {
		t.Error("expected the harvester-scoped CVE-2019-11881 row")
	}
	if !sawStdlib {
		t.Error("expected the stdlib@v1.19.2 row")
	}
}
