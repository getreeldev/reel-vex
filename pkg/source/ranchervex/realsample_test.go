package ranchervex

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/getreeldev/reel-vex/pkg/source"
)

// TestAdapter_RealSample runs the adapter over a trimmed real-feed fixture
// (testdata/rancher-sample.openvex.json) carved straight from the published
// rancher.openvex.json. It guards against upstream restructuring: the real
// shapes — golang product+subcomponent, stdlib@version subcomponents, the
// repository_url-qualified OCI product, and the non-CVE (SUSE-SU / GHSA) tail
// we skip — exercise the parser as published, not just hand-authored fixtures.
func TestAdapter_RealSample(t *testing.T) {
	payload, err := os.ReadFile("testdata/rancher-sample.openvex.json")
	if err != nil {
		t.Fatal(err)
	}
	// Serve the trimmed real-feed fixture as a single per-package file behind a
	// one-entry index — exercises the index path against real shapes.
	files := map[string][]byte{"pkg/sample/scan.openvex.json": payload}
	server, _ := serveRepo(t, files, nil)
	defer server.Close()
	a := newAdapter(t, server)
	var stmts []source.Statement
	if err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
		stmts = append(stmts, s)
		return nil
	}); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// The 4 CVE-named statements emit (one subcomponent each); the SUSE-SU and
	// GHSA statements are skipped.
	if len(stmts) != 4 {
		t.Fatalf("emitted %d rows, want 4: %+v", len(stmts), stmts)
	}

	var sawHarvester, sawStdlib bool
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
			if !strings.HasPrefix(s.Version, "v0.0.0") {
				t.Errorf("harvester-scoped version: got %q", s.Version)
			}
		}
		if s.BaseID == "pkg:golang/stdlib" {
			sawStdlib = true
			if s.Version != "v1.19.2" {
				t.Errorf("stdlib version: got %q", s.Version)
			}
		}
	}
	if !sawHarvester {
		t.Error("expected the harvester-scoped CVE-2019-11881 row")
	}
	if !sawStdlib {
		t.Error("expected the stdlib@v1.19.2 row")
	}
}
