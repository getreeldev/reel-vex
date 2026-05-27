package ranchervex

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/getreeldev/reel-vex/pkg/openvex"
	"github.com/getreeldev/reel-vex/pkg/source"
)

// repoPrefix is the owner/repo/ref path layout the adapter parses out of the
// configured index URL.
const repoPrefix = "/rancher/vexhub/refs/heads/main"

func mustJSON(t *testing.T, doc openvex.Document) []byte {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}

// serveRepo mounts the index.json repo layout: an index.json listing every file
// in `files` (keyed by repo-relative location), the per-package docs themselves,
// and a stub GitHub commits+compare API. `changed` is the set of locations the
// compare API reports as modified (the incremental path); empty means "no
// commits since the watermark". The returned counter tracks per-package GETs.
func serveRepo(t *testing.T, files map[string][]byte, changed []string) (*httptest.Server, *int) {
	t.Helper()
	fileGets := 0
	mux := http.NewServeMux()

	mux.HandleFunc(repoPrefix+"/index.json", func(w http.ResponseWriter, r *http.Request) {
		type pkg struct {
			ID       string `json:"id"`
			Location string `json:"location"`
		}
		idx := struct {
			Version  int   `json:"version"`
			Packages []pkg `json:"packages"`
		}{Version: 1}
		for loc := range files {
			idx.Packages = append(idx.Packages, pkg{ID: "pkg:test/" + loc, Location: loc})
		}
		_ = json.NewEncoder(w).Encode(idx)
	})

	for loc, body := range files {
		l, b := loc, body
		mux.HandleFunc(repoPrefix+"/"+l, func(w http.ResponseWriter, r *http.Request) {
			fileGets++
			w.Write(b)
		})
	}

	// Stub GitHub commits API: a non-empty `changed` ⇒ one commit; else none.
	mux.HandleFunc("/repos/rancher/vexhub/commits", func(w http.ResponseWriter, r *http.Request) {
		if len(changed) == 0 {
			w.Write([]byte("[]"))
			return
		}
		w.Write([]byte(`[{"sha":"head","parents":[{"sha":"base"}]}]`))
	})
	// Stub compare API: report `changed` files as modified.
	mux.HandleFunc("/repos/rancher/vexhub/compare/", func(w http.ResponseWriter, r *http.Request) {
		type f struct {
			Filename string `json:"filename"`
			Status   string `json:"status"`
		}
		var out struct {
			Files []f `json:"files"`
		}
		for _, loc := range changed {
			out.Files = append(out.Files, f{Filename: loc, Status: "modified"})
		}
		_ = json.NewEncoder(w).Encode(out)
	})

	return httptest.NewServer(mux), &fileGets
}

// newAdapter builds an adapter pointed at the mock repo, redirecting apiBase to
// the same server so the commits/compare stub is hit instead of github.com.
func newAdapter(t *testing.T, server *httptest.Server) *Adapter {
	t.Helper()
	a, err := New(source.AdapterConfig{Type: Type, ID: "rancher-vex", URL: server.URL + repoPrefix + "/index.json"})
	if err != nil {
		t.Fatal(err)
	}
	ra := a.(*Adapter)
	ra.apiBase = server.URL
	return ra
}

// scopedProduct builds a product Component with subcomponents.
func scopedProduct(id string, subs ...string) openvex.Component {
	c := openvex.Component{ID: id}
	for _, s := range subs {
		c.Subcomponents = append(c.Subcomponents, openvex.Component{ID: s})
	}
	return c
}

func stmt(cve, status, justification string, products ...openvex.Component) openvex.Statement {
	return openvex.Statement{
		Vulnerability: openvex.Vulnerability{Name: cve},
		Products:      products,
		Status:        status,
		Justification: justification,
	}
}

func TestNew(t *testing.T) {
	t.Run("requires id", func(t *testing.T) {
		if _, err := New(source.AdapterConfig{Type: Type, URL: "https://x/index.json"}); err == nil {
			t.Fatal("expected error for empty id")
		}
	})
	t.Run("requires url", func(t *testing.T) {
		if _, err := New(source.AdapterConfig{Type: Type, ID: "rancher-vex"}); err == nil {
			t.Fatal("expected error for empty url")
		}
	})
	t.Run("default name", func(t *testing.T) {
		a, err := New(source.AdapterConfig{Type: Type, ID: "rancher-vex", URL: "https://x/index.json"})
		if err != nil {
			t.Fatal(err)
		}
		if a.Name() != "SUSE Rancher (OpenVEX)" {
			t.Errorf("default Name(): got %q", a.Name())
		}
	})
}

func TestAdapter_Identity(t *testing.T) {
	a, err := New(source.AdapterConfig{Type: Type, ID: "rancher-vex", URL: "https://x/index.json"})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID() != "rancher-vex" {
		t.Errorf("ID: got %q, want rancher-vex", a.ID())
	}
	if a.Vendor() != "rancher" {
		t.Errorf("Vendor: got %q, want rancher", a.Vendor())
	}
	if a.SourceFormat() != "openvex" {
		// db.BulkInsert defaults an empty SourceFormat to "csaf" — forgetting
		// this would silently misclassify every row.
		t.Errorf("SourceFormat: got %q, want openvex", a.SourceFormat())
	}
	if Type != "rancher-vex" {
		t.Errorf("Type constant: got %q, want rancher-vex", Type)
	}
}

// TestAdapter_Sync covers a first (full) ingest: walk the index, fetch every
// per-package file, and emit one row per (product-scope × subcomponent) for the
// CVE-named, subcomponent-bearing statements only.
func TestAdapter_Sync(t *testing.T) {
	const ociID = "pkg:oci/longhorn-engine?repository_url=registry.suse.com/rancher/longhorn-engine"
	ociDoc := openvex.Document{Context: openvex.Context, Author: "SUSE Rancher Security", Version: 1,
		Statements: []openvex.Statement{
			// emitted: CVE-named, OCI product, one Go-module subcomponent.
			stmt("CVE-2024-1", "not_affected", "vulnerable_code_not_present",
				scopedProduct(ociID, "pkg:golang/golang.org/x/net@v0.17.0")),
			// skipped: non-CVE (SUSE advisory).
			stmt("SUSE-SU-2026:1432-1", "not_affected", "vulnerable_code_not_in_execute_path",
				scopedProduct(ociID, "pkg:rpm/suse/libcap2")),
			// skipped: product with no subcomponent (would be a global claim).
			stmt("CVE-2024-2", "not_affected", "", openvex.Component{ID: ociID}),
		}}
	golangDoc := openvex.Document{Context: openvex.Context, Version: 1,
		Statements: []openvex.Statement{
			// emitted: golang-module product, stdlib subcomponent.
			stmt("CVE-2024-3", "not_affected", "vulnerable_code_not_present",
				scopedProduct("pkg:golang/github.com/harvester/harvester", "pkg:golang/stdlib@v1.24.6")),
			// skipped: product carries no identifier — no unscoped (global) row.
			stmt("CVE-2024-4", "not_affected", "vulnerable_code_not_present",
				scopedProduct("", "pkg:golang/x@v1.0.0")),
		}}
	files := map[string][]byte{
		"pkg/oci/longhorn-engine/scan.openvex.json": mustJSON(t, ociDoc),
		"pkg/golang/harvester/scan.openvex.json":    mustJSON(t, golangDoc),
	}
	server, _ := serveRepo(t, files, nil)
	defer server.Close()
	a := newAdapter(t, server)

	feed, err := a.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if feed.FeedURL == "" {
		t.Error("expected FeedURL set")
	}

	var stmts []source.Statement
	if err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
		stmts = append(stmts, s)
		return nil
	}); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// Only the two CVE-named, subcomponent-bearing statements emit.
	if len(stmts) != 2 {
		t.Fatalf("emitted %d rows, want 2: %+v", len(stmts), stmts)
	}

	var got *source.Statement
	for i := range stmts {
		if stmts[i].CVE == "CVE-2024-1" {
			got = &stmts[i]
		}
	}
	if got == nil {
		t.Fatal("CVE-2024-1 row not emitted")
	}
	if got.ProductID != "pkg:golang/golang.org/x/net@v0.17.0" {
		t.Errorf("ProductID (subcomponent): got %q", got.ProductID)
	}
	if got.BaseID != "pkg:golang/golang.org/x/net" {
		t.Errorf("BaseID: got %q", got.BaseID)
	}
	if got.Version != "v0.17.0" {
		t.Errorf("Version: got %q", got.Version)
	}
	if got.Scope != ociID {
		t.Errorf("Scope (product @id): got %q, want %q", got.Scope, ociID)
	}
	if got.Status != "not_affected" || got.Justification != "vulnerable_code_not_present" {
		t.Errorf("status/justification: got %q / %q", got.Status, got.Justification)
	}
	if got.IDType != "purl" {
		t.Errorf("IDType: got %q, want purl", got.IDType)
	}
	if got.Updated.IsZero() {
		t.Error("Updated should fall back to now(), got zero")
	}

	for _, s := range stmts {
		if s.CVE == "SUSE-SU-2026:1432-1" || s.CVE == "CVE-2024-2" || s.CVE == "CVE-2024-4" {
			t.Errorf("a skipped statement leaked: %q", s.CVE)
		}
	}
}

// TestAdapter_Incremental covers the commits-API incremental path: nothing
// changed → skip with zero per-file fetches; a changed file → fetch only it.
func TestAdapter_Incremental(t *testing.T) {
	doc := openvex.Document{Context: openvex.Context, Version: 1,
		Statements: []openvex.Statement{
			stmt("CVE-2024-9", "not_affected", "vulnerable_code_not_present",
				scopedProduct("pkg:golang/github.com/x/y", "pkg:golang/z@v1.0.0")),
		}}
	loc := "pkg/golang/github.com/x/y/scan.openvex.json"
	files := map[string][]byte{loc: mustJSON(t, doc)}
	watermark := time.Now().Add(-time.Hour)

	t.Run("no commits since watermark skips", func(t *testing.T) {
		server, fileGets := serveRepo(t, files, nil)
		defer server.Close()
		a := newAdapter(t, server)
		emitted := 0
		if err := a.Sync(context.Background(), watermark, func(source.Statement) error { emitted++; return nil }); err != nil {
			t.Fatal(err)
		}
		if emitted != 0 {
			t.Errorf("no-change cycle emitted %d, want 0", emitted)
		}
		if *fileGets != 0 {
			t.Errorf("no-change cycle fetched %d files, want 0", *fileGets)
		}
	})

	t.Run("changed file is fetched", func(t *testing.T) {
		server, fileGets := serveRepo(t, files, []string{loc})
		defer server.Close()
		a := newAdapter(t, server)
		var stmts []source.Statement
		if err := a.Sync(context.Background(), watermark, func(s source.Statement) error {
			stmts = append(stmts, s)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if len(stmts) != 1 {
			t.Fatalf("changed cycle emitted %d, want 1", len(stmts))
		}
		if *fileGets != 1 {
			t.Errorf("changed cycle fetched %d files, want exactly 1", *fileGets)
		}
	})
}

// TestAdapter_Sync_LFSPointerError: if index.json itself comes back as a Git LFS
// pointer (quota exhausted), fail with a clear message, not a JSON parse error.
func TestAdapter_Sync_LFSPointerError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc(repoPrefix+"/index.json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 123\n"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	a := newAdapter(t, server)
	err := a.Sync(context.Background(), time.Time{}, func(source.Statement) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "Git LFS pointer") {
		t.Fatalf("want a clear LFS-pointer error, got: %v", err)
	}
}
