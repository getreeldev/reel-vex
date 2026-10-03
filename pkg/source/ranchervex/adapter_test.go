package ranchervex

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/getreeldev/reel-vex/pkg/openvex"
	"github.com/getreeldev/reel-vex/pkg/source"
)

// snapshotPath is where the test server serves the repository snapshot — the
// same path GitHub's archive URL has.
const snapshotPath = "/rancher/vexhub/archive/refs/heads/main.tar.gz"

func mustJSON(t *testing.T, doc openvex.Document) []byte {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}

// snapEntry is one file in a test snapshot, at its repo-relative path.
type snapEntry struct {
	name string
	body []byte
}

// indexJSON builds an index.json listing the given locations.
func indexJSON(t *testing.T, locs ...string) []byte {
	t.Helper()
	type pkg struct {
		ID       string `json:"id"`
		Location string `json:"location"`
	}
	idx := struct {
		Version  int   `json:"version"`
		Packages []pkg `json:"packages"`
	}{Version: 1, Packages: []pkg{}}
	for _, loc := range locs {
		idx.Packages = append(idx.Packages, pkg{ID: "pkg:test/" + loc, Location: loc})
	}
	b, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// buildSnapshot packs entries, in order, into a gzipped tar laid out like a
// GitHub archive: a pax global header carrying the commit, then everything
// under one top-level vexhub-main/ directory.
func buildSnapshot(t *testing.T, entries ...snapEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "pax_global_header",
		PAXRecords: map[string]string{"comment": "0123456789abcdef"}}); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: "vexhub-main/", Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "vexhub-main/" + e.name, Mode: 0o644, Size: int64(len(e.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// serveSnapshot serves the tarball at snapshotPath. The returned counter
// tracks GETs of it.
func serveSnapshot(t *testing.T, tarball []byte) (*httptest.Server, *int) {
	t.Helper()
	gets := 0
	mux := http.NewServeMux()
	mux.HandleFunc(snapshotPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets++
		}
		w.Write(tarball)
	})
	return httptest.NewServer(mux), &gets
}

// serveRepo serves a snapshot whose index.json lists every file, followed by
// the files themselves.
func serveRepo(t *testing.T, files ...snapEntry) (*httptest.Server, *int) {
	t.Helper()
	locs := make([]string, 0, len(files))
	for _, f := range files {
		locs = append(locs, f.name)
	}
	entries := append([]snapEntry{{"index.json", indexJSON(t, locs...)}}, files...)
	return serveSnapshot(t, buildSnapshot(t, entries...))
}

func newAdapter(t *testing.T, server *httptest.Server) *Adapter {
	t.Helper()
	a, err := New(source.AdapterConfig{Type: Type, ID: "rancher-vex", URL: server.URL + snapshotPath})
	if err != nil {
		t.Fatal(err)
	}
	return a.(*Adapter)
}

// syncAll runs Sync with an emit that collects every statement.
func syncAll(t *testing.T, a *Adapter, since time.Time) ([]source.Statement, source.SyncResult, error) {
	t.Helper()
	var stmts []source.Statement
	res, err := a.Sync(context.Background(), since, func(s source.Statement) error {
		stmts = append(stmts, s)
		return nil
	})
	return stmts, res, err
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

// oneStatementDoc is a valid per-package document with a single emitted row.
func oneStatementDoc(t *testing.T, cve string) []byte {
	return mustJSON(t, openvex.Document{Context: openvex.Context, Version: 1,
		Statements: []openvex.Statement{
			stmt(cve, "not_affected", "vulnerable_code_not_present",
				scopedProduct("pkg:golang/github.com/x/y", "pkg:golang/z@v1.0.0")),
		}})
}

func TestNew(t *testing.T) {
	t.Run("requires id", func(t *testing.T) {
		if _, err := New(source.AdapterConfig{Type: Type, URL: "https://x/main.tar.gz"}); err == nil {
			t.Fatal("expected error for empty id")
		}
	})
	t.Run("requires url", func(t *testing.T) {
		if _, err := New(source.AdapterConfig{Type: Type, ID: "rancher-vex"}); err == nil {
			t.Fatal("expected error for empty url")
		}
	})
	t.Run("default name", func(t *testing.T) {
		a, err := New(source.AdapterConfig{Type: Type, ID: "rancher-vex", URL: "https://x/main.tar.gz"})
		if err != nil {
			t.Fatal(err)
		}
		if a.Name() != "SUSE Rancher (OpenVEX)" {
			t.Errorf("default Name(): got %q", a.Name())
		}
	})
}

func TestAdapter_Identity(t *testing.T) {
	a, err := New(source.AdapterConfig{Type: Type, ID: "rancher-vex", URL: "https://x/main.tar.gz"})
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

// TestAdapter_Sync covers a full ingest from the snapshot: read index.json,
// parse every listed per-package file, and emit one row per (product-scope ×
// subcomponent) for the CVE-named, subcomponent-bearing statements only. A
// file index.json does not list is not read.
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
			// skipped: the generator's own error text in place of an identifier.
			stmt("CVE-2024-5", "not_affected", "vulnerable_code_not_present",
				scopedProduct(ociID, "[ERROR] CVE type  not mapped")),
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
	server, gets := serveSnapshot(t, buildSnapshot(t,
		snapEntry{"index.json", indexJSON(t, "pkg/oci/longhorn-engine/scan.openvex.json", "pkg/golang/harvester/scan.openvex.json")},
		snapEntry{"pkg/oci/longhorn-engine/scan.openvex.json", mustJSON(t, ociDoc)},
		snapEntry{"pkg/golang/harvester/scan.openvex.json", mustJSON(t, golangDoc)},
		snapEntry{"pkg/golang/unlisted/scan.openvex.json", oneStatementDoc(t, "CVE-2024-8")},
	))
	defer server.Close()
	a := newAdapter(t, server)

	feed, err := a.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if feed.FeedURL == "" {
		t.Error("expected FeedURL set")
	}

	stmts, res, err := syncAll(t, a, time.Time{})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	// Skips by design (non-CVE, no or bad subcomponent) leave the run complete.
	if !res.Complete {
		t.Error("a snapshot whose every listed file parsed must report Complete")
	}
	if *gets != 1 {
		t.Errorf("snapshot GETs: got %d, want 1", *gets)
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
	if got.ProductID != "pkg:golang/golang.org/x/net" {
		t.Errorf("ProductID (subcomponent without its version): got %q", got.ProductID)
	}
	if got.BaseID != "pkg:golang/golang.org/x/net" {
		t.Errorf("BaseID: got %q", got.BaseID)
	}
	if strings.Join(got.Versions, ",") != "v0.17.0" || got.VersionKind != "exact" || got.Version != "" {
		t.Errorf("Versions/VersionKind/Version: got %v / %q / %q, want [v0.17.0] / exact / empty", got.Versions, got.VersionKind, got.Version)
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
		if s.CVE == "SUSE-SU-2026:1432-1" || s.CVE == "CVE-2024-2" || s.CVE == "CVE-2024-4" || s.CVE == "CVE-2024-5" || s.CVE == "CVE-2024-8" {
			t.Errorf("a skipped statement leaked: %q", s.CVE)
		}
	}
}

// TestAdapter_DocTimestamp: statements carry no timestamp of their own, so the
// emitted row must inherit the document-level timestamp (vendor assertion time),
// not fall back to ingest-time now().
func TestAdapter_DocTimestamp(t *testing.T) {
	doc := openvex.Document{Context: openvex.Context, Version: 1,
		Timestamp: "2026-05-12T09:52:44Z",
		Statements: []openvex.Statement{
			stmt("CVE-2024-7", "not_affected", "vulnerable_code_not_present",
				scopedProduct("pkg:golang/github.com/x/y", "pkg:golang/z@v1.0.0")),
		}}
	server, _ := serveRepo(t, snapEntry{"pkg/golang/x/scan.openvex.json", mustJSON(t, doc)})
	defer server.Close()

	stmts, _, err := syncAll(t, newAdapter(t, server), time.Time{})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(stmts) != 1 {
		t.Fatalf("emitted %d rows, want 1", len(stmts))
	}
	want, _ := time.Parse(time.RFC3339, "2026-05-12T09:52:44Z")
	if !stmts[0].Updated.Equal(want) {
		t.Errorf("Updated: got %v, want doc timestamp %v", stmts[0].Updated, want)
	}
}

// TestAdapter_IgnoresSince: every sync reads the whole snapshot, so a
// watermark changes nothing — the same rows, one GET, Complete.
func TestAdapter_IgnoresSince(t *testing.T) {
	server, gets := serveRepo(t, snapEntry{"pkg/golang/github.com/x/y/scan.openvex.json", oneStatementDoc(t, "CVE-2024-9")})
	defer server.Close()
	stmts, res, err := syncAll(t, newAdapter(t, server), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(stmts) != 1 || !res.Complete || *gets != 1 {
		t.Errorf("got %d rows, complete=%v, %d GETs; want 1, true, 1", len(stmts), res.Complete, *gets)
	}
}

// TestAdapter_TarOrder: files are emitted in the order the snapshot holds
// them, not the order index.json lists them; a file's rows are emitted once
// it has parsed whole, in key order, and two justifications of one key are two
// rows rather than the later one winning.
func TestAdapter_TarOrder(t *testing.T) {
	first := openvex.Document{Context: openvex.Context, Version: 1,
		Statements: []openvex.Statement{
			stmt("CVE-2024-1", "not_affected", "vulnerable_code_not_present",
				scopedProduct("pkg:golang/github.com/a/a", "pkg:golang/z@v1.0.0")),
			stmt("CVE-2024-1", "not_affected", "inline_mitigations_already_exist",
				scopedProduct("pkg:golang/github.com/a/a", "pkg:golang/z@v1.0.0")),
		}}
	server, _ := serveSnapshot(t, buildSnapshot(t,
		snapEntry{"index.json", indexJSON(t, "pkg/b/scan.openvex.json", "pkg/a/scan.openvex.json")},
		snapEntry{"pkg/a/scan.openvex.json", mustJSON(t, first)},
		snapEntry{"pkg/b/scan.openvex.json", oneStatementDoc(t, "CVE-2024-2")},
	))
	defer server.Close()
	stmts, _, err := syncAll(t, newAdapter(t, server), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range stmts {
		got = append(got, s.CVE+"/"+s.Justification)
	}
	want := []string{
		"CVE-2024-1/inline_mitigations_already_exist",
		"CVE-2024-1/vulnerable_code_not_present",
		"CVE-2024-2/vulnerable_code_not_present",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("emit order: got %v, want %v", got, want)
	}
}

// TestAdapter_Incomplete: a listed file the snapshot lacks, or one that does
// not parse, is skipped and makes the run incomplete; the rest still emit.
func TestAdapter_Incomplete(t *testing.T) {
	good := oneStatementDoc(t, "CVE-2024-9")
	for name, entries := range map[string][]snapEntry{
		"listed file missing": {
			{"index.json", indexJSON(t, "pkg/good/scan.openvex.json", "pkg/gone/scan.openvex.json")},
			{"pkg/good/scan.openvex.json", good},
		},
		"listed file unparseable": {
			{"index.json", indexJSON(t, "pkg/good/scan.openvex.json", "pkg/bad/scan.openvex.json")},
			{"pkg/good/scan.openvex.json", good},
			{"pkg/bad/scan.openvex.json", []byte(`{"statements": [ {not json`)},
		},
	} {
		t.Run(name, func(t *testing.T) {
			server, _ := serveSnapshot(t, buildSnapshot(t, entries...))
			defer server.Close()
			stmts, res, err := syncAll(t, newAdapter(t, server), time.Time{})
			if err != nil {
				t.Fatalf("Sync: %v", err)
			}
			if res.Complete {
				t.Error("want Complete=false")
			}
			if len(stmts) != 1 {
				t.Errorf("emitted %d rows, want the good file's 1", len(stmts))
			}
		})
	}
}

// TestAdapter_SnapshotErrors: a snapshot that cannot say what Rancher
// publishes is an error, never an empty Complete run — that would read as the
// vendor withdrawing every statement.
func TestAdapter_SnapshotErrors(t *testing.T) {
	doc := oneStatementDoc(t, "CVE-2024-9")
	for name, tc := range map[string]struct {
		entries []snapEntry
		want    string
	}{
		"no index.json": {[]snapEntry{{"pkg/a/scan.openvex.json", doc}}, "no index.json"},
		"LFS pointer index.json": {[]snapEntry{
			{"index.json", []byte("version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 123\n")},
		}, "Git LFS pointer"},
		"index lists no packages": {[]snapEntry{{"index.json", indexJSON(t)}, {"pkg/a/scan.openvex.json", doc}}, "lists no packages"},
		"no listed file parses": {[]snapEntry{
			{"index.json", indexJSON(t, "pkg/a/scan.openvex.json", "pkg/b/scan.openvex.json")},
			{"pkg/a/scan.openvex.json", []byte("not json")},
		}, "none of the 2 files"},
	} {
		t.Run(name, func(t *testing.T) {
			server, _ := serveSnapshot(t, buildSnapshot(t, tc.entries...))
			defer server.Close()
			_, res, err := syncAll(t, newAdapter(t, server), time.Time{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error containing %q, got %v", tc.want, err)
			}
			if res.Complete {
				t.Error("a failed Sync must not report Complete")
			}
		})
	}
}

// TestAdapter_EmitErrorStops: an error from emit is the orchestrator's and
// stops the sync; it is not one more unparseable file.
func TestAdapter_EmitErrorStops(t *testing.T) {
	server, _ := serveRepo(t,
		snapEntry{"pkg/a/scan.openvex.json", oneStatementDoc(t, "CVE-2024-9")},
		snapEntry{"pkg/b/scan.openvex.json", oneStatementDoc(t, "CVE-2024-10")})
	defer server.Close()
	sentinel := errors.New("disk full")
	calls := 0
	_, err := newAdapter(t, server).Sync(context.Background(), time.Time{}, func(source.Statement) error {
		calls++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("want the emit error, got %v", err)
	}
	if calls != 1 {
		t.Errorf("emit called %d times, want 1 (the sync must stop at the first error)", calls)
	}
}
