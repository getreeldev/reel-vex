package amazonalas

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/getreeldev/reel-vex/pkg/source"
)

// fixture reads a committed testdata file (kept uncompressed for readability;
// the gzip step happens in the test server).
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func gzipBytes(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		t.Fatalf("gzip fixture: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// crawlServer mounts the three-hop crawl on one httptest server and returns the
// server plus the mirror.list URL to hand to New(). mirrorPath is the path the
// adapter's config URL points at — it carries the distro segment ("2" or
// "al2023") that New() infers the distro from, mirroring the real cdn URLs.
// mirror.list resolves to <server><repoPath>/ where repomd.xml +
// updateinfo.xml.gz live.
func crawlServer(t *testing.T, mirrorPath, repoPath, updateInfoFixture string) (*httptest.Server, string) {
	t.Helper()
	repomd := fixture(t, "repomd.xml")
	gz := gzipBytes(t, fixture(t, updateInfoFixture))

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc(mirrorPath, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s%s/\n", srv.URL, repoPath)
	})
	mux.HandleFunc(repoPath+"/repodata/repomd.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write(repomd)
	})
	mux.HandleFunc(repoPath+"/repodata/updateinfo.xml.gz", func(w http.ResponseWriter, r *http.Request) {
		w.Write(gz)
	})
	return srv, srv.URL + mirrorPath
}

func TestNew(t *testing.T) {
	t.Run("requires id", func(t *testing.T) {
		_, err := New(source.AdapterConfig{Type: Type, URL: "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list"})
		if err == nil {
			t.Fatal("expected error for empty id")
		}
	})
	t.Run("requires url", func(t *testing.T) {
		_, err := New(source.AdapterConfig{Type: Type, ID: "amazon-alas-2"})
		if err == nil {
			t.Fatal("expected error for empty url")
		}
	})
	t.Run("rejects unrecognised distro url", func(t *testing.T) {
		_, err := New(source.AdapterConfig{Type: Type, ID: "x", URL: "https://cdn.amazonlinux.com/2022/core/latest/x86_64/mirror.list"})
		if err == nil {
			t.Fatal("expected error for url with no recognisable distro segment")
		}
	})
	t.Run("defaults name from distro", func(t *testing.T) {
		a, err := New(source.AdapterConfig{Type: Type, ID: "amazon-alas-2023", URL: "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list"})
		if err != nil {
			t.Fatal(err)
		}
		if a.Name() != "Amazon Linux 2023" {
			t.Errorf("Name: got %q, want Amazon Linux 2023", a.Name())
		}
	})
}

func TestDistroFromMirrorURL(t *testing.T) {
	cases := []struct {
		url       string
		wantMajor string
		wantErr   bool
	}{
		{"https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list", "2", false},
		{"https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list", "2023", false},
		// AL1 (amzn1) is out of scope; its path has neither "2" nor "al2023".
		{"https://cdn.amazonlinux.com/latest/main/mirror.list", "", true},
		{"https://cdn.amazonlinux.com/2022/core/latest/x86_64/mirror.list", "", true},
	}
	for _, c := range cases {
		got, err := distroFromMirrorURL(c.url)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: expected error, got major %q", c.url, got.major)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error: %v", c.url, err)
			continue
		}
		if got.major != c.wantMajor {
			t.Errorf("%s: major got %q, want %q", c.url, got.major, c.wantMajor)
		}
	}
}

func TestAdapter_Identity(t *testing.T) {
	a, err := New(source.AdapterConfig{Type: Type, ID: "amazon-alas-2", URL: "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list"})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID() != "amazon-alas-2" {
		t.Errorf("ID: got %q", a.ID())
	}
	if a.Vendor() != "amazon" {
		t.Errorf("Vendor: got %q, want amazon", a.Vendor())
	}
	if a.SourceFormat() != "updateinfo" {
		t.Errorf("SourceFormat: got %q, want updateinfo", a.SourceFormat())
	}
}

// TestAdapter_Sync_amzn2 exercises the full crawl against fixtures and asserts
// CVE fan-out, arch-dedup, epoch handling, version shape, status, and the
// <updated> date parse.
func TestAdapter_Sync_amzn2(t *testing.T) {
	_, mirrorURL := crawlServer(t, "/2/core/latest/x86_64/mirror.list", "/2/core/2.0/x86_64/abc123", "amzn2-updateinfo.xml")
	a, err := New(source.AdapterConfig{Type: Type, ID: "amazon-alas-2", URL: mirrorURL})
	if err != nil {
		t.Fatal(err)
	}

	feed, err := a.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if feed.FeedURL != mirrorURL {
		t.Errorf("FeedURL: got %q", feed.FeedURL)
	}

	var stmts []source.Statement
	if err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
		stmts = append(stmts, s)
		return nil
	}); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// Advisory 1 (ALAS2-2018-1044): 2 CVEs × 3 deduped packages (kernel,
	// kernel-headers [x86_64+i686 collapse to one], perf) = 6 rows.
	// Advisory 2 (ALAS2-2023-2010): 1 CVE × 2 packages (bind, bind-libs) = 2 rows.
	// Total 8.
	if len(stmts) != 8 {
		t.Fatalf("expected 8 statements, got %d:\n%+v", len(stmts), stmts)
	}

	for _, s := range stmts {
		if s.IDType != "purl" {
			t.Errorf("%s: IDType got %q, want purl", s.ProductID, s.IDType)
		}
		if s.Status != "fixed" {
			t.Errorf("%s: Status got %q, want fixed", s.ProductID, s.Status)
		}
		if s.Justification != "" {
			t.Errorf("%s: Justification got %q, want empty", s.ProductID, s.Justification)
		}
		if s.Scope != "" {
			t.Errorf("%s: Scope got %q, want empty", s.ProductID, s.Scope)
		}
	}

	// Arch-dedup: exactly one kernel-headers row per CVE (the i686 duplicate is
	// collapsed). Two CVEs reference it, so two rows total — both for the same
	// base/version, differing only by CVE.
	khBase := "pkg:rpm/amazon/kernel-headers?distro=amazon-2"
	var kh []source.Statement
	for _, s := range stmts {
		if s.BaseID == khBase {
			kh = append(kh, s)
		}
	}
	if len(kh) != 2 {
		t.Fatalf("kernel-headers: expected 2 rows (1 per CVE, arch-deduped), got %d", len(kh))
	}
	for _, s := range kh {
		if s.Version != "4.14.51-66.38.amzn2" {
			t.Errorf("kernel-headers Version got %q, want 4.14.51-66.38.amzn2", s.Version)
		}
		if s.ProductID != khBase+"@4.14.51-66.38.amzn2" {
			t.Errorf("kernel-headers ProductID got %q", s.ProductID)
		}
	}
	cves := map[string]bool{kh[0].CVE: true, kh[1].CVE: true}
	if !cves["CVE-2018-1000199"] || !cves["CVE-2018-3639"] {
		t.Errorf("kernel-headers CVEs got %v, want the two advisory-1 CVEs", cves)
	}

	// <updated date="2018-07-16 01:28:00"/> parsed as UTC.
	wantUpdated := time.Date(2018, 7, 16, 1, 28, 0, 0, time.UTC)
	if !kh[0].Updated.Equal(wantUpdated) {
		t.Errorf("Updated got %v, want %v", kh[0].Updated, wantUpdated)
	}

	// Non-zero epoch (bind has epoch="32") => "epoch:" prefix on Version.
	var bind *source.Statement
	for i := range stmts {
		if stmts[i].BaseID == "pkg:rpm/amazon/bind?distro=amazon-2" {
			bind = &stmts[i]
			break
		}
	}
	if bind == nil {
		t.Fatal("missing bind statement")
	}
	if bind.Version != "32:9.11.4-26.P2.amzn2.5.2" {
		t.Errorf("bind Version got %q, want 32:9.11.4-26.P2.amzn2.5.2", bind.Version)
	}
	if bind.CVE != "CVE-2021-25220" {
		t.Errorf("bind CVE got %q", bind.CVE)
	}
	if bind.ProductID != "pkg:rpm/amazon/bind?distro=amazon-2@32:9.11.4-26.P2.amzn2.5.2" {
		t.Errorf("bind ProductID got %q", bind.ProductID)
	}
}

// TestAdapter_Sync_al2023 checks the 2023 distro qualifier and an epoch="1"
// package matching the spec's example shape.
func TestAdapter_Sync_al2023(t *testing.T) {
	_, mirrorURL := crawlServer(t, "/al2023/core/mirrors/latest/x86_64/mirror.list", "/al2023/core/guids/deadbeef/x86_64", "al2023-updateinfo.xml")
	a, err := New(source.AdapterConfig{Type: Type, ID: "amazon-alas-2023", URL: mirrorURL})
	if err != nil {
		t.Fatal(err)
	}

	var stmts []source.Statement
	if err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
		stmts = append(stmts, s)
		return nil
	}); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// 1 advisory × 1 CVE × 2 packages = 2 rows.
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(stmts))
	}

	byBase := map[string]source.Statement{}
	for _, s := range stmts {
		byBase[s.BaseID] = s
		if s.CVE != "CVE-2021-25220" {
			t.Errorf("%s: CVE got %q", s.BaseID, s.CVE)
		}
	}

	tzdata, ok := byBase["pkg:rpm/amazon/tzdata?distro=amazon-2023"]
	if !ok {
		t.Fatalf("missing tzdata statement; got %v", byBase)
	}
	if tzdata.Version != "2022g-1.amzn2023.0.2" { // epoch 0 elided
		t.Errorf("tzdata Version got %q, want 2022g-1.amzn2023.0.2", tzdata.Version)
	}

	tzjava, ok := byBase["pkg:rpm/amazon/tzdata-java?distro=amazon-2023"]
	if !ok {
		t.Fatalf("missing tzdata-java statement")
	}
	if tzjava.Version != "1:8.2204.0-3.amzn2023.0.2" { // epoch 1 prefixed
		t.Errorf("tzdata-java Version got %q, want 1:8.2204.0-3.amzn2023.0.2", tzjava.Version)
	}
}

// TestAdapter_Sync_MirrorFallthrough verifies that a broken first mirror is
// skipped and the next usable one is used.
func TestAdapter_Sync_MirrorFallthrough(t *testing.T) {
	repomd := fixture(t, "repomd.xml")
	gz := gzipBytes(t, fixture(t, "al2023-updateinfo.xml"))

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mirrorPath := "/al2023/core/mirrors/latest/x86_64/mirror.list"
	good := "/al2023/core/guids/good/x86_64"
	// mirror.list lists a dead base first, then the working one.
	mux.HandleFunc(mirrorPath, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s/al2023/core/guids/dead/x86_64/\n%s%s/\n", srv.URL, srv.URL, good)
	})
	// dead base: repomd.xml 404s (no handler registered for it -> 404).
	mux.HandleFunc(good+"/repodata/repomd.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write(repomd)
	})
	mux.HandleFunc(good+"/repodata/updateinfo.xml.gz", func(w http.ResponseWriter, r *http.Request) {
		w.Write(gz)
	})

	a, err := New(source.AdapterConfig{Type: Type, ID: "amazon-alas-2023", URL: srv.URL + mirrorPath})
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
		n++
		return nil
	}); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 statements after fallthrough, got %d", n)
	}
}

// TestAdapter_Sync_AllMirrorsFail asserts a hard error when no mirror resolves.
func TestAdapter_Sync_AllMirrorsFail(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mirrorPath := "/2/core/latest/x86_64/mirror.list"
	mux.HandleFunc(mirrorPath, func(w http.ResponseWriter, r *http.Request) {
		// A base whose repomd.xml will 404 (no handler).
		fmt.Fprintf(w, "%s/2/core/2.0/x86_64/missing/\n", srv.URL)
	})

	a, err := New(source.AdapterConfig{Type: Type, ID: "amazon-alas-2", URL: srv.URL + mirrorPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error { return nil }); err == nil {
		t.Fatal("expected error when all mirrors fail")
	}
}

// TestAdapter_Sync_EmptyMirrorList asserts a hard error on an empty mirror.list.
func TestAdapter_Sync_EmptyMirrorList(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mirrorPath := "/2/core/latest/x86_64/mirror.list"
	mux.HandleFunc(mirrorPath, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "\n  \n")
	})

	a, err := New(source.AdapterConfig{Type: Type, ID: "amazon-alas-2", URL: srv.URL + mirrorPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error { return nil }); err == nil {
		t.Fatal("expected error on empty mirror.list")
	}
}

// TestPackageVersion covers the epoch-elision rule in isolation.
func TestPackageVersion(t *testing.T) {
	cases := []struct {
		p    Package
		want string
	}{
		{Package{Version: "1.0", Release: "1.amzn2", Epoch: "0"}, "1.0-1.amzn2"},
		{Package{Version: "1.0", Release: "1.amzn2", Epoch: ""}, "1.0-1.amzn2"},
		{Package{Version: "1.0", Release: "1.amzn2", Epoch: "2"}, "2:1.0-1.amzn2"},
		{Package{Version: "8.2204.0", Release: "3.amzn2023.0.2", Epoch: "1"}, "1:8.2204.0-3.amzn2023.0.2"},
	}
	for _, c := range cases {
		if got := packageVersion(c.p); got != c.want {
			t.Errorf("packageVersion(%+v) = %q, want %q", c.p, got, c.want)
		}
	}
}

// TestDedupePackages confirms same-name multi-arch collapse, first-wins order.
func TestDedupePackages(t *testing.T) {
	in := []Package{
		{Name: "kernel-headers", Arch: "x86_64"},
		{Name: "kernel-headers", Arch: "i686"},
		{Name: "kernel", Arch: "x86_64"},
		{Name: "", Arch: "x86_64"}, // unnamed, dropped
	}
	out := dedupePackages(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 deduped packages, got %d: %+v", len(out), out)
	}
	if out[0].Name != "kernel-headers" || out[0].Arch != "x86_64" {
		t.Errorf("first deduped pkg got %+v, want kernel-headers/x86_64 (first wins)", out[0])
	}
	if out[1].Name != "kernel" {
		t.Errorf("second deduped pkg got %q, want kernel", out[1].Name)
	}
}

// TestEmitStatements_SkipsNoCVE asserts advisories with no cve reference emit
// nothing (and are counted), while a self-referencing advisory still emits its
// cve-typed refs.
func TestEmitStatements_SkipsNoCVE(t *testing.T) {
	ui := UpdateInfo{ALASList: []ALAS{
		{
			ID:         "ALAS2-2099-9999",
			References: []Reference{{ID: "ALAS2-2099-9999", Type: "self"}},
			Packages:   []Package{{Name: "foo", Version: "1", Release: "1.amzn2", Epoch: "0", Arch: "x86_64"}},
		},
	}}
	ui.ALASList[0].Updated.Date = "2099-01-01 00:00:00"

	var emitted int
	c, err := emitStatements(ui, distroSpec{major: "2"}, func(s source.Statement) error {
		emitted++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if emitted != 0 {
		t.Errorf("expected 0 emitted for cve-less advisory, got %d", emitted)
	}
	if c.skippedNoCVE != 1 {
		t.Errorf("skippedNoCVE got %d, want 1", c.skippedNoCVE)
	}
}
