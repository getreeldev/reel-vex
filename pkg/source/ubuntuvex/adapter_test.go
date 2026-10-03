package ubuntuvex

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ulikunitz/xz"

	"github.com/getreeldev/reel-vex/pkg/openvex"
	"github.com/getreeldev/reel-vex/pkg/source"
)

// fixtureEntry is one tar entry written into the test tarball: a path inside
// the archive plus the raw file body. Body is bytes (not a typed object) so
// individual tests can inject malformed JSON for the skip-on-error case.
type fixtureEntry struct {
	name string
	body []byte
}

// buildTarXZ assembles the tar.xz the test server hands out. Streaming xz
// writer + tar writer in memory; output is small (a few KB).
func buildTarXZ(t *testing.T, entries []fixtureEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	xzw, err := xz.NewWriter(&buf)
	if err != nil {
		t.Fatalf("xz.NewWriter: %v", err)
	}
	tw := tar.NewWriter(xzw)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     0o644,
			Size:     int64(len(e.body)),
			Typeflag: tar.TypeReg,
			ModTime:  time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar.WriteHeader: %v", err)
		}
		if _, err := tw.Write(e.body); err != nil {
			t.Fatalf("tar.Write: %v", err)
		}
	}
	// Directory entry — for the FilterEntryTypes test.
	dirHdr := &tar.Header{Name: "vex/cve/2026/", Mode: 0o755, Typeflag: tar.TypeDir, ModTime: time.Now()}
	if err := tw.WriteHeader(dirHdr); err != nil {
		t.Fatalf("tar.WriteHeader (dir): %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar.Close: %v", err)
	}
	if err := xzw.Close(); err != nil {
		t.Fatalf("xz.Close: %v", err)
	}
	return buf.Bytes()
}

// mustJSON marshals an OpenVEX document; only used in test code where errors
// are programmer mistakes.
func mustJSON(t *testing.T, doc openvex.Document) []byte {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}

// serveFixture stands up an httptest server that serves the tarball at
// /vex-all.tar.xz with the given Last-Modified. Returns the server (caller
// closes it) plus the bytes-served counter so a test can assert no GET
// happened after a HEAD short-circuit.
func serveFixture(t *testing.T, payload []byte, lastModified time.Time) (*httptest.Server, *int) {
	t.Helper()
	getCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/vex-all.tar.xz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", lastModified.UTC().Format(http.TimeFormat))
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		getCalls++
		w.Header().Set("Content-Type", "application/x-xz")
		w.Write(payload)
	})
	return httptest.NewServer(mux), &getCalls
}

// minimal OpenVEX doc helper for fixture authoring.
func docOne(cve string, products []openvex.Component, status string, justification string, ts string) openvex.Document {
	return openvex.Document{
		Context:   openvex.Context,
		Author:    "Canonical Ltd.",
		Timestamp: ts,
		Version:   1,
		Statements: []openvex.Statement{
			{
				Vulnerability: openvex.Vulnerability{Name: cve},
				Products:      products,
				Status:        status,
				Justification: justification,
				Timestamp:     ts,
			},
		},
	}
}

func purl(id string) openvex.Component {
	return openvex.Component{ID: id}
}

func TestNew(t *testing.T) {
	t.Run("requires id", func(t *testing.T) {
		_, err := New(source.AdapterConfig{Type: Type, URL: "https://example/vex-all.tar.xz"})
		if err == nil {
			t.Fatal("expected error for empty id")
		}
	})
	t.Run("requires url", func(t *testing.T) {
		_, err := New(source.AdapterConfig{Type: Type, ID: "ubuntu-vex"})
		if err == nil {
			t.Fatal("expected error for empty url")
		}
	})
	t.Run("default name", func(t *testing.T) {
		a, err := New(source.AdapterConfig{Type: Type, ID: "ubuntu-vex", URL: "https://example/vex-all.tar.xz"})
		if err != nil {
			t.Fatal(err)
		}
		if a.Name() != "Ubuntu (OpenVEX)" {
			t.Errorf("default Name(): got %q, want %q", a.Name(), "Ubuntu (OpenVEX)")
		}
	})
	t.Run("config name override", func(t *testing.T) {
		a, _ := New(source.AdapterConfig{Type: Type, ID: "ubuntu-vex", Name: "Custom", URL: "https://example/vex-all.tar.xz"})
		if a.Name() != "Custom" {
			t.Errorf("Name() override: got %q, want Custom", a.Name())
		}
	})
}

func TestAdapter_Identity(t *testing.T) {
	a, err := New(source.AdapterConfig{Type: Type, ID: "ubuntu-vex", URL: "https://example/vex-all.tar.xz"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Vendor() != "ubuntu" {
		t.Errorf("Vendor: got %q, want ubuntu", a.Vendor())
	}
	if a.SourceFormat() != "openvex" {
		// Defensive guard: db.BulkInsert defaults empty SourceFormat to "csaf".
		// Forgetting this would silently misclassify rows. (pkg/db/db.go:142-144)
		t.Errorf("SourceFormat: got %q, want openvex", a.SourceFormat())
	}
	if Type != "ubuntu-vex" {
		t.Errorf("Type constant: got %q, want ubuntu-vex", Type)
	}
}

func TestAdapter_Lifecycle(t *testing.T) {
	lastModified := time.Date(2026, 4, 29, 18, 21, 49, 0, time.UTC)
	statementTS := "2026-04-23T00:00:00Z"

	entries := []fixtureEntry{
		{
			name: "vex/cve/2026/CVE-2026-31431.json",
			body: mustJSON(t, openvex.Document{
				Context:   openvex.Context,
				Author:    "Canonical Ltd.",
				Timestamp: statementTS,
				Version:   1,
				Statements: []openvex.Statement{
					{
						Vulnerability: openvex.Vulnerability{Name: "CVE-2026-31431"},
						Products: []openvex.Component{
							purl("pkg:deb/ubuntu/linux@4.15.0-1199.214~14.04.1?arch=source&distro=esm-infra-legacy/trusty"),
							purl("pkg:deb/ubuntu/linux@5.15.0-100?distro=ubuntu/jammy"),
						},
						Status:    "affected",
						Timestamp: statementTS,
					},
					{
						Vulnerability: openvex.Vulnerability{Name: "CVE-2026-31431"},
						Products: []openvex.Component{
							purl("pkg:deb/ubuntu/linux-aws?distro=ubuntu/noble"),
						},
						Status:        "not_affected",
						Justification: "vulnerable_code_not_present",
						Timestamp:     statementTS,
					},
				},
			}),
		},
	}

	server, _ := serveFixture(t, buildTarXZ(t, entries), lastModified)
	defer server.Close()

	a, err := New(source.AdapterConfig{Type: Type, ID: "ubuntu-vex", URL: server.URL + "/vex-all.tar.xz"})
	if err != nil {
		t.Fatal(err)
	}

	feed, err := a.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if feed.FeedURL == "" {
		t.Error("expected FeedURL set")
	}

	var stmts []source.Statement
	res, err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
		stmts = append(stmts, s)
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !res.Complete {
		t.Error("a clean full walk must report Complete")
	}

	if len(stmts) != 3 {
		t.Fatalf("expected 3 emitted statements, got %d: %+v", len(stmts), stmts)
	}

	// Every emitted PURL must carry the rewritten ubuntu-<v> form.
	for _, s := range stmts {
		if s.IDType != "purl" {
			t.Errorf("IDType: got %q, want purl for %q", s.IDType, s.ProductID)
		}
		if s.Updated.IsZero() {
			t.Errorf("Updated zero on %q", s.ProductID)
		}
		// Look for `distro=ubuntu-` regardless of whether it follows `?` or `&`
		// — it can be the first qualifier or come after `arch=` etc.
		if !contains(s.ProductID, "distro=ubuntu-") {
			t.Errorf("ProductID %q missing rewritten distro qualifier (distro=ubuntu-)", s.ProductID)
		}
		// The unrewritten ESM track values must not leak through.
		for _, esm := range []string{"esm-infra-legacy/", "esm-apps/", "esm-infra/", "ubuntu/trusty", "ubuntu/jammy", "ubuntu/noble"} {
			if contains(s.ProductID, esm) {
				t.Errorf("ProductID %q still carries pre-normalization qualifier %q", s.ProductID, esm)
			}
		}
	}

	// Confirm the not_affected row is present with its justification.
	var sawNotAffected bool
	for _, s := range stmts {
		if s.Status == "not_affected" {
			if s.Justification != "vulnerable_code_not_present" {
				t.Errorf("not_affected justification: got %q", s.Justification)
			}
			sawNotAffected = true
		}
	}
	if !sawNotAffected {
		t.Error("expected one not_affected row")
	}
}

func TestAdapter_HEADShortCircuit(t *testing.T) {
	lastModified := time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC)
	since := time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)

	server, getCalls := serveFixture(t, buildTarXZ(t, nil), lastModified)
	defer server.Close()

	a, _ := New(source.AdapterConfig{Type: Type, ID: "ubuntu-vex", URL: server.URL + "/vex-all.tar.xz"})
	var emitted int
	if _, err := a.Sync(context.Background(), since, func(s source.Statement) error {
		emitted++
		return nil
	}); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if emitted != 0 {
		t.Errorf("expected no emit on short-circuit, got %d", emitted)
	}
	if *getCalls != 0 {
		t.Errorf("expected no GET on short-circuit, got %d", *getCalls)
	}
}

func TestAdapter_FilterEntryTypes(t *testing.T) {
	// Only the CVE entry should produce statements. USN and (implicit) dir
	// entries must be silently skipped.
	cveDoc := docOne("CVE-2026-1",
		[]openvex.Component{purl("pkg:deb/ubuntu/curl?distro=ubuntu/jammy")},
		"fixed", "", "2026-04-01T00:00:00Z")
	usnDoc := docOne("USN-1234",
		[]openvex.Component{purl("pkg:deb/ubuntu/curl?distro=ubuntu/jammy")},
		"fixed", "", "2026-04-01T00:00:00Z")

	entries := []fixtureEntry{
		{name: "vex/cve/2026/CVE-2026-1.json", body: mustJSON(t, cveDoc)},
		{name: "vex/usn/USN-1234-1.json", body: mustJSON(t, usnDoc)},
	}
	server, _ := serveFixture(t, buildTarXZ(t, entries), time.Now().UTC())
	defer server.Close()

	a, _ := New(source.AdapterConfig{Type: Type, ID: "ubuntu-vex", URL: server.URL + "/vex-all.tar.xz"})
	var stmts []source.Statement
	if _, err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
		stmts = append(stmts, s)
		return nil
	}); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement (USN entry must be skipped), got %d", len(stmts))
	}
	if stmts[0].CVE != "CVE-2026-1" {
		t.Errorf("got CVE %q, want CVE-2026-1", stmts[0].CVE)
	}
}

func TestAdapter_SkipsMalformed(t *testing.T) {
	good := docOne("CVE-2026-1",
		[]openvex.Component{purl("pkg:deb/ubuntu/curl?distro=ubuntu/jammy")},
		"fixed", "", "2026-04-01T00:00:00Z")
	entries := []fixtureEntry{
		{name: "vex/cve/2026/CVE-2026-1.json", body: mustJSON(t, good)},
		{name: "vex/cve/2026/CVE-2026-2.json", body: []byte(`{not valid json`)},
	}
	server, _ := serveFixture(t, buildTarXZ(t, entries), time.Now().UTC())
	defer server.Close()

	a, _ := New(source.AdapterConfig{Type: Type, ID: "ubuntu-vex", URL: server.URL + "/vex-all.tar.xz"})
	var stmts []source.Statement
	res, err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
		stmts = append(stmts, s)
		return nil
	})
	if err != nil {
		t.Fatalf("Sync should not error on a malformed entry: %v", err)
	}
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement (good one survives), got %d", len(stmts))
	}
	// The malformed CVE's rows were not re-emitted, so the run must not claim
	// to hold the feed's whole set.
	if res.Complete {
		t.Error("a run that skipped a malformed entry must report Complete=false")
	}
}

func TestAdapter_DedupAcrossESMTracks(t *testing.T) {
	// Three distro tracks for the same Ubuntu release × the same package =>
	// one emitted row after Normalize + dedup.
	doc := openvex.Document{
		Context:   openvex.Context,
		Author:    "Canonical Ltd.",
		Timestamp: "2026-04-01T00:00:00Z",
		Version:   1,
		Statements: []openvex.Statement{
			{
				Vulnerability: openvex.Vulnerability{Name: "CVE-2026-1"},
				Products: []openvex.Component{
					purl("pkg:deb/ubuntu/openssl?distro=ubuntu/jammy"),
					purl("pkg:deb/ubuntu/openssl?distro=esm-apps/jammy"),
					purl("pkg:deb/ubuntu/openssl?distro=esm-infra/jammy"),
				},
				Status:    "fixed",
				Timestamp: "2026-04-01T00:00:00Z",
			},
		},
	}
	entries := []fixtureEntry{
		{name: "vex/cve/2026/CVE-2026-1.json", body: mustJSON(t, doc)},
	}
	server, _ := serveFixture(t, buildTarXZ(t, entries), time.Now().UTC())
	defer server.Close()

	a, _ := New(source.AdapterConfig{Type: Type, ID: "ubuntu-vex", URL: server.URL + "/vex-all.tar.xz"})
	var stmts []source.Statement
	if _, err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
		stmts = append(stmts, s)
		return nil
	}); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(stmts) != 1 {
		// Dedup failure would emit 3 rows.
		ids := make([]string, 0, len(stmts))
		for _, s := range stmts {
			ids = append(ids, s.ProductID)
		}
		sort.Strings(ids)
		t.Fatalf("expected 1 deduped row, got %d (%v)", len(stmts), ids)
	}
	if stmts[0].ProductID != "pkg:deb/ubuntu/openssl?distro=ubuntu-22.04" {
		t.Errorf("dedup target: got %q, want pkg:deb/ubuntu/openssl?distro=ubuntu-22.04", stmts[0].ProductID)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// canonicalStatements is the exact-list example for CVE-2024-1234 on Ubuntu
// 22.04 amd64, written the way Canonical does: one product per binary
// version, the same verdict repeated across versions, and an ESM track that
// folds onto the mainline release.
func canonicalStatements() []openvex.Statement {
	const ts = "2026-04-01T00:00:00Z"
	at := func(name, version string) openvex.Component {
		return purl("pkg:deb/ubuntu/" + name + "@" + version + "?arch=amd64&distro=jammy")
	}
	return []openvex.Statement{
		{Vulnerability: openvex.Vulnerability{Name: "CVE-2024-1234"}, Status: "fixed", Timestamp: ts,
			Products: []openvex.Component{at("openssl", "1.10"), at("openssl", "1.11"), at("glibc", "2.35-2"),
				purl("pkg:deb/ubuntu/openssl@1.11?arch=amd64&distro=esm-infra/jammy")}},
		{Vulnerability: openvex.Vulnerability{Name: "CVE-2024-1234"}, Status: "not_affected",
			Justification: "vulnerable_code_not_present", Timestamp: ts,
			Products: []openvex.Component{at("zlib", "1.2"), at("zlib", "1.3")}},
		{Vulnerability: openvex.Vulnerability{Name: "CVE-2024-1234"}, Status: "affected", Timestamp: "2026-04-02T00:00:00Z",
			Products: []openvex.Component{at("curl", "7.81"), at("glibc", "2.35-1")}},
	}
}

// TestEmitDoc_OneRowPerVerdict: rows group by (CVE, product without its
// version, status, justification), each carrying the versions stated for that
// verdict, in the same order whatever order the document lists them in.
func TestEmitDoc_OneRowPerVerdict(t *testing.T) {
	want := []string{
		"CVE-2024-1234 pkg:deb/ubuntu/curl?arch=amd64&distro=ubuntu-22.04 affected/ [7.81]",
		"CVE-2024-1234 pkg:deb/ubuntu/glibc?arch=amd64&distro=ubuntu-22.04 affected/ [2.35-1]",
		"CVE-2024-1234 pkg:deb/ubuntu/glibc?arch=amd64&distro=ubuntu-22.04 fixed/ [2.35-2]",
		"CVE-2024-1234 pkg:deb/ubuntu/openssl?arch=amd64&distro=ubuntu-22.04 fixed/ [1.10 1.11]",
		"CVE-2024-1234 pkg:deb/ubuntu/zlib?arch=amd64&distro=ubuntu-22.04 not_affected/vulnerable_code_not_present [1.2 1.3]",
	}
	render := func(stmts []openvex.Statement) []string {
		var got []string
		_, err := emitDoc(openvex.Document{Statements: stmts}, time.Now(), func(s source.Statement) error {
			if s.VersionKind != "exact" || s.Version != "" {
				t.Errorf("want an exact-list row with no single Version: %+v", s)
			}
			if s.BaseID != "pkg:deb/ubuntu/"+s.ProductID[len("pkg:deb/ubuntu/"):strings.IndexByte(s.ProductID, '?')]+"?distro=ubuntu-22.04" {
				t.Errorf("BaseID %q is not SplitPURL of %q", s.BaseID, s.ProductID)
			}
			got = append(got, fmt.Sprintf("%s %s %s/%s %v", s.CVE, s.ProductID, s.Status, s.Justification, s.Versions))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	got := render(canonicalStatements())
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// Reversed statements and products: the same rows, in the same order.
	rev := canonicalStatements()
	slices.Reverse(rev)
	for i := range rev {
		slices.Reverse(rev[i].Products)
	}
	if again := render(rev); strings.Join(again, "\n") != strings.Join(want, "\n") {
		t.Errorf("order-dependent output:\n%s", strings.Join(again, "\n"))
	}
}

// TestEmitDoc_GroupDetails: a group's timestamp is its latest; a product with
// no @version gives an empty list; an arch is part of the product, so amd64
// and arm64 are separate rows; a not_affected under two justifications is two
// rows.
func TestEmitDoc_GroupDetails(t *testing.T) {
	stmts := []openvex.Statement{
		{Vulnerability: openvex.Vulnerability{Name: "CVE-1"}, Status: "fixed", Timestamp: "2026-01-01T00:00:00Z",
			Products: []openvex.Component{purl("pkg:deb/ubuntu/a@1?arch=amd64&distro=jammy")}},
		{Vulnerability: openvex.Vulnerability{Name: "CVE-1"}, Status: "fixed", Timestamp: "2026-03-01T00:00:00Z",
			Products: []openvex.Component{purl("pkg:deb/ubuntu/a@2?arch=amd64&distro=jammy"), purl("pkg:deb/ubuntu/a@2?arch=arm64&distro=jammy")}},
		{Vulnerability: openvex.Vulnerability{Name: "CVE-1"}, Status: "not_affected", Justification: "component_not_present",
			Timestamp: "2026-01-01T00:00:00Z", Products: []openvex.Component{purl("pkg:deb/ubuntu/b?distro=noble")}},
		{Vulnerability: openvex.Vulnerability{Name: "CVE-1"}, Status: "not_affected", Justification: "vulnerable_code_not_present",
			Timestamp: "2026-01-01T00:00:00Z", Products: []openvex.Component{purl("pkg:deb/ubuntu/b?distro=noble")}},
	}
	var got []source.Statement
	if _, err := emitDoc(openvex.Document{Statements: stmts}, time.Now(), func(s source.Statement) error {
		got = append(got, s)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("want 4 rows (a amd64, a arm64, b twice), got %d: %+v", len(got), got)
	}
	a := got[0]
	if a.ProductID != "pkg:deb/ubuntu/a?arch=amd64&distro=ubuntu-22.04" || strings.Join(a.Versions, ",") != "1,2" ||
		!a.Updated.Equal(time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("amd64 row: %+v", a)
	}
	if got[1].ProductID != "pkg:deb/ubuntu/a?arch=arm64&distro=ubuntu-22.04" || strings.Join(got[1].Versions, ",") != "2" {
		t.Errorf("arm64 row: %+v", got[1])
	}
	for _, b := range got[2:] {
		if b.ProductID != "pkg:deb/ubuntu/b?distro=ubuntu-24.04" || len(b.Versions) != 0 {
			t.Errorf("versionless row: %+v", b)
		}
	}
	if got[2].Justification == got[3].Justification {
		t.Errorf("two justifications should be two rows: %+v", got[2:])
	}
}

// TestEmitDoc_FoldedTracksKeepEachVerdict: two ESM tracks of one release
// fold onto one identifier; when Canonical gives them different verdicts at
// different builds, each verdict is its own row with its own version, rather
// than one key the last statement wins.
func TestEmitDoc_FoldedTracksKeepEachVerdict(t *testing.T) {
	stmts := []openvex.Statement{
		{Vulnerability: openvex.Vulnerability{Name: "CVE-1"}, Status: "affected", Timestamp: "2026-01-01T00:00:00Z",
			Products: []openvex.Component{purl("pkg:deb/ubuntu/a@1.0?arch=amd64&distro=xenial")}},
		{Vulnerability: openvex.Vulnerability{Name: "CVE-1"}, Status: "fixed", Timestamp: "2026-01-01T00:00:00Z",
			Products: []openvex.Component{purl("pkg:deb/ubuntu/a@1.0+esm1?arch=amd64&distro=esm-infra/xenial")}},
	}
	var got []string
	if _, err := emitDoc(openvex.Document{Statements: stmts}, time.Now(), func(s source.Statement) error {
		got = append(got, fmt.Sprintf("%s %s %v", s.ProductID, s.Status, s.Versions))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"pkg:deb/ubuntu/a?arch=amd64&distro=ubuntu-16.04 affected [1.0]",
		"pkg:deb/ubuntu/a?arch=amd64&distro=ubuntu-16.04 fixed [1.0+esm1]",
	}
	if !slices.Equal(got, want) {
		t.Errorf("rows %v, want %v", got, want)
	}
}
