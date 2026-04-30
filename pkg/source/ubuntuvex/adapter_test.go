package ubuntuvex

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
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
	if err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
		stmts = append(stmts, s)
		return nil
	}); err != nil {
		t.Fatalf("Sync: %v", err)
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
	if err := a.Sync(context.Background(), since, func(s source.Statement) error {
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
	if err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
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
	if err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
		stmts = append(stmts, s)
		return nil
	}); err != nil {
		t.Fatalf("Sync should not error on a malformed entry: %v", err)
	}
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement (good one survives), got %d", len(stmts))
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
	if err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
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
