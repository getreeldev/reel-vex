package alpinesecdb

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getreeldev/reel-vex/pkg/source"
)

// fixturePath resolves the repo-root testdata/ path from this package's test dir.
func fixturePath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "testdata", name)
}

// serveFixture boots an httptest.Server that serves the committed JSON fixture
// for both HEAD and GET, with a stable Last-Modified header.
func serveFixture(t *testing.T, lastModified time.Time) *httptest.Server {
	t.Helper()
	raw, err := os.ReadFile(fixturePath(t, "alpine-secdb-v3.21-main-sample.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v3.21/main.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", lastModified.UTC().Format(http.TimeFormat))
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw)
	})
	return httptest.NewServer(mux)
}

func TestNew(t *testing.T) {
	t.Run("requires id", func(t *testing.T) {
		_, err := New(source.AdapterConfig{Type: Type, URL: "https://secdb.alpinelinux.org/v3.21/main.json"})
		if err == nil {
			t.Fatal("expected error for empty id")
		}
	})
	t.Run("requires url", func(t *testing.T) {
		_, err := New(source.AdapterConfig{Type: Type, ID: "alpine"})
		if err == nil {
			t.Fatal("expected error for empty url")
		}
	})
	t.Run("defaults name", func(t *testing.T) {
		a, err := New(source.AdapterConfig{Type: Type, ID: "alpine", URL: "https://x/main.json"})
		if err != nil {
			t.Fatal(err)
		}
		if a.Name() != "Alpine Linux" {
			t.Errorf("Name: got %q, want Alpine Linux", a.Name())
		}
	})
}

func TestAdapter_Lifecycle(t *testing.T) {
	lastModified := time.Date(2026, 6, 6, 20, 2, 35, 0, time.UTC)
	server := serveFixture(t, lastModified)
	defer server.Close()

	a, err := New(source.AdapterConfig{
		Type: Type,
		ID:   "alpine-secdb-v3.21-main",
		URL:  server.URL + "/v3.21/main.json",
	})
	if err != nil {
		t.Fatal(err)
	}

	if a.Vendor() != "alpine" {
		t.Errorf("Vendor: got %q, want alpine", a.Vendor())
	}
	if a.SourceFormat() != "secdb" {
		t.Errorf("SourceFormat: got %q, want secdb", a.SourceFormat())
	}

	feed, err := a.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if feed.FeedURL == "" {
		t.Error("expected FeedURL set")
	}

	var stmts []source.Statement
	err = a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
		stmts = append(stmts, s)
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// Fixture (aom + busybox + glib):
	//   aom 3.1.1-r0 → 3 CVE (fixed), 3.9.1-r0 → 1 CVE (fixed)        = 4 fixed
	//   busybox "0"  → 3 CVE (not_affected, empty version)            = 3 not_affected
	//   busybox 1.34.0-r0 → 11 CVE (fixed)                            = 11 fixed
	//   busybox 1.35.0-r7 → [ALPINE-13661 skipped, CVE-2022-28391]    = 1 fixed
	//   glib 2.66.8-r0 → ["CVE-2021-27219 GHSL-2021-045"] (glued)     = 1 fixed
	// Totals: 20 emitted, 17 fixed, 3 not_affected, 1 non-CVE skipped.
	if len(stmts) != 20 {
		t.Fatalf("expected 20 statements, got %d", len(stmts))
	}

	var fixed, notAffected int
	var sawAomFix, sawBusyboxFix, sawBusyboxNotAffected, sawMixedArrayCVE, sawGluedCVE bool
	for _, s := range stmts {
		if s.IDType != "purl" {
			t.Errorf("%s: IDType got %q, want purl", s.CVE, s.IDType)
		}
		if s.Scope != "" {
			t.Errorf("%s: Scope got %q, want empty", s.CVE, s.Scope)
		}
		// BARE PURL: ProductID == BaseID, no version embedded, no ?distro=.
		if s.ProductID != s.BaseID {
			t.Errorf("%s: ProductID %q != BaseID %q", s.CVE, s.ProductID, s.BaseID)
		}
		// Branch-scoped: the fixture is v3.21, so every BaseID carries ?distro=alpine-3.21.
		if s.BaseID != "pkg:apk/alpine/aom?distro=alpine-3.21" &&
			s.BaseID != "pkg:apk/alpine/busybox?distro=alpine-3.21" &&
			s.BaseID != "pkg:apk/alpine/glib?distro=alpine-3.21" {
			t.Errorf("%s: unexpected BaseID %q", s.CVE, s.BaseID)
		}
		// No emitted CVE may carry whitespace — guards the glued-id split.
		if strings.ContainsAny(s.CVE, " \t") {
			t.Errorf("emitted CVE %q contains whitespace (glued secfixes id not split)", s.CVE)
		}
		if !s.Updated.Equal(lastModified) {
			t.Errorf("%s: Updated got %v, want %v", s.CVE, s.Updated, lastModified)
		}

		switch s.Status {
		case "fixed":
			fixed++
			if s.Justification != "" {
				t.Errorf("%s: Justification got %q, want empty", s.CVE, s.Justification)
			}
			if s.Version == "" {
				t.Errorf("%s: fixed statement has empty version", s.CVE)
			}
			if s.CVE == "CVE-2024-5171" {
				sawAomFix = true
				if s.Version != "3.9.1-r0" {
					t.Errorf("CVE-2024-5171: got version %q, want 3.9.1-r0", s.Version)
				}
			}
			if s.CVE == "CVE-2021-42386" {
				sawBusyboxFix = true
				if s.Version != "1.34.0-r0" {
					t.Errorf("CVE-2021-42386: got version %q, want 1.34.0-r0", s.Version)
				}
			}
			// The CVE in the mixed [ALPINE-13661, CVE-2022-28391] array.
			if s.CVE == "CVE-2022-28391" {
				sawMixedArrayCVE = true
				if s.Version != "1.35.0-r7" {
					t.Errorf("CVE-2022-28391: got version %q, want 1.35.0-r7", s.Version)
				}
			}
			// The glued "CVE-2021-27219 GHSL-2021-045" id must yield the bare CVE.
			if s.CVE == "CVE-2021-27219" {
				sawGluedCVE = true
				if s.Version != "2.66.8-r0" {
					t.Errorf("CVE-2021-27219: got version %q, want 2.66.8-r0", s.Version)
				}
			}
		case "not_affected":
			notAffected++
			if s.Version != "" {
				t.Errorf("%s: not_affected statement must have empty version, got %q", s.CVE, s.Version)
			}
			if s.Justification != "vulnerable_code_not_present" {
				t.Errorf("%s: Justification got %q, want vulnerable_code_not_present", s.CVE, s.Justification)
			}
			if s.BaseID != "pkg:apk/alpine/busybox?distro=alpine-3.21" {
				t.Errorf("not_affected: got BaseID %q, want busybox?distro=alpine-3.21", s.BaseID)
			}
			if s.CVE == "CVE-2021-42373" {
				sawBusyboxNotAffected = true
			}
		default:
			t.Errorf("%s: unexpected status %q", s.CVE, s.Status)
		}

		// Non-CVE ids must never be emitted.
		if s.CVE == "ALPINE-13661" {
			t.Errorf("non-CVE id ALPINE-13661 was emitted")
		}
	}

	if fixed != 17 {
		t.Errorf("fixed count: got %d, want 17", fixed)
	}
	if notAffected != 3 {
		t.Errorf("not_affected count: got %d, want 3", notAffected)
	}
	if !sawAomFix {
		t.Error("missing aom fix CVE-2024-5171")
	}
	if !sawBusyboxFix {
		t.Error("missing busybox fix CVE-2021-42386")
	}
	if !sawBusyboxNotAffected {
		t.Error("missing busybox not_affected CVE-2021-42373 (the \"0\" key)")
	}
	if !sawMixedArrayCVE {
		t.Error("missing CVE-2022-28391 from the mixed CVE/ALPINE array")
	}
	if !sawGluedCVE {
		t.Error("missing CVE-2021-27219 split from the glued \"CVE-... GHSL-...\" id")
	}
}

func TestAdapter_HEADShortCircuit(t *testing.T) {
	lastModified := time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC)
	since := time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)

	var getCalls int
	mux := http.NewServeMux()
	mux.HandleFunc("/v3.21/main.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", lastModified.UTC().Format(http.TimeFormat))
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		getCalls++
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	a, _ := New(source.AdapterConfig{Type: Type, ID: "alpine", URL: server.URL + "/v3.21/main.json"})
	var emitCount int
	err := a.Sync(context.Background(), since, func(s source.Statement) error {
		emitCount++
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if emitCount != 0 {
		t.Errorf("expected no emit on short-circuit, got %d", emitCount)
	}
	if getCalls != 0 {
		t.Errorf("expected no GET on short-circuit, got %d", getCalls)
	}
}

// syncBody runs one Sync over an in-memory secdb body.
func syncBody(t *testing.T, body string) []source.Statement {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v3.24/main.json", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Write([]byte(body))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	a, err := New(source.AdapterConfig{Type: Type, ID: "alpine", URL: server.URL + "/v3.24/main.json"})
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
	return stmts
}

// TestAdapter_SeveralKeysOneRow: a (package, CVE) listed under several secfixes
// keys is one row, chosen the same way every time: the highest fixed version by
// apk ordering (an unparseable key loses to any valid one), and "0" only when
// no fixed version lists it. Shapes from the live v3.24 feeds: zlib lists
// CVE-2026-22184 under "0" and 1.3.2-r0; cacti lists CVE-2024-43362 under
// 1.2.28-r0 and 1.2.29-r0. secfixes is a Go map, so this runs repeatedly.
func TestAdapter_SeveralKeysOneRow(t *testing.T) {
	const body = `{"distroversion": "v3.24", "packages": [
		{"pkg": {"name": "zlib", "secfixes": {
			"0": ["CVE-2026-22184", "CVE-2026-0001"],
			"1.3.2-r0": ["CVE-2026-22184"]}}},
		{"pkg": {"name": "cacti", "secfixes": {
			"1.2.29-r0": ["CVE-2024-43362"],
			"1.2.28-r0": ["CVE-2024-43362"],
			"1.2.9-r0": ["CVE-2024-43362"],
			"not-a-version": ["CVE-2024-43362", "CVE-2024-0002"],
			"also-not-one": ["CVE-2024-0002"]}}}]}`
	want := []string{
		"zlib CVE-2026-0001 not_affected ",
		"zlib CVE-2026-22184 fixed 1.3.2-r0",
		"cacti CVE-2024-0002 fixed not-a-version",
		"cacti CVE-2024-43362 fixed 1.2.29-r0",
	}
	for i := 0; i < 50; i++ {
		stmts := syncBody(t, body)
		var got []string
		for _, s := range stmts {
			name := strings.TrimSuffix(strings.TrimPrefix(s.BaseID, "pkg:apk/alpine/"), "?distro=alpine-3.24")
			got = append(got, name+" "+s.CVE+" "+s.Status+" "+s.Version)
		}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("run %d:\n got  %q\n want %q", i, got, want)
		}
	}
}
