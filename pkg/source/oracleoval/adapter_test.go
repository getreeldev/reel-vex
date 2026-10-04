package oracleoval

import (
	"compress/bzip2"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getreeldev/oval-to-vex/translator"
	"github.com/getreeldev/reel-vex/pkg/db"
	"github.com/getreeldev/reel-vex/pkg/source"
)

func fixturePath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "testdata", name)
}

// serveFixture serves the committed bz2 OVAL fixture for HEAD and GET with a
// stable Last-Modified.
func serveFixture(t *testing.T, lastModified time.Time) *httptest.Server {
	t.Helper()
	raw, err := os.ReadFile(fixturePath(t, "oracle-oval-ol9-sample.oval.xml.bz2"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/com.oracle.elsa-ol9.xml.bz2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", lastModified.UTC().Format(http.TimeFormat))
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/x-bzip2")
		w.Write(raw)
	})
	return httptest.NewServer(mux)
}

func TestNew(t *testing.T) {
	t.Run("requires id", func(t *testing.T) {
		if _, err := New(source.AdapterConfig{Type: Type, URL: "https://x/com.oracle.elsa-ol9.xml.bz2"}); err == nil {
			t.Fatal("expected error for empty id")
		}
	})
	t.Run("requires url", func(t *testing.T) {
		if _, err := New(source.AdapterConfig{Type: Type, ID: "oracle"}); err == nil {
			t.Fatal("expected error for empty url")
		}
	})
	t.Run("requires a release in the file name", func(t *testing.T) {
		for _, u := range []string{
			"https://x/com.oracle.elsa-all.xml.bz2",
			"https://x/com.oracle.elsa-ol.xml.bz2",
			"https://x/oval.xml.bz2",
		} {
			if _, err := New(source.AdapterConfig{Type: Type, ID: "oracle", URL: u}); err == nil {
				t.Errorf("%s: expected error, release cannot be derived", u)
			}
		}
	})
	t.Run("defaults name", func(t *testing.T) {
		a, err := New(source.AdapterConfig{Type: Type, ID: "oracle", URL: "https://x/com.oracle.elsa-ol9.xml.bz2"})
		if err != nil {
			t.Fatal(err)
		}
		if a.Name() != "Oracle Linux" {
			t.Errorf("Name: got %q, want Oracle Linux", a.Name())
		}
	})
}

func TestAdapter_Lifecycle(t *testing.T) {
	lastModified := time.Date(2026, 6, 8, 16, 56, 9, 0, time.UTC)
	server := serveFixture(t, lastModified)
	defer server.Close()

	a, err := New(source.AdapterConfig{Type: Type, ID: "oracle-oval-ol9", URL: server.URL + "/com.oracle.elsa-ol9.xml.bz2"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Vendor() != "oracle" {
		t.Errorf("Vendor: got %q, want oracle", a.Vendor())
	}
	if a.SourceFormat() != "oval" {
		t.Errorf("SourceFormat: got %q, want oval", a.SourceFormat())
	}
	if _, err := a.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	var stmts []source.Statement
	if _, err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
		stmts = append(stmts, s)
		return nil
	}); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(stmts) == 0 {
		t.Fatal("expected at least one statement from the fixture")
	}

	// The adapter is a thin wrapper over translator.FromOracleOVAL (which the
	// oval-to-vex repo unit-tests for exact tuples); here we assert the wiring:
	// shape, the UTC Last-Modified stamp, and the oracle distro identity.
	var sawOracle9 bool
	for _, s := range stmts {
		if s.IDType != "purl" {
			t.Errorf("%s: IDType got %q, want purl", s.CVE, s.IDType)
		}
		if s.Status != "fixed" {
			t.Errorf("%s: Status got %q, want fixed", s.CVE, s.Status)
		}
		if s.Version == "" || s.VersionKind != db.VersionKindBoundary {
			t.Errorf("%s: fixed-in version %q of kind %q, want a version of kind boundary", s.CVE, s.Version, s.VersionKind)
		}
		if !s.Updated.Equal(lastModified) {
			t.Errorf("%s: Updated got %v, want %v", s.CVE, s.Updated, lastModified)
		}
		if q := strings.IndexByte(s.ProductID, '?'); q >= 0 && strings.Contains(s.ProductID[q:], "@") {
			t.Errorf("%s: ProductID %q puts the version after the qualifiers", s.CVE, s.ProductID)
		}
		if !strings.HasPrefix(s.BaseID, "pkg:rpm/oracle/") {
			t.Errorf("%s: BaseID %q is not pkg:rpm/oracle/*", s.CVE, s.BaseID)
		}
		if !strings.Contains(s.BaseID, "?distro=oracle-") {
			t.Errorf("%s: BaseID %q missing ?distro=oracle-", s.CVE, s.BaseID)
		}
		if strings.Contains(s.BaseID, "?distro=oracle-9") {
			sawOracle9 = true
		}
		if strings.Contains(s.Version, "ksplice") {
			t.Errorf("%s: ksplice variant should be skipped, got version %q", s.CVE, s.Version)
		}
	}
	if !sawOracle9 {
		t.Error("expected at least one ?distro=oracle-9 statement from the ol9 fixture")
	}
}

func TestAdapter_HEADShortCircuit(t *testing.T) {
	lastModified := time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC)
	since := time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)

	var getCalls int
	mux := http.NewServeMux()
	mux.HandleFunc("/com.oracle.elsa-ol9.xml.bz2", func(w http.ResponseWriter, r *http.Request) {
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

	a, _ := New(source.AdapterConfig{Type: Type, ID: "oracle", URL: server.URL + "/com.oracle.elsa-ol9.xml.bz2"})
	var emitCount int
	if _, err := a.Sync(context.Background(), since, func(s source.Statement) error { emitCount++; return nil }); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if emitCount != 0 {
		t.Errorf("expected no emit on short-circuit, got %d", emitCount)
	}
	if getCalls != 0 {
		t.Errorf("expected no GET on short-circuit, got %d", getCalls)
	}
}

// TestAdapter_OwnReleaseOnly: an ELSA in the ol9 file that also covers OL8
// yields distro=oracle-8 rows from the translator, which the ol8 adapter
// writes too; the ol9 adapter keeps only oracle-9 rows.
func TestAdapter_OwnReleaseOnly(t *testing.T) {
	raw, err := os.Open(fixturePath(t, "oracle-oval-ol9-sample.oval.xml.bz2"))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	all, err := translator.FromOracleOVAL(bzip2.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var own, other int
	for _, s := range all {
		if strings.HasSuffix(s.BaseID, "?distro=oracle-9") {
			own++
		} else {
			other++
		}
	}
	if own == 0 || other == 0 {
		t.Fatalf("fixture must yield rows of release 9 and of another release; got %d and %d", own, other)
	}

	server := serveFixture(t, time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC))
	defer server.Close()
	a, err := New(source.AdapterConfig{Type: Type, ID: "oracle-oval-ol9", URL: server.URL + "/com.oracle.elsa-ol9.xml.bz2"})
	if err != nil {
		t.Fatal(err)
	}
	var emitted int
	if _, err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
		emitted++
		if !strings.HasSuffix(s.BaseID, "?distro=oracle-9") {
			t.Errorf("%s: ol9 adapter emitted %q", s.CVE, s.BaseID)
		}
		return nil
	}); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if emitted != own {
		t.Errorf("emitted %d statements, want the %d of release 9", emitted, own)
	}
}
