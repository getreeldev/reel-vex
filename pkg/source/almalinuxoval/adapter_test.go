package almalinuxoval

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

func fixturePath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "testdata", name)
}

func serveFixture(t *testing.T, lastModified time.Time) *httptest.Server {
	t.Helper()
	raw, err := os.ReadFile(fixturePath(t, "almalinux-oval-9-sample.oval.xml.bz2"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/org.almalinux.alsa-9.xml.bz2", func(w http.ResponseWriter, r *http.Request) {
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
		if _, err := New(source.AdapterConfig{Type: Type, URL: "https://x/org.almalinux.alsa-9.xml.bz2"}); err == nil {
			t.Fatal("expected error for empty id")
		}
	})
	t.Run("requires url", func(t *testing.T) {
		if _, err := New(source.AdapterConfig{Type: Type, ID: "alma"}); err == nil {
			t.Fatal("expected error for empty url")
		}
	})
	t.Run("derives release from url + defaults name", func(t *testing.T) {
		a, err := New(source.AdapterConfig{Type: Type, ID: "alma", URL: "https://security.almalinux.org/oval/org.almalinux.alsa-9.xml.bz2"})
		if err != nil {
			t.Fatal(err)
		}
		if a.Name() != "AlmaLinux 9" {
			t.Errorf("Name: got %q, want AlmaLinux 9 (release parsed from url)", a.Name())
		}
	})
	t.Run("rejects url with no derivable release", func(t *testing.T) {
		if _, err := New(source.AdapterConfig{Type: Type, ID: "alma", URL: "https://x/no-release-here.xml.bz2"}); err == nil {
			t.Fatal("expected error when release major can't be derived from url")
		}
	})
}

func TestAdapter_Lifecycle(t *testing.T) {
	lastModified := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	server := serveFixture(t, lastModified)
	defer server.Close()

	a, err := New(source.AdapterConfig{Type: Type, ID: "almalinux-oval-9", URL: server.URL + "/org.almalinux.alsa-9.xml.bz2"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Vendor() != "almalinux" {
		t.Errorf("Vendor: got %q, want almalinux", a.Vendor())
	}
	if a.SourceFormat() != "oval" {
		t.Errorf("SourceFormat: got %q, want oval", a.SourceFormat())
	}
	if _, err := a.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	var stmts []source.Statement
	if err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
		stmts = append(stmts, s)
		return nil
	}); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(stmts) == 0 {
		t.Fatal("expected at least one statement from the fixture")
	}

	// Thin wrapper over translator.FromAlmaLinuxOVAL (exact tuples are tested in
	// oval-to-vex). Assert the wiring: shape, UTC stamp, the major-scoped distro
	// (release parsed from the alsa-9 URL), and the dual-namespace emission.
	var sawAlmalinuxNS, sawAlmaNS bool
	for _, s := range stmts {
		if s.IDType != "purl" {
			t.Errorf("%s: IDType got %q, want purl", s.CVE, s.IDType)
		}
		if s.Status != "fixed" {
			t.Errorf("%s: Status got %q, want fixed", s.CVE, s.Status)
		}
		if !s.Updated.Equal(lastModified) {
			t.Errorf("%s: Updated got %v, want %v", s.CVE, s.Updated, lastModified)
		}
		if !strings.Contains(s.BaseID, "?distro=almalinux-9") {
			t.Errorf("%s: BaseID %q missing ?distro=almalinux-9", s.CVE, s.BaseID)
		}
		switch {
		case strings.HasPrefix(s.BaseID, "pkg:rpm/almalinux/"):
			sawAlmalinuxNS = true
		case strings.HasPrefix(s.BaseID, "pkg:rpm/alma/"):
			sawAlmaNS = true
		default:
			t.Errorf("%s: unexpected BaseID namespace %q", s.CVE, s.BaseID)
		}
	}
	if !sawAlmalinuxNS {
		t.Error("expected statements under pkg:rpm/almalinux/")
	}
	if !sawAlmaNS {
		t.Error("expected statements under pkg:rpm/alma/ (namespace-drift insurance)")
	}
}

func TestAdapter_HEADShortCircuit(t *testing.T) {
	lastModified := time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC)
	since := time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)

	var getCalls int
	mux := http.NewServeMux()
	mux.HandleFunc("/org.almalinux.alsa-9.xml.bz2", func(w http.ResponseWriter, r *http.Request) {
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

	a, _ := New(source.AdapterConfig{Type: Type, ID: "alma", URL: server.URL + "/org.almalinux.alsa-9.xml.bz2"})
	var emitCount int
	if err := a.Sync(context.Background(), since, func(s source.Statement) error { emitCount++; return nil }); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if emitCount != 0 {
		t.Errorf("expected no emit on short-circuit, got %d", emitCount)
	}
	if getCalls != 0 {
		t.Errorf("expected no GET on short-circuit, got %d", getCalls)
	}
}
