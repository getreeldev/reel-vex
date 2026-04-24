package debianoval

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/getreeldev/reel-vex/pkg/source"
)

// fixturePath resolves the repo-root testdata/ path from this package's test dir.
func fixturePath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "testdata", name)
}

// serveFixture boots an httptest.Server that serves the committed bz2
// fixture for both HEAD and GET, with a stable Last-Modified header.
func serveFixture(t *testing.T, lastModified time.Time) *httptest.Server {
	t.Helper()
	raw, err := os.ReadFile(fixturePath(t, "debian-oval-bookworm-sample.oval.xml.bz2"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/oval-definitions-bookworm.xml.bz2", func(w http.ResponseWriter, r *http.Request) {
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
		_, err := New(source.AdapterConfig{Type: Type, URL: "https://example/oval-definitions-bookworm.xml.bz2"})
		if err == nil {
			t.Fatal("expected error for empty id")
		}
	})
	t.Run("requires url", func(t *testing.T) {
		_, err := New(source.AdapterConfig{Type: Type, ID: "deb"})
		if err == nil {
			t.Fatal("expected error for empty url")
		}
	})
}

func TestAdapter_Lifecycle(t *testing.T) {
	lastModified := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	server := serveFixture(t, lastModified)
	defer server.Close()

	a, err := New(source.AdapterConfig{
		Type: Type,
		ID:   "debian-oval-bookworm",
		URL:  server.URL + "/oval-definitions-bookworm.xml.bz2",
	})
	if err != nil {
		t.Fatal(err)
	}

	if a.Vendor() != "debian" {
		t.Errorf("Vendor: got %q, want debian", a.Vendor())
	}
	if a.SourceFormat() != "oval" {
		t.Errorf("SourceFormat: got %q, want oval", a.SourceFormat())
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

	// Fixture: 4 defs → 2 fixed statements (CVE-2021-44228, CVE-2022-0778)
	// + 1 affected statement (CVE-2026-0001, unpatched).
	if len(stmts) != 3 {
		t.Fatalf("expected 3 statements, got %d", len(stmts))
	}

	wantFixed := map[string]string{
		"pkg:deb/debian/apache-log4j2?distro=debian-12": "0:2.15.0-1",
		"pkg:deb/debian/openssl?distro=debian-12":       "0:3.0.2-2",
	}
	var sawAffected bool
	for _, s := range stmts {
		if s.IDType != "purl" {
			t.Errorf("IDType: got %q, want purl", s.IDType)
		}
		if !s.Updated.Equal(lastModified) {
			t.Errorf("Updated: got %v, want %v", s.Updated, lastModified)
		}
		switch s.Status {
		case "fixed":
			want, ok := wantFixed[s.ProductID]
			if !ok {
				t.Errorf("unexpected fixed statement for %q", s.ProductID)
				continue
			}
			if s.Version != want {
				t.Errorf("%q: got version %q, want %q", s.ProductID, s.Version, want)
			}
			delete(wantFixed, s.ProductID)
		case "affected":
			if s.ProductID != "pkg:deb/debian/curl?distro=debian-12" {
				t.Errorf("affected: got %q", s.ProductID)
			}
			if s.Version != "" {
				t.Errorf("affected statement must have empty version, got %q", s.Version)
			}
			sawAffected = true
		default:
			t.Errorf("unexpected status %q", s.Status)
		}
	}
	for missing := range wantFixed {
		t.Errorf("missing fixed statement for %q", missing)
	}
	if !sawAffected {
		t.Errorf("missing affected statement for unpatched-CVE fixture def")
	}
}

func TestAdapter_HEADShortCircuit(t *testing.T) {
	lastModified := time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC)
	since := time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)

	var getCalls int
	mux := http.NewServeMux()
	mux.HandleFunc("/oval-definitions-bookworm.xml.bz2", func(w http.ResponseWriter, r *http.Request) {
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

	a, _ := New(source.AdapterConfig{Type: Type, ID: "deb", URL: server.URL + "/oval-definitions-bookworm.xml.bz2"})
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
