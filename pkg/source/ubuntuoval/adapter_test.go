package ubuntuoval

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
	raw, err := os.ReadFile(fixturePath(t, "ubuntu-oval-noble-sample.oval.xml.bz2"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/oci.com.ubuntu.noble.usn.oval.xml.bz2", func(w http.ResponseWriter, r *http.Request) {
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
		_, err := New(source.AdapterConfig{Type: Type, URL: "https://example/ubuntu.oval.xml.bz2"})
		if err == nil {
			t.Fatal("expected error for empty id")
		}
	})
	t.Run("requires url", func(t *testing.T) {
		_, err := New(source.AdapterConfig{Type: Type, ID: "ub"})
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
		ID:   "ubuntu-oval-noble-oci",
		URL:  server.URL + "/oci.com.ubuntu.noble.usn.oval.xml.bz2",
	})
	if err != nil {
		t.Fatal(err)
	}

	if a.Vendor() != "ubuntu" {
		t.Errorf("Vendor: got %q, want ubuntu", a.Vendor())
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

	// Fixture emits exactly 2 statements (USN-6673-3: 1 CVE × 2 packages).
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements from fixture, got %d", len(stmts))
	}

	wantPkgs := map[string]bool{
		"pkg:deb/ubuntu/python3-cryptography?distro=ubuntu-24.04":    false,
		"pkg:deb/ubuntu/python-cryptography-doc?distro=ubuntu-24.04": false,
	}
	for _, s := range stmts {
		if s.CVE != "CVE-2024-26130" {
			t.Errorf("CVE: got %q, want CVE-2024-26130", s.CVE)
		}
		if s.IDType != "purl" {
			t.Errorf("IDType: got %q, want purl", s.IDType)
		}
		if s.Status != "fixed" {
			t.Errorf("Status: got %q, want fixed", s.Status)
		}
		if s.Version != "0:41.0.7-4ubuntu0.1" {
			t.Errorf("Version: got %q, want 0:41.0.7-4ubuntu0.1", s.Version)
		}
		if !s.Updated.Equal(lastModified) {
			t.Errorf("Updated: got %v, want %v", s.Updated, lastModified)
		}
		if _, ok := wantPkgs[s.ProductID]; ok {
			wantPkgs[s.ProductID] = true
		}
	}
	for pkg, found := range wantPkgs {
		if !found {
			t.Errorf("missing statement for %q", pkg)
		}
	}
}

func TestAdapter_HEADShortCircuit(t *testing.T) {
	// When since > Last-Modified, Sync must skip the GET and emit nothing.
	lastModified := time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC)
	since := time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)

	var getCalls int
	mux := http.NewServeMux()
	mux.HandleFunc("/oci.com.ubuntu.noble.usn.oval.xml.bz2", func(w http.ResponseWriter, r *http.Request) {
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

	a, _ := New(source.AdapterConfig{Type: Type, ID: "ub", URL: server.URL + "/oci.com.ubuntu.noble.usn.oval.xml.bz2"})
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
