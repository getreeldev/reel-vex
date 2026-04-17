package redhatoval

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
func serveFixture(t *testing.T, lastModified time.Time) (*httptest.Server, []byte) {
	t.Helper()
	raw, err := os.ReadFile(fixturePath(t, "redhat-oval-eus-sample.oval.xml.bz2"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/rhel-9.6-eus.oval.xml.bz2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", lastModified.UTC().Format(http.TimeFormat))
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/x-bzip2")
		w.Write(raw)
	})
	return httptest.NewServer(mux), raw
}

func TestNew(t *testing.T) {
	t.Run("requires id", func(t *testing.T) {
		_, err := New(source.AdapterConfig{Type: Type, URL: "https://example/rhel.oval.xml.bz2"})
		if err == nil {
			t.Fatal("expected error for empty id")
		}
	})
	t.Run("requires url", func(t *testing.T) {
		_, err := New(source.AdapterConfig{Type: Type, ID: "rh"})
		if err == nil {
			t.Fatal("expected error for empty url")
		}
	})
}

func TestAdapter_Lifecycle(t *testing.T) {
	lastModified := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)
	server, _ := serveFixture(t, lastModified)
	defer server.Close()

	a, err := New(source.AdapterConfig{
		Type: Type,
		ID:   "redhat-oval-test",
		URL:  server.URL + "/rhel-9.6-eus.oval.xml.bz2",
	})
	if err != nil {
		t.Fatal(err)
	}

	if a.Vendor() != "redhat" {
		t.Errorf("Vendor: got %q, want redhat", a.Vendor())
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

	// First sync with since=0 pulls the whole file.
	var stmts []source.Statement
	err = a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
		stmts = append(stmts, s)
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(stmts) == 0 {
		t.Fatal("expected statements emitted, got 0")
	}

	// SECDATA-1181 check: the EUS CPEs CSAF doesn't publish should be
	// present here. This is the whole point of the adapter.
	required := []string{
		"cpe:/a:redhat:rhel_eus:9.6::appstream",
		"cpe:/a:redhat:rhel_eus:9.6::sap_hana",
	}
	for _, want := range required {
		var found bool
		for _, s := range stmts {
			if s.ProductID == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected statement for %q (SECDATA-1181 EUS coverage gap)", want)
		}
	}

	// Every statement carries the file's Last-Modified as Updated.
	for _, s := range stmts {
		if !s.Updated.Equal(lastModified) {
			t.Errorf("statement.Updated: got %v, want %v", s.Updated, lastModified)
			break
		}
	}
}

func TestAdapter_HEADShortCircuit(t *testing.T) {
	// When since > Last-Modified, Sync must skip the GET and emit nothing.
	lastModified := time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC)
	since := time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)

	var getCalls int
	mux := http.NewServeMux()
	mux.HandleFunc("/rhel-9.6-eus.oval.xml.bz2", func(w http.ResponseWriter, r *http.Request) {
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

	a, _ := New(source.AdapterConfig{Type: Type, ID: "rh", URL: server.URL + "/rhel-9.6-eus.oval.xml.bz2"})
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
