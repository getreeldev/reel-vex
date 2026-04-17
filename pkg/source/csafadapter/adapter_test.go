package csafadapter

import (
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

// fixturePath resolves the repo-root testdata/ path from this package's test dir.
func fixturePath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "testdata", name)
}

// newTestFeed boots an httptest server that serves a minimal provider-
// metadata + changes.csv + single CSAF document (the real RH CVE-2024-0217
// fixture committed at testdata/). Returns the metadata URL the adapter
// should point at.
func newTestFeed(t *testing.T) (metadataURL string, close func()) {
	t.Helper()
	fixture, err := os.ReadFile(fixturePath(t, "secdata-1220-cve-2024-0217.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	mux.HandleFunc("/provider-metadata.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"publisher":{"name":"Test Vendor"},"distributions":[{"directory_url":"%s/vex/"}]}`, server.URL)
	})
	mux.HandleFunc("/vex/changes.csv", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		fmt.Fprint(w, `"2024/cve-2024-0217.json","2024-01-05T00:00:00+00:00"`+"\n")
	})
	mux.HandleFunc("/vex/2024/cve-2024-0217.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(fixture)
	})
	return server.URL + "/provider-metadata.json", server.Close
}

func TestCSAFAdapter_New(t *testing.T) {
	t.Run("rejects empty id", func(t *testing.T) {
		_, err := New(source.AdapterConfig{Type: Type, URL: "https://example/metadata.json"})
		if err == nil {
			t.Fatal("expected error for empty id")
		}
	})
	t.Run("rejects empty url", func(t *testing.T) {
		_, err := New(source.AdapterConfig{Type: Type, ID: "v"})
		if err == nil {
			t.Fatal("expected error for empty url")
		}
	})
}

func TestCSAFAdapter_LifecycleAgainstHTTPTest(t *testing.T) {
	metadataURL, shutdown := newTestFeed(t)
	defer shutdown()

	a, err := New(source.AdapterConfig{
		Type: Type,
		ID:   "test",
		URL:  metadataURL,
	})
	if err != nil {
		t.Fatal(err)
	}

	if a.SourceFormat() != "csaf" {
		t.Errorf("SourceFormat: got %q, want csaf", a.SourceFormat())
	}

	feed, err := a.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if feed.FeedURL == "" {
		t.Error("expected non-empty FeedURL")
	}
	if a.Name() != "Test Vendor" {
		t.Errorf("Name picked up from discovery: got %q, want Test Vendor", a.Name())
	}

	var count int
	var sawBaseCPE bool
	err = a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
		count++
		if s.ProductID == "cpe:/o:redhat:enterprise_linux:8" {
			sawBaseCPE = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if count == 0 {
		t.Fatal("expected statements emitted, got 0")
	}
	if !sawBaseCPE {
		t.Error("expected base RHEL 8 CPE statement from fixture")
	}
}
