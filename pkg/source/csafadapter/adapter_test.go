package csafadapter

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
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
	res, err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
		count++
		if s.ProductID == "cpe:/o:redhat:enterprise_linux:8" {
			sawBaseCPE = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	// A cold start that read every document is complete.
	if !res.Complete {
		t.Error("cold-start crawl with no failures must report Complete")
	}
	if want := []string{"CVE-2024-0217"}; !slices.Equal(res.RefreshedCVEs, want) {
		t.Errorf("RefreshedCVEs: got %v, want %v", res.RefreshedCVEs, want)
	}
	// The feed serves no index.txt (404): no manifest, and nil — not empty.
	if res.LiveCVEs != nil {
		t.Errorf("LiveCVEs must be nil when index.txt 404s, got %#v", res.LiveCVEs)
	}
	if count == 0 {
		t.Fatal("expected statements emitted, got 0")
	}
	if !sawBaseCPE {
		t.Error("expected base RHEL 8 CPE statement from fixture")
	}
}

// zeroStatementDoc is a CSAF document that parses but yields no statements —
// SUSE re-publishes some CVEs with no product_status at all.
const zeroStatementDoc = `{"document":{"category":"csaf_vex","title":"t"},"vulnerabilities":[{"cve":"CVE-2024-9999"}]}`

// TestSync_IncrementalReportsRefreshedAndLive: an incremental run is never
// Complete; RefreshedCVEs lists exactly the documents fetched and parsed —
// a zero-statement document included, a 404 left out — and LiveCVEs is the
// distribution's index.txt as CVE ids.
func TestSync_IncrementalReportsRefreshedAndLive(t *testing.T) {
	fixture, err := os.ReadFile(fixturePath(t, "secdata-1220-cve-2024-0217.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/provider-metadata.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"publisher":{"name":"Test Vendor"},"distributions":[{"directory_url":"%s/vex/"}]}`, server.URL)
	})
	mux.HandleFunc("/vex/changes.csv", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `"2024/cve-2024-0217.json","2024-01-05T00:00:00+00:00"`+"\n"+
			`"2024/cve-2024-9999.json","2024-01-06T00:00:00+00:00"`+"\n"+
			`"2024/cve-2024-0404.json","2024-01-07T00:00:00+00:00"`+"\n"+
			`"2023/cve-2023-0001.json","2023-06-01T00:00:00+00:00"`+"\n") // before since: not fetched
	})
	mux.HandleFunc("/vex/2024/cve-2024-0217.json", func(w http.ResponseWriter, r *http.Request) { w.Write(fixture) })
	mux.HandleFunc("/vex/2024/cve-2024-9999.json", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, zeroStatementDoc) })
	// /vex/2024/cve-2024-0404.json has no handler: 404.
	mux.HandleFunc("/vex/index.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "2023/cve-2023-0001.json\n2024/CVE-2024-0217.json\n\nREADME.md\n2024/cve-2024-9999.json\n")
	})

	a, err := New(source.AdapterConfig{Type: Type, ID: "test", URL: server.URL + "/provider-metadata.json"})
	if err != nil {
		t.Fatal(err)
	}
	since := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	var count int
	res, err := a.Sync(context.Background(), since, func(s source.Statement) error { count++; return nil })
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if count == 0 {
		t.Fatal("expected statements from cve-2024-0217")
	}
	if res.Complete {
		t.Error("an incremental run must not report Complete")
	}
	if want := []string{"CVE-2024-0217", "CVE-2024-9999"}; !slices.Equal(res.RefreshedCVEs, want) {
		t.Errorf("RefreshedCVEs: got %v, want %v", res.RefreshedCVEs, want)
	}
	if want := []string{"CVE-2023-0001", "CVE-2024-0217", "CVE-2024-9999"}; !slices.Equal(res.LiveCVEs, want) {
		t.Errorf("LiveCVEs: got %v, want %v", res.LiveCVEs, want)
	}
}

// TestSync_LiveCVEsNilWhenIndexNamesNoCVE: a 200 index.txt that names no CVE
// document is not a manifest of zero live documents; it is no manifest.
func TestSync_LiveCVEsNilWhenIndexNamesNoCVE(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/provider-metadata.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"publisher":{"name":"Test Vendor"},"distributions":[{"directory_url":"%s/vex/"}]}`, server.URL)
	})
	mux.HandleFunc("/vex/changes.csv", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/vex/index.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>not a listing</html>\n")
	})
	a, err := New(source.AdapterConfig{Type: Type, ID: "test", URL: server.URL + "/provider-metadata.json"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.Sync(context.Background(), time.Now(), func(source.Statement) error { return nil })
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if res.LiveCVEs != nil {
		t.Errorf("LiveCVEs must be nil when index.txt names no CVE, got %#v", res.LiveCVEs)
	}
}

// TestSync_UnparseableChangesLineIsIncomplete: a cold-start crawl whose
// changes.csv has a line it cannot parse may have missed a document, so it is
// not Complete — a whole-feed sweep would otherwise delete that document's rows.
func TestSync_UnparseableChangesLineIsIncomplete(t *testing.T) {
	fixture, err := os.ReadFile(fixturePath(t, "secdata-1220-cve-2024-0217.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/provider-metadata.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"publisher":{"name":"Test Vendor"},"distributions":[{"directory_url":"%s/vex/"}]}`, server.URL)
	})
	mux.HandleFunc("/vex/changes.csv", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `"2024/cve-2024-0217.json","2024-01-05T00:00:00+00:00"`+"\n"+
			`"2024/cve-2024-0218.json","2024-01-05 00:00:00"`+"\n")
	})
	mux.HandleFunc("/vex/2024/cve-2024-0217.json", func(w http.ResponseWriter, r *http.Request) { w.Write(fixture) })

	a, err := New(source.AdapterConfig{Type: Type, ID: "test", URL: server.URL + "/provider-metadata.json"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.Sync(context.Background(), time.Time{}, func(source.Statement) error { return nil })
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if res.Complete {
		t.Error("a crawl that skipped an unparseable changes.csv line must not report Complete")
	}
	if want := []string{"CVE-2024-0217"}; !slices.Equal(res.RefreshedCVEs, want) {
		t.Errorf("RefreshedCVEs: got %v, want %v", res.RefreshedCVEs, want)
	}
}

func TestDocCVE(t *testing.T) {
	for in, want := range map[string]string{
		"2024/cve-2024-6387.json":                     "CVE-2024-6387",
		"cve-2024-6387.json":                          "CVE-2024-6387",
		"csaf_vex_2026-05-23/2024/cve-2024-6387.json": "CVE-2024-6387",
		"2024/CVE-2024-12345.JSON":                    "CVE-2024-12345",
		"2024/cve-2024-6387.json.asc":                 "",
		"index.txt":                                   "",
		"2024/suse-su-2024-1.json":                    "",
	} {
		if got := docCVE(in); got != want {
			t.Errorf("docCVE(%q) = %q, want %q", in, got, want)
		}
	}
}
