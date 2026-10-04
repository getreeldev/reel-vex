package csafadapter

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getreeldev/reel-vex/pkg/source"
)

// TestMain drops the pause before the second read of failed documents.
func TestMain(m *testing.M) {
	retryPause = 0
	os.Exit(m.Run())
}

// fixturePath resolves the repo-root testdata/ path from this package's test dir.
func fixturePath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "testdata", name)
}

// newTestFeed boots an httptest server that serves a minimal provider-
// metadata + changes.csv + index.txt + single CSAF document (the real RH
// CVE-2024-0217 fixture committed at testdata/). Returns the metadata URL the
// adapter should point at.
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
	mux.HandleFunc("/vex/index.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "2024/cve-2024-0217.json\n")
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
		if q := strings.IndexByte(s.ProductID, '?'); q >= 0 && strings.Contains(s.ProductID[q:], "@") {
			t.Errorf("%s: ProductID %q puts the version after the qualifiers", s.CVE, s.ProductID)
		}
		if s.ProductID == "cpe:/o:redhat:enterprise_linux:8" {
			sawBaseCPE = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	// A cold start that read every document index.txt lists is complete.
	if !res.Complete {
		t.Error("cold-start crawl with no failures must report Complete")
	}
	if want := []string{"CVE-2024-0217"}; !slices.Equal(res.RefreshedCVEs, want) {
		t.Errorf("RefreshedCVEs: got %v, want %v", res.RefreshedCVEs, want)
	}
	if want := []string{"CVE-2024-0217"}; !slices.Equal(res.LiveCVEs, want) {
		t.Errorf("LiveCVEs: got %v, want %v", res.LiveCVEs, want)
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
const zeroStatementDoc = `{"document":{"category":"csaf_vex","csaf_version":"2.0","title":"t","tracking":{"id":"CVE-2024-9999"}},"vulnerabilities":[{"cve":"CVE-2024-9999"}]}`

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

// TestSync_ColdStartWithoutManifestIsIncomplete: without its index.txt a cold start
// cannot know it read every live document, so it is not Complete.
func TestSync_ColdStartWithoutManifestIsIncomplete(t *testing.T) {
	fixture, err := os.ReadFile(fixturePath(t, "secdata-1220-cve-2024-0217.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	metadataURL, _ := feedServer(t, map[string][]byte{
		"changes.csv":             []byte(`"2024/cve-2024-0217.json","2024-01-05T00:00:00+00:00"` + "\n"),
		"2024/cve-2024-0217.json": fixture,
	})
	a, err := New(source.AdapterConfig{Type: Type, ID: "test", URL: metadataURL})
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.Sync(context.Background(), time.Time{}, func(source.Statement) error { return nil })
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if res.Complete {
		t.Error("a cold start with no index.txt must not report Complete")
	}
	// No manifest: nil, not empty.
	if res.LiveCVEs != nil {
		t.Errorf("LiveCVEs must be nil when index.txt 404s, got %#v", res.LiveCVEs)
	}
	if want := []string{"CVE-2024-0217"}; !slices.Equal(res.RefreshedCVEs, want) {
		t.Errorf("RefreshedCVEs: got %v, want %v", res.RefreshedCVEs, want)
	}
}

// csafDoc is a minimal CSAF VEX document for cve stating status for one
// openssl RPM, released at released.
func csafDoc(cve, status, released string) []byte {
	return []byte(fmt.Sprintf(`{
 "document": {"category":"csaf_vex","csaf_version":"2.0","title":"t","publisher":{"category":"vendor","name":"x","namespace":"https://x"},
   "tracking":{"id":"%[1]s","current_release_date":"%[3]s","initial_release_date":"2020-01-01T00:00:00Z","revision_history":[{"date":"2020-01-01T00:00:00Z","number":"1","summary":"s"}],"status":"final","version":"1"}},
 "product_tree": {"full_product_names":[{"name":"openssl","product_id":"P1","product_identification_helper":{"purl":"pkg:rpm/redhat/openssl@3.0.7-1.el9?arch=x86_64"}}]},
 "vulnerabilities":[{"cve":"%[1]s","product_status":{"%[2]s":["P1"]}}]
}`, cve, status, released))
}

// feedServer serves provider-metadata.json, and under /vex/ each file in
// files (path relative to the feed). hits counts the requests per path.
func feedServer(t *testing.T, files map[string][]byte) (metadataURL string, hits map[string]int) {
	t.Helper()
	return feedServerWrapped(t, files, func(h http.Handler) http.Handler { return h })
}

// feedServerWrapped is feedServer with wrap around its handler, to answer
// some paths otherwise.
func feedServerWrapped(t *testing.T, files map[string][]byte, wrap func(http.Handler) http.Handler) (metadataURL string, hits map[string]int) {
	t.Helper()
	hits = map[string]int{}
	var mu sync.Mutex
	mux := http.NewServeMux()
	server := httptest.NewServer(wrap(mux))
	t.Cleanup(server.Close)
	mux.HandleFunc("/provider-metadata.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"publisher":{"name":"Test Vendor"},"distributions":[{"directory_url":"%s/vex/"}]}`, server.URL)
	})
	mux.HandleFunc("/vex/", func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/vex/")
		mu.Lock()
		hits[p]++
		mu.Unlock()
		body, ok := files[p]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	})
	return server.URL + "/provider-metadata.json", hits
}

// TestSync_NonCSAFAnswerIsAFailure: a 200 whose JSON body is not the CSAF
// document its path names extracts to nothing without error; counted as
// refreshed, the per-document replace would delete every row of that CVE. It
// is a failed fetch: not refreshed, and the run is incomplete. A real SUSE
// document with no vulnerabilities array (SUSE's cve-1999-0003.json, 2026-10)
// is a valid document that states nothing, and refreshes.
func TestSync_NonCSAFAnswerIsAFailure(t *testing.T) {
	const suseNoVulns = `{"document":{"category":"csaf_vex","csaf_version":"2.0","title":"SUSE CVE CVE-1999-0003",
		"tracking":{"current_release_date":"2023-02-15T06:22:07Z","id":"CVE-1999-0003","initial_release_date":"2023-02-15T06:22:07Z",
		"revision_history":[{"date":"2023-02-15T06:22:07Z","number":"1","summary":"Current version"}],"status":"final","version":"1"}}}`
	files := map[string][]byte{
		"changes.csv": []byte(`"cve-2099-0001.json","2026-05-25T00:00:00Z"` + "\n" +
			`"cve-2099-0002.json","2026-05-25T00:00:00Z"` + "\n" +
			`"cve-2099-0003.json","2026-05-25T00:00:00Z"` + "\n" +
			`"cve-2099-0004.json","2026-05-25T00:00:00Z"` + "\n" +
			`"cve-1999-0003.json","2026-05-25T00:00:00Z"` + "\n"),
		"index.txt":          []byte("cve-2099-0001.json\ncve-2099-0002.json\ncve-2099-0003.json\ncve-2099-0004.json\ncve-1999-0003.json\n"),
		"cve-2099-0001.json": []byte(`{}`),
		"cve-2099-0002.json": []byte(`{"message":"Service Unavailable"}`),
		"cve-2099-0003.json": csafDoc("CVE-2099-0009", "fixed", "2026-05-25T00:00:00Z"), // another CVE's document
		"cve-2099-0004.json": []byte(`[]`),
		"cve-1999-0003.json": []byte(suseNoVulns),
	}
	for _, since := range []time.Time{{}, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} {
		metadataURL, _ := feedServer(t, files)
		a, err := New(source.AdapterConfig{Type: Type, ID: "test", URL: metadataURL})
		if err != nil {
			t.Fatal(err)
		}
		var count int
		res, err := a.Sync(context.Background(), since, func(source.Statement) error { count++; return nil })
		if err != nil {
			t.Fatalf("Sync: %v", err)
		}
		if want := []string{"CVE-1999-0003"}; !slices.Equal(res.RefreshedCVEs, want) {
			t.Errorf("since %v: RefreshedCVEs: got %v, want %v", since, res.RefreshedCVEs, want)
		}
		if res.Complete {
			t.Errorf("since %v: a run that read a non-CSAF answer must not report Complete", since)
		}
		if count != 0 {
			t.Errorf("since %v: %d statements emitted from documents that are not the CVE's", since, count)
		}
	}
}

func TestCheckDocument(t *testing.T) {
	for _, c := range []struct {
		doc, cve string
		ok       bool
	}{
		{`{"document":{"csaf_version":"2.0","tracking":{"id":"CVE-2024-1"}}}`, "CVE-2024-1", true},
		{`{"document":{"csaf_version":"2.0","tracking":{"id":"cve-2024-1"}}}`, "CVE-2024-1", true},
		{`{"document":{"csaf_version":"2.0","tracking":{"id":"RHSA-1"}},"vulnerabilities":[{"cve":"CVE-2024-1"}]}`, "CVE-2024-1", true},
		{`{"document":{"csaf_version":"2.0","tracking":{"id":"CVE-2024-2"}},"vulnerabilities":[{"cve":"CVE-2024-2"}]}`, "CVE-2024-1", false},
		{`{"document":{"csaf_version":"2.0","tracking":{"id":"X"}}}`, "", true},
		{`{"document":{"tracking":{"id":"CVE-2024-1"}}}`, "CVE-2024-1", false},
		{`{"document":{"csaf_version":"2.0"}}`, "CVE-2024-1", false},
		{`{"vulnerabilities":[{"cve":"CVE-2024-1"}]}`, "CVE-2024-1", false},
		{`{}`, "CVE-2024-1", false},
		{`{"message":"Service Unavailable"}`, "CVE-2024-1", false},
		{`[]`, "CVE-2024-1", false},
		{`<html>`, "CVE-2024-1", false},
	} {
		if err := checkDocument([]byte(c.doc), c.cve); (err == nil) != c.ok {
			t.Errorf("checkDocument(%s, %q) = %v, want ok=%v", c.doc, c.cve, err, c.ok)
		}
	}
}

// TestSync_ManifestMissingAFetchedDocumentIsNotTrusted: an index.txt that
// does not list a document this run fetched from the same feed is truncated
// or mid-rewrite, so it is no manifest: LiveCVEs nil (a withdrawal by it could
// remove live CVEs), and a cold start is not Complete.
func TestSync_ManifestMissingAFetchedDocumentIsNotTrusted(t *testing.T) {
	files := map[string][]byte{
		"changes.csv": []byte(`"2099/cve-2099-0001.json","2026-05-25T00:00:00+00:00"` + "\n" +
			`"2099/cve-2099-0002.json","2026-05-24T00:00:00+00:00"` + "\n"),
		// The vendor is rewriting it: the first line only.
		"index.txt":               []byte("2099/cve-2099-0002.json\n"),
		"2099/cve-2099-0001.json": csafDoc("CVE-2099-0001", "fixed", "2026-05-25T00:00:00Z"),
		"2099/cve-2099-0002.json": csafDoc("CVE-2099-0002", "fixed", "2026-05-24T00:00:00Z"),
	}
	for _, since := range []time.Time{{}, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} {
		metadataURL, _ := feedServer(t, files)
		a, err := New(source.AdapterConfig{Type: Type, ID: "test", URL: metadataURL})
		if err != nil {
			t.Fatal(err)
		}
		res, err := a.Sync(context.Background(), since, func(source.Statement) error { return nil })
		if err != nil {
			t.Fatalf("Sync: %v", err)
		}
		if res.LiveCVEs != nil {
			t.Errorf("since %v: LiveCVEs must be nil when index.txt lacks a fetched document, got %v", since, res.LiveCVEs)
		}
		if res.Complete {
			t.Errorf("since %v: Complete with an untrusted manifest", since)
		}
		if want := []string{"CVE-2099-0001", "CVE-2099-0002"}; !slices.Equal(res.RefreshedCVEs, want) {
			t.Errorf("since %v: RefreshedCVEs: got %v, want %v", since, res.RefreshedCVEs, want)
		}
	}
}

// changesLine is one changes.csv line dated at.
func changesLine(path string, at time.Time) string {
	return `"` + path + `","` + at.UTC().Format(time.RFC3339) + `"` + "\n"
}

// TestSync_GoneAndUnlistedIsWithdrawn: a document changes.csv names that
// answers 404 or 410 and that index.txt does not list was withdrawn after it
// was listed: not a failure, not refreshed, no retry. One index.txt does list
// is a failure, read again next run.
func TestSync_GoneAndUnlistedIsWithdrawn(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	unlisted404, unlisted410, listed404 := now.Add(-3*time.Hour), now.Add(-2*time.Hour), now.Add(-time.Hour)
	files := map[string][]byte{
		"changes.csv": []byte(changesLine("2099/cve-2099-0001.json", unlisted404) +
			changesLine("2099/cve-2099-0002.json", unlisted410) +
			changesLine("2099/cve-2099-0003.json", now.Add(-30*time.Minute))),
		"index.txt":               []byte("2099/cve-2099-0003.json\n"),
		"2099/cve-2099-0003.json": csafDoc("CVE-2099-0003", "fixed", "2026-05-25T00:00:00Z"),
	}
	gone410 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/cve-2099-0002.json") {
				w.WriteHeader(http.StatusGone)
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	t.Run("unlisted", func(t *testing.T) {
		metadataURL, _ := feedServerWrapped(t, files, gone410)
		a, err := New(source.AdapterConfig{Type: Type, ID: "suse", URL: metadataURL})
		if err != nil {
			t.Fatal(err)
		}
		res, err := a.Sync(context.Background(), time.Time{}, func(source.Statement) error { return nil })
		if err != nil {
			t.Fatalf("Sync: %v", err)
		}
		if !res.Complete {
			t.Error("documents withdrawn after changes.csv named them must not make a cold start incomplete")
		}
		if !res.RetryFrom.IsZero() {
			t.Errorf("RetryFrom = %v, want zero: nothing failed", res.RetryFrom)
		}
		if want := []string{"CVE-2099-0003"}; !slices.Equal(res.RefreshedCVEs, want) {
			t.Errorf("RefreshedCVEs: got %v, want %v", res.RefreshedCVEs, want)
		}
	})

	t.Run("listed", func(t *testing.T) {
		listedFiles := map[string][]byte{}
		for k, v := range files {
			listedFiles[k] = v
		}
		listedFiles["changes.csv"] = append(append([]byte{}, files["changes.csv"]...), changesLine("2099/cve-2099-0004.json", listed404)...)
		listedFiles["index.txt"] = []byte("2099/cve-2099-0003.json\n2099/cve-2099-0004.json\n")
		metadataURL, _ := feedServerWrapped(t, listedFiles, gone410)
		a, err := New(source.AdapterConfig{Type: Type, ID: "suse", URL: metadataURL})
		if err != nil {
			t.Fatal(err)
		}
		res, err := a.Sync(context.Background(), now.Add(-24*time.Hour), func(source.Statement) error { return nil })
		if err != nil {
			t.Fatalf("Sync: %v", err)
		}
		if !res.RetryFrom.Equal(listed404) {
			t.Errorf("RetryFrom = %v, want the listed 404's date %v", res.RetryFrom, listed404)
		}
		if want := []string{"CVE-2099-0003"}; !slices.Equal(res.RefreshedCVEs, want) {
			t.Errorf("RefreshedCVEs: got %v, want %v", res.RefreshedCVEs, want)
		}
	})
}

// TestSync_FailureSetsRetryFrom: RetryFrom is the changes.csv date of the
// earliest document that failed — a refused body, an HTTP error — so the
// next run reads it again; a failure older than retryWindow is given up on
// and holds nothing back.
func TestSync_FailureSetsRetryFrom(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	recent, older, ancient := now.Add(-time.Hour), now.Add(-6*24*time.Hour), now.Add(-8*24*time.Hour)
	forbidden := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/cve-2099-0002.json") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	for _, c := range []struct {
		name  string
		lines string
		want  time.Time
	}{
		{"recent failures", changesLine("2099/cve-2099-0001.json", recent) + changesLine("2099/cve-2099-0002.json", older) +
			changesLine("2099/cve-2099-0003.json", now), older},
		{"a failure past the window", changesLine("2099/cve-2099-0001.json", recent) + changesLine("2099/cve-2099-0002.json", ancient) +
			changesLine("2099/cve-2099-0003.json", now), recent},
		{"only a failure past the window", changesLine("2099/cve-2099-0002.json", ancient) +
			changesLine("2099/cve-2099-0003.json", now), time.Time{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			metadataURL, _ := feedServerWrapped(t, map[string][]byte{
				"changes.csv":             []byte(c.lines),
				"index.txt":               []byte("2099/cve-2099-0001.json\n2099/cve-2099-0002.json\n2099/cve-2099-0003.json\n"),
				"2099/cve-2099-0001.json": []byte(`{"message":"Service Unavailable"}`),
				"2099/cve-2099-0003.json": csafDoc("CVE-2099-0003", "fixed", "2026-05-25T00:00:00Z"),
			}, forbidden)
			a, err := New(source.AdapterConfig{Type: Type, ID: "suse", URL: metadataURL})
			if err != nil {
				t.Fatal(err)
			}
			res, err := a.Sync(context.Background(), now.Add(-30*24*time.Hour), func(source.Statement) error { return nil })
			if err != nil {
				t.Fatalf("Sync: %v", err)
			}
			if !res.RetryFrom.Equal(c.want) {
				t.Errorf("RetryFrom = %v, want %v", res.RetryFrom, c.want)
			}
			if want := []string{"CVE-2099-0003"}; !slices.Equal(res.RefreshedCVEs, want) {
				t.Errorf("RefreshedCVEs: got %v, want %v", res.RefreshedCVEs, want)
			}
		})
	}
}

// TestSync_FailedDocumentsAreReadOnceMore: after the main pass, every
// document that failed — an HTTP error, a non-CSAF body, a 404 on a listed
// document, an index.txt-only document — is read once more, retryPause later.
// One read then counts exactly as if the first read had worked; only one that
// fails again is a failure. A withdrawn document is not read again.
func TestSync_FailedDocumentsAreReadOnceMore(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	const (
		forbiddenOnce = "2099/cve-2099-0001.json"
		errorPageOnce = "2099/cve-2099-0002.json"
		indexOnly     = "2099/cve-2099-0003.json" // 404 once, listed
		alwaysBroken  = "2099/cve-2099-0004.json"
		withdrawn     = "2099/cve-2099-0005.json" // 404, unlisted
	)
	brokenAt := now.Add(-2 * time.Hour)
	run := func(t *testing.T, withBroken bool, pause time.Duration) (source.SyncResult, map[string]int, map[string][]time.Time) {
		t.Helper()
		old := retryPause
		retryPause = pause
		t.Cleanup(func() { retryPause = old })
		changes := changesLine(forbiddenOnce, now.Add(-3*time.Hour)) + changesLine(errorPageOnce, now.Add(-time.Hour)) +
			changesLine(withdrawn, now.Add(-time.Hour))
		index := forbiddenOnce + "\n" + errorPageOnce + "\n" + indexOnly + "\n"
		if withBroken {
			changes += changesLine(alwaysBroken, brokenAt)
			index += alwaysBroken + "\n"
		}
		var mu sync.Mutex
		at := map[string][]time.Time{}
		flaky := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p := strings.TrimPrefix(r.URL.Path, "/vex/")
				mu.Lock()
				at[p] = append(at[p], time.Now())
				n := len(at[p])
				mu.Unlock()
				switch {
				case p == alwaysBroken:
					w.WriteHeader(http.StatusForbidden)
				case p == forbiddenOnce && n == 1:
					w.WriteHeader(http.StatusForbidden)
				case p == errorPageOnce && n == 1:
					fmt.Fprint(w, `{"message":"Service Unavailable"}`)
				case p == indexOnly && n == 1:
					http.NotFound(w, r)
				default:
					next.ServeHTTP(w, r)
				}
			})
		}
		metadataURL, hits := feedServerWrapped(t, map[string][]byte{
			"changes.csv": []byte(changes),
			"index.txt":   []byte(index),
			forbiddenOnce: csafDoc("CVE-2099-0001", "fixed", "2026-05-25T00:00:00Z"),
			errorPageOnce: csafDoc("CVE-2099-0002", "fixed", "2026-05-25T00:00:00Z"),
			indexOnly:     csafDoc("CVE-2099-0003", "fixed", "2026-05-25T00:00:00Z"),
		}, flaky)
		a, err := New(source.AdapterConfig{Type: Type, ID: "suse", URL: metadataURL})
		if err != nil {
			t.Fatal(err)
		}
		emitted := map[string]int{}
		res, err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error { emitted[s.CVE]++; return nil })
		if err != nil {
			t.Fatalf("Sync: %v", err)
		}
		for _, cve := range []string{"CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"} {
			if emitted[cve] != 1 {
				t.Errorf("%s: %d statements emitted, want the second read's 1", cve, emitted[cve])
			}
		}
		if want := []string{"CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"}; !slices.Equal(res.RefreshedCVEs, want) {
			t.Errorf("RefreshedCVEs: got %v, want %v", res.RefreshedCVEs, want)
		}
		if hits[withdrawn] != 1 {
			t.Errorf("a withdrawn document was read %d times, want once", hits[withdrawn])
		}
		return res, hits, at
	}

	t.Run("all recover", func(t *testing.T) {
		res, _, _ := run(t, false, 0)
		if !res.Complete {
			t.Error("documents read on the second pass leave a cold start Complete")
		}
		if !res.RetryFrom.IsZero() {
			t.Errorf("RetryFrom = %v, want zero: every document was read", res.RetryFrom)
		}
	})

	t.Run("one stays broken", func(t *testing.T) {
		res, _, at := run(t, true, 0)
		if res.Complete {
			t.Error("a document that failed twice must make the run incomplete")
		}
		if !res.RetryFrom.Equal(brokenAt) {
			t.Errorf("RetryFrom = %v, want the broken document's date %v", res.RetryFrom, brokenAt)
		}
		if n := len(at[alwaysBroken]); n != 2 {
			t.Errorf("the broken document was read %d times, want twice", n)
		}
	})

	t.Run("the second read waits retryPause", func(t *testing.T) {
		const pause = 150 * time.Millisecond
		_, _, at := run(t, false, pause)
		if ts := at[forbiddenOnce]; len(ts) != 2 || ts[1].Sub(ts[0]) < pause {
			t.Errorf("second read of %s: requests at %v, want two at least %v apart", forbiddenOnce, ts, pause)
		}
	})
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
