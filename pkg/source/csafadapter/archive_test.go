package csafadapter

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/getreeldev/reel-vex/pkg/source"
	"github.com/klauspost/compress/zstd"
)

// buildZstdTar packs name->content into a tar and zstd-compresses it, mirroring
// Red Hat's csaf_vex_*.tar.zst layout.
func buildZstdTar(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var zBuf bytes.Buffer
	zw, err := zstd.NewWriter(&zBuf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(tarBuf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return zBuf.Bytes()
}

// TestSync_BulkArchiveColdStart verifies the cold-start path downloads and
// walks the bulk archive (instead of per-document crawling), stamps statements
// with the document's own current_release_date (not the archive date), and
// uses the archive date as the floor for the changes.csv
// delta (so it does NOT re-crawl pre-archive documents).
func TestSync_BulkArchiveColdStart(t *testing.T) {
	fixture, err := os.ReadFile(fixturePath(t, "secdata-1220-cve-2024-0217.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	const archiveName = "csaf_vex_2026-05-23.tar.zst"
	archive := buildZstdTar(t, map[string][]byte{
		"csaf_vex_2026-05-23/2024/cve-2024-0217.json": fixture,
		"csaf_vex_2026-05-23/index.txt":               []byte("non-json, must be skipped"),
	})

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/provider-metadata.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"publisher":{"name":"Test Vendor"},"distributions":[{"directory_url":"%s/vex/"}]}`, server.URL)
	})
	mux.HandleFunc("/vex/archive_latest.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, archiveName)
	})
	mux.HandleFunc("/vex/"+archiveName, func(w http.ResponseWriter, r *http.Request) {
		w.Write(archive)
	})
	mux.HandleFunc("/vex/changes.csv", func(w http.ResponseWriter, r *http.Request) {
		// One entry dated BEFORE the archive cut — the delta must filter it out.
		fmt.Fprint(w, `"2024/cve-2024-0217.json","2024-01-05T00:00:00+00:00"`+"\n")
	})
	var docFetched bool
	mux.HandleFunc("/vex/2024/cve-2024-0217.json", func(w http.ResponseWriter, r *http.Request) {
		docFetched = true
		w.Write(fixture)
	})
	mux.HandleFunc("/vex/index.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "2024/cve-2024-0217.json\n")
	})

	a, err := New(source.AdapterConfig{Type: Type, ID: "test", URL: server.URL + "/provider-metadata.json"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	var count int
	var sawBaseCPE bool
	var updated time.Time
	res, err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
		count++
		updated = s.Updated
		if s.ProductID == "cpe:/o:redhat:enterprise_linux:8" {
			sawBaseCPE = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if count == 0 {
		t.Fatal("expected statements from the bulk archive, got 0")
	}
	if !sawBaseCPE {
		t.Error("expected base RHEL 8 CPE statement from the archived doc")
	}
	// The fixture's document.tracking.current_release_date.
	if want := time.Date(2025, 11, 21, 14, 53, 29, 0, time.UTC); !updated.Equal(want) {
		t.Errorf("archive statement Updated: got %v, want %v", updated, want)
	}
	if docFetched {
		t.Error("delta should not re-fetch a pre-archive-date doc — full crawl was not avoided")
	}
	if !res.Complete {
		t.Error("archive cold start with no failed entry must report Complete")
	}
	if len(res.RefreshedCVEs) != 1 || res.RefreshedCVEs[0] != "CVE-2024-0217" {
		t.Errorf("archive-parsed documents count as refreshed: got %v", res.RefreshedCVEs)
	}
}

// TestSync_ArchiveEmitErrorIsReturned: an error from emit while walking the
// archive is the orchestrator's (a full disk, a closed pool), not the
// archive's; the cold start must return it, not fall back to the hours-long
// crawl. Also: an archive entry that fails to extract is read again from the
// feed, and the run is Complete only if that read succeeds.
func TestSync_ArchiveEmitErrorIsReturned(t *testing.T) {
	fixture, err := os.ReadFile(fixturePath(t, "secdata-1220-cve-2024-0217.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	const archiveName = "csaf_vex_2026-05-23.tar.zst"
	feed := func(archived map[string][]byte, live map[string][]byte) map[string][]byte {
		files := map[string][]byte{
			"archive_latest.txt": []byte(archiveName + "\n"),
			archiveName:          buildZstdTar(t, archived),
			// Both dated before the cut: the archive's copies are current.
			"changes.csv": []byte(`"2024/cve-2024-0217.json","2024-01-05T00:00:00+00:00"` + "\n" +
				`"2024/cve-2024-0001.json","2024-01-04T00:00:00+00:00"` + "\n"),
			"index.txt": []byte("2024/cve-2024-0217.json\n2024/cve-2024-0001.json\n"),
		}
		for p, b := range live {
			files[p] = b
		}
		return files
	}

	t.Run("emit error", func(t *testing.T) {
		metadataURL, hits := feedServer(t, feed(map[string][]byte{"csaf_vex_2026-05-23/2024/cve-2024-0217.json": fixture},
			map[string][]byte{"2024/cve-2024-0217.json": fixture}))
		a, err := New(source.AdapterConfig{Type: Type, ID: "test", URL: metadataURL})
		if err != nil {
			t.Fatal(err)
		}
		sentinel := errors.New("disk full")
		res, err := a.Sync(context.Background(), time.Time{}, func(source.Statement) error { return sentinel })
		if !errors.Is(err, sentinel) {
			t.Fatalf("want the emit error back, got %v", err)
		}
		if n := hits["2024/cve-2024-0217.json"] + hits["2024/cve-2024-0001.json"]; n != 0 {
			t.Errorf("an emit error fell back to the crawl (%d document request(s))", n)
		}
		if res.Complete || res.RefreshedCVEs != nil || res.LiveCVEs != nil {
			t.Errorf("a failed Sync must return a zero SyncResult, got %+v", res)
		}
	})

	archived := map[string][]byte{
		"csaf_vex_2026-05-23/2024/cve-2024-0217.json": fixture,
		"csaf_vex_2026-05-23/2024/cve-2024-0001.json": []byte("{not json"),
	}
	t.Run("failed entry, feed fails too", func(t *testing.T) {
		metadataURL, hits := feedServer(t, feed(archived, nil))
		a, err := New(source.AdapterConfig{Type: Type, ID: "test", URL: metadataURL})
		if err != nil {
			t.Fatal(err)
		}
		res, err := a.Sync(context.Background(), time.Time{}, func(source.Statement) error { return nil })
		if err != nil {
			t.Fatalf("Sync: %v", err)
		}
		if res.Complete {
			t.Error("an archive entry that failed to extract and to fetch must make the run incomplete")
		}
		if want := []string{"CVE-2024-0217"}; !slices.Equal(res.RefreshedCVEs, want) {
			t.Errorf("RefreshedCVEs: got %v, want %v", res.RefreshedCVEs, want)
		}
		if hits["2024/cve-2024-0001.json"] != 1 || hits["2024/cve-2024-0217.json"] != 0 {
			t.Errorf("want only the failed entry fetched, once: %v", hits)
		}
	})

	t.Run("failed entry, read from the feed", func(t *testing.T) {
		metadataURL, _ := feedServer(t, feed(archived, map[string][]byte{
			"2024/cve-2024-0001.json": csafDoc("CVE-2024-0001", "fixed", "2024-01-04T00:00:00Z"),
		}))
		a, err := New(source.AdapterConfig{Type: Type, ID: "test", URL: metadataURL})
		if err != nil {
			t.Fatal(err)
		}
		res, err := a.Sync(context.Background(), time.Time{}, func(source.Statement) error { return nil })
		if err != nil {
			t.Fatalf("Sync: %v", err)
		}
		if !res.Complete {
			t.Error("an archive entry read again from the feed leaves the run Complete")
		}
		if want := []string{"CVE-2024-0001", "CVE-2024-0217"}; !slices.Equal(res.RefreshedCVEs, want) {
			t.Errorf("RefreshedCVEs: got %v, want %v", res.RefreshedCVEs, want)
		}
	})
}

// tarFile is one archive entry, in order.
type tarFile struct {
	name string
	body []byte
}

// buildZstdTarCut packs files in order and zstd-compresses the tar; with cut,
// the tar ends halfway through the last file's body — an archive that breaks
// part-way through its walk.
func buildZstdTarCut(t *testing.T, files []tarFile, cut bool) []byte {
	t.Helper()
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	var lastBody int
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		lastBody = tarBuf.Len() // WriteHeader wrote the header block through

		if _, err := tw.Write(f.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := tarBuf.Bytes()
	if cut {
		raw = raw[:lastBody+len(files[len(files)-1].body)/2]
	}
	var zBuf bytes.Buffer
	zw, err := zstd.NewWriter(&zBuf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return zBuf.Bytes()
}

// TestSync_ColdStartReadsEachDocumentOnce: a document changed after the
// weekly archive was cut is in the archive at its old version and in
// changes.csv at its new one. Emitting both would make both versions' rows
// "seen", and the old verdict would survive the complete sweep (affected and
// fixed for one product, served until the vendor republishes). The archive
// skips it and the feed's copy is the only one emitted — whether the archive
// is read whole or breaks part-way and the crawl takes over; and the crawl
// does not fetch again what the archive read before it broke.
func TestSync_ColdStartReadsEachDocumentOnce(t *testing.T) {
	const archiveName = "csaf_vex_2026-05-23.tar.zst"
	const (
		unchanged = "2099/cve-2099-0001.json" // archived, current
		changed   = "2099/cve-2099-0002.json" // archived, changed after the cut
		lost      = "2099/cve-2099-0003.json" // archived after the point the archive breaks
	)
	entries := []tarFile{
		{"csaf_vex_2026-05-23/" + unchanged, csafDoc("CVE-2099-0001", "fixed", "2026-05-01T00:00:00Z")},
		{"csaf_vex_2026-05-23/" + changed, csafDoc("CVE-2099-0002", "known_affected", "2026-05-20T00:00:00Z")},
		{"csaf_vex_2026-05-23/" + lost, csafDoc("CVE-2099-0003", "fixed", "2026-05-02T00:00:00Z")},
	}
	for _, tc := range []struct {
		name string
		cut  bool
	}{
		{"archive read whole", false},
		{"archive breaks part-way", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metadataURL, hits := feedServer(t, map[string][]byte{
				"archive_latest.txt": []byte(archiveName + "\n"),
				archiveName:          buildZstdTarCut(t, entries, tc.cut),
				"changes.csv": []byte(`"` + changed + `","2026-05-25T00:00:00+00:00"` + "\n" +
					`"` + lost + `","2026-05-02T00:00:00+00:00"` + "\n" +
					`"` + unchanged + `","2026-05-01T00:00:00+00:00"` + "\n"),
				"index.txt": []byte(unchanged + "\n" + changed + "\n" + lost + "\n"),
				unchanged:   csafDoc("CVE-2099-0001", "fixed", "2026-05-01T00:00:00Z"),
				changed:     csafDoc("CVE-2099-0002", "fixed", "2026-05-25T00:00:00Z"),
				lost:        csafDoc("CVE-2099-0003", "fixed", "2026-05-02T00:00:00Z"),
			})
			a, err := New(source.AdapterConfig{Type: Type, ID: "redhat", URL: metadataURL})
			if err != nil {
				t.Fatal(err)
			}
			emitted := map[string][]string{}
			res, err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
				emitted[s.CVE] = append(emitted[s.CVE], s.Status)
				return nil
			})
			if err != nil {
				t.Fatalf("Sync: %v", err)
			}
			for _, cve := range []string{"CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"} {
				if got := emitted[cve]; !slices.Equal(got, []string{"fixed"}) {
					t.Errorf("%s: emitted %v, want the current document's [fixed] once", cve, got)
				}
			}
			if hits[unchanged] != 0 {
				t.Errorf("the crawl fetched %s again after the archive read it", unchanged)
			}
			if hits[changed] != 1 {
				t.Errorf("%s fetched %d times, want once", changed, hits[changed])
			}
			if !res.Complete {
				t.Error("a cold start that read every document must report Complete")
			}
			if want := []string{"CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"}; !slices.Equal(res.RefreshedCVEs, want) {
				t.Errorf("RefreshedCVEs: got %v, want %v", res.RefreshedCVEs, want)
			}
		})
	}
}

// TestSync_ColdStartReadsIndexOnlyDocuments: a live document index.txt lists
// that changes.csv does not (Red Hat had 6 in 2026-10) and the archive does
// not hold — here the archive is unreadable and the crawl took over — is
// fetched by its index path and dated by its own release date; the run is
// Complete only if that fetch succeeds.
func TestSync_ColdStartReadsIndexOnlyDocuments(t *testing.T) {
	const archiveName = "csaf_vex_2026-05-23.tar.zst"
	files := func(indexOnly []byte) map[string][]byte {
		f := map[string][]byte{
			"archive_latest.txt":      []byte(archiveName + "\n"),
			archiveName:               []byte("not zstd"),
			"changes.csv":             []byte(`"2099/cve-2099-0001.json","2026-05-25T00:00:00+00:00"` + "\n"),
			"index.txt":               []byte("2005/cve-2005-0473.json\n2099/cve-2099-0001.json\n"),
			"2099/cve-2099-0001.json": csafDoc("CVE-2099-0001", "fixed", "2026-05-25T00:00:00Z"),
		}
		if indexOnly != nil {
			f["2005/cve-2005-0473.json"] = indexOnly
		}
		return f
	}

	t.Run("read", func(t *testing.T) {
		metadataURL, _ := feedServer(t, files(csafDoc("CVE-2005-0473", "fixed", "2019-03-01T00:00:00Z")))
		a, err := New(source.AdapterConfig{Type: Type, ID: "redhat", URL: metadataURL})
		if err != nil {
			t.Fatal(err)
		}
		updated := map[string]time.Time{}
		res, err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
			updated[s.CVE] = s.Updated
			return nil
		})
		if err != nil {
			t.Fatalf("Sync: %v", err)
		}
		if !res.Complete {
			t.Error("a cold start that read every index.txt document must report Complete")
		}
		if want := []string{"CVE-2005-0473", "CVE-2099-0001"}; !slices.Equal(res.RefreshedCVEs, want) {
			t.Errorf("RefreshedCVEs: got %v, want %v", res.RefreshedCVEs, want)
		}
		if want := time.Date(2019, 3, 1, 0, 0, 0, 0, time.UTC); !updated["CVE-2005-0473"].Equal(want) {
			t.Errorf("index-only document dated %v, want its release date %v", updated["CVE-2005-0473"], want)
		}
	})

	t.Run("fetch fails", func(t *testing.T) {
		metadataURL, _ := feedServer(t, files(nil))
		a, err := New(source.AdapterConfig{Type: Type, ID: "redhat", URL: metadataURL})
		if err != nil {
			t.Fatal(err)
		}
		res, err := a.Sync(context.Background(), time.Time{}, func(source.Statement) error { return nil })
		if err != nil {
			t.Fatalf("Sync: %v", err)
		}
		if res.Complete {
			t.Error("a cold start that could not read an index.txt document must not report Complete")
		}
	})
}

// TestSync_NoArchiveFallsBackToCrawl verifies that a feed without
// archive_latest.txt (e.g. SUSE) still works via the changes.csv crawl.
func TestSync_NoArchiveFallsBackToCrawl(t *testing.T) {
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
	// No /vex/archive_latest.txt handler -> 404 -> fall back to crawl.
	mux.HandleFunc("/vex/changes.csv", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `"2024/cve-2024-0217.json","2024-01-05T00:00:00+00:00"`+"\n")
	})
	var docFetched bool
	mux.HandleFunc("/vex/2024/cve-2024-0217.json", func(w http.ResponseWriter, r *http.Request) {
		docFetched = true
		w.Write(fixture)
	})

	a, err := New(source.AdapterConfig{Type: Type, ID: "test", URL: server.URL + "/provider-metadata.json"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	var count int
	if _, err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error { count++; return nil }); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !docFetched {
		t.Error("expected the crawl to fetch the document when no archive is published")
	}
	if count == 0 {
		t.Fatal("expected statements from the crawl, got 0")
	}
}

// TestReleaseDate: an archived document is dated by its own
// current_release_date; one without a readable date falls back.
func TestReleaseDate(t *testing.T) {
	fallback := time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		doc  string
		want time.Time
	}{
		{`{"document":{"tracking":{"current_release_date":"2025-11-21T14:53:29+00:00"}}}`, time.Date(2025, 11, 21, 14, 53, 29, 0, time.UTC)},
		{`{"document":{"tracking":{"current_release_date":"2025-11-21T16:53:29+02:00"}}}`, time.Date(2025, 11, 21, 14, 53, 29, 0, time.UTC)},
		{`{"document":{"tracking":{}}}`, fallback},
		{`{"document":{"tracking":{"current_release_date":"21 Nov 2025"}}}`, fallback},
		{`not json`, fallback},
	}
	for _, c := range cases {
		if got := releaseDate([]byte(c.doc), fallback); !got.Equal(c.want) || got.Location() != time.UTC {
			t.Errorf("releaseDate(%s) = %v, want %v", c.doc, got, c.want)
		}
	}
}
