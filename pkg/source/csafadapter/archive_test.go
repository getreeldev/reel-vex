package csafadapter

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
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
// with the archive date, and uses that date as the floor for the changes.csv
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
	err = a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
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
	if want := time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC); !updated.Equal(want) {
		t.Errorf("archive statement Updated: got %v, want %v", updated, want)
	}
	if docFetched {
		t.Error("delta should not re-fetch a pre-archive-date doc — full crawl was not avoided")
	}
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
	if err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error { count++; return nil }); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !docFetched {
		t.Error("expected the crawl to fetch the document when no archive is published")
	}
	if count == 0 {
		t.Fatal("expected statements from the crawl, got 0")
	}
}
