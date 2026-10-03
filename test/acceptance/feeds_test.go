//go:build integration

package acceptance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Last-Modified of every fixture file: day 1, and day 2 for the files the
// day-2 overlay changes. Feeds whose rows carry no date of their own (OVAL,
// secdb) are dated by it.
var (
	day1Time = time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	day2Time = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
)

// day2Pinned are day-2 files served with the day-1 Last-Modified although
// their content changed, so the adapter must treat the feed as unchanged.
var day2Pinned = map[string]bool{
	"security-metadata.canonical.com/oval/com.ubuntu.noble.usn.oval.xml.bz2": true,
}

// day2Gone are files that no longer exist on day 2 (404).
var day2Gone = map[string]bool{
	"security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-94282.json": true,
}

// feedServer serves testdata/feeds/<day>/<host>/<path> at /<host>/<path>, so
// every fixture sits at a path shaped like its vendor URL. On day 2 a file in
// feeds/day2 replaces its day-1 copy. Provider metadata and mirror lists name
// other vendor URLs; their "https://" is rewritten to this server.
type feedServer struct {
	srv  *httptest.Server
	root string
	mu   sync.Mutex
	day  string
}

func newFeedServer(root string) (*feedServer, error) {
	if _, err := os.Stat(filepath.Join(root, "day1")); err != nil {
		return nil, err
	}
	f := &feedServer{root: root, day: "day1"}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	return f, nil
}

func (f *feedServer) URL() string { return f.srv.URL }
func (f *feedServer) Close()      { f.srv.Close() }

func (f *feedServer) SetDay(day string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.day = day
}

func (f *feedServer) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	day := f.day
	f.mu.Unlock()

	rel := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if rel == "" || strings.Contains(rel, "..") {
		http.NotFound(w, r)
		return
	}
	modTime := day1Time
	file := filepath.Join(f.root, "day1", filepath.FromSlash(rel))
	if day == "day2" {
		if day2Gone[rel] {
			http.NotFound(w, r)
			return
		}
		if p := filepath.Join(f.root, "day2", filepath.FromSlash(rel)); exists(p) {
			file = p
			if !day2Pinned[rel] {
				modTime = day2Time
			}
		}
	}
	b, err := os.ReadFile(file)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if base := path.Base(rel); base == "provider-metadata.json" || base == "mirror.list" {
		b = bytes.ReplaceAll(b, []byte("https://"), []byte(f.srv.URL+"/"))
	}
	sum := sha256.Sum256(b)
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:8])+`"`)
	http.ServeContent(w, r, path.Base(rel), modTime, bytes.NewReader(b))
}

func exists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
