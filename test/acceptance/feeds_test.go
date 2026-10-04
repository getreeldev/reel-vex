//go:build integration

package acceptance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
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

// day404 are the paths each day's ingest may ask for and get a 404: SUSE
// publishes no bulk archive (as live), and day2Gone. Any other 404 is a
// fixture an adapter looked for and did not find, which fails the ingest.
var day404 = map[string]map[string]bool{
	"day1": {"ftp.suse.com/pub/projects/security/csaf-vex/archive_latest.txt": true},
	"day2": day2Gone,
}

// feedServer serves testdata/feeds/<day>/<host>/<path> at /<host>/<path>, so
// every fixture sits at a path shaped like its vendor URL. On day 2 a file in
// feeds/day2 replaces its day-1 copy. Provider metadata and mirror lists name
// other vendor URLs; their "https://" is rewritten to this server. It records
// every path asked for since the last SetDay, and every 404.
type feedServer struct {
	srv       *httptest.Server
	root      string
	mu        sync.Mutex
	day       string
	requested map[string]int
	notFound  []string
}

func newFeedServer(root string) (*feedServer, error) {
	if _, err := os.Stat(filepath.Join(root, "day1")); err != nil {
		return nil, err
	}
	f := &feedServer{root: root, day: "day1", requested: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	return f, nil
}

func (f *feedServer) URL() string { return f.srv.URL }
func (f *feedServer) Close()      { f.srv.Close() }

// SetDay switches the fixtures served and starts a new request record.
func (f *feedServer) SetDay(day string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.day = day
	f.requested = map[string]int{}
	f.notFound = nil
}

// check returns every way the requests since SetDay differ from what the
// day's fixtures imply: a 404 not in day404, and a file of feeds/<day> no
// adapter asked for (a fixture the suite believes is read, and is not).
func (f *feedServer) check() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var bad []string
	for _, rel := range f.notFound {
		if !day404[f.day][rel] {
			bad = append(bad, "fixture server: 404 for /"+rel)
		}
	}
	dayRoot := filepath.Join(f.root, f.day)
	err := filepath.WalkDir(dayRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dayRoot, p)
		if err != nil {
			return err
		}
		if rel = filepath.ToSlash(rel); f.requested[rel] == 0 {
			bad = append(bad, "fixture server: "+f.day+"/"+rel+" was never requested")
		}
		return nil
	})
	if err != nil {
		bad = append(bad, "fixture server: walk "+dayRoot+": "+err.Error())
	}
	return bad
}

func (f *feedServer) serve(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	f.mu.Lock()
	day := f.day
	f.requested[rel]++
	f.mu.Unlock()
	notFound := func() {
		f.mu.Lock()
		f.notFound = append(f.notFound, rel)
		f.mu.Unlock()
		http.NotFound(w, r)
	}

	if rel == "" || strings.Contains(rel, "..") {
		notFound()
		return
	}
	modTime := day1Time
	file := filepath.Join(f.root, "day1", filepath.FromSlash(rel))
	if day == "day2" {
		if day2Gone[rel] {
			notFound()
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
		notFound()
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
