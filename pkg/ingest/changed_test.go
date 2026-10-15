package ingest

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/ulikunitz/xz"

	"github.com/getreeldev/reel-vex/pkg/db"
	"github.com/getreeldev/reel-vex/pkg/db/dbtest"
	"github.com/getreeldev/reel-vex/pkg/openvex"
	"github.com/getreeldev/reel-vex/pkg/source"
	"github.com/getreeldev/reel-vex/pkg/source/ubuntuvex"
)

// changedFake is a fakeAdapter that is also a ChangedDocsAdapter: it records
// which entry point the orchestrator called and the fingerprints it was given.
type changedFake struct {
	*fakeAdapter
	calledChanged bool
	gotLast       map[string]string
}

func (f *changedFake) SyncChanged(ctx context.Context, since time.Time, last map[string]string, emit func(source.Statement) error) (source.SyncResult, error) {
	f.calledChanged = true
	f.gotLast = last
	return f.fakeAdapter.Sync(ctx, since, emit)
}

func changed(res source.SyncResult, emitFn func(func(source.Statement) error) error) *changedFake {
	return &changedFake{fakeAdapter: fake("fake", res, emitFn)}
}

func storedFingerprints(t *testing.T, s db.Store) map[string]string {
	t.Helper()
	return storedFingerprintsOf(t, s, "fake")
}

func storedFingerprintsOf(t *testing.T, s db.Store, id string) map[string]string {
	t.Helper()
	fps, err := s.DocumentFingerprints(id)
	if err != nil {
		t.Fatal(err)
	}
	return fps
}

func TestChangedDocs_ReplacesWhatChangedAndStoresFingerprints(t *testing.T) {
	logs := captureLogs(t)
	s := dbtest.New()
	seed(t, s, "fake", "CVE-1", 1, 2)
	seed(t, s, "fake", "CVE-2", 1, 2)
	seed(t, s, "fake", "CVE-GONE", 1)
	if err := s.SaveDocumentFingerprints("fake", map[string]string{"CVE-1": "a", "CVE-2": "b", "CVE-GONE": "c"}); err != nil {
		t.Fatal(err)
	}
	// CVE-1 unchanged (left out), CVE-2 re-read with package 2 gone, CVE-GONE
	// no longer in the feed.
	next := map[string]string{"CVE-1": "a", "CVE-2": "b2"}
	fa := changed(source.SyncResult{RefreshedCVEs: []string{"CVE-2"}, LiveCVEs: []string{"CVE-1", "CVE-2"}, Fingerprints: next},
		emitting(st("CVE-2", 1)))
	if err := runAdapter(context.Background(), fa, s, Options{SweepMaxFraction: 0.5}); err != nil {
		t.Fatal(err)
	}
	if !fa.calledChanged {
		t.Fatal("the orchestrator called Sync, not SyncChanged, with removal enabled")
	}
	if want := map[string]string{"CVE-1": "a", "CVE-2": "b", "CVE-GONE": "c"}; !maps.Equal(fa.gotLast, want) {
		t.Errorf("SyncChanged got last = %v, want %v", fa.gotLast, want)
	}
	wantRows(t, s, "CVE-1", 1, 2)
	wantRows(t, s, "CVE-2", 1)
	wantRows(t, s, "CVE-GONE")
	if got := storedFingerprints(t, s); !maps.Equal(got, next) {
		t.Errorf("stored fingerprints = %v, want %v", got, next)
	}
	oneLine(t, logs, "sweep", "scope=cves:1", "deleted=1")
	oneLine(t, logs, "withdraw", "withdrawn_cves=1")
}

// TestChangedDocs_RemovalDisabledReadsEverything: without removal a re-read
// document's dropped rows could not be deleted, so nothing may be left out,
// and the rows it wrote are not what the stored fingerprints describe.
func TestChangedDocs_RemovalDisabledReadsEverything(t *testing.T) {
	s := dbtest.New()
	if err := s.SaveDocumentFingerprints("fake", map[string]string{"CVE-1": "a"}); err != nil {
		t.Fatal(err)
	}
	fa := changed(source.SyncResult{Complete: true, Fingerprints: map[string]string{"CVE-1": "z"}}, emitting(st("CVE-1", 1)))
	if err := runAdapter(context.Background(), fa, s, Options{}); err != nil {
		t.Fatal(err)
	}
	if fa.calledChanged {
		t.Error("SyncChanged called with removal disabled")
	}
	if got := storedFingerprints(t, s); len(got) != 0 {
		t.Errorf("stored fingerprints = %v; a run that wrote rows it could not replace must clear them", got)
	}
}

// TestChangedDocs_FingerprintsClearedWhenRemovalFails: a document whose rows
// were not replaced must be read again next run, and so must one reverted to
// the bytes its stored fingerprint names — whether the sweep failed, was
// refused, or the run was cut short. The watermark stays where it was, so
// the next run fetches the feed again.
func TestChangedDocs_FingerprintsClearedWhenRemovalFails(t *testing.T) {
	old := map[string]string{"CVE-1": "a"}
	next := map[string]string{"CVE-1": "b"}
	modified := time.Date(2026, 10, 15, 6, 12, 54, 0, time.UTC)
	cases := []struct {
		name  string
		store func() db.Store
		res   source.SyncResult
		opts  Options
	}{
		{"sweep error", func() db.Store { s := newFaultStore(); s.failFinish = true; return s },
			source.SyncResult{RefreshedCVEs: []string{"CVE-1"}, LiveCVEs: []string{"CVE-1"}, Fingerprints: next, Watermark: modified}, Options{SweepMaxFraction: 0.5}},
		{"guard refusal", func() db.Store { return dbtest.New() },
			source.SyncResult{Complete: true, Fingerprints: next, Watermark: modified}, Options{SweepMaxFraction: 0.2}},
		{"limit", func() db.Store { return dbtest.New() },
			source.SyncResult{RefreshedCVEs: []string{"CVE-1"}, LiveCVEs: []string{"CVE-1"}, Fingerprints: next, Watermark: modified}, Options{SweepMaxFraction: 0.5, Limit: 1}},
		{"withdrawal refused", func() db.Store { return dbtest.New() },
			source.SyncResult{RefreshedCVEs: []string{"CVE-1"}, LiveCVEs: []string{"CVE-1"}, Fingerprints: next, Watermark: modified}, Options{SweepMaxFraction: 0.5}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.store()
			seed(t, s, "fake", "CVE-1", 1, 2, 3, 4, 5)
			// Held CVEs the manifest drops: three of four, over any guard.
			seed(t, s, "fake", "CVE-2", 1)
			seed(t, s, "fake", "CVE-3", 1)
			seed(t, s, "fake", "CVE-4", 1)
			if err := s.SaveDocumentFingerprints("fake", old); err != nil {
				t.Fatal(err)
			}
			if err := s.UpsertAdapterState("fake", "https://example/feed", "2026-10-14T06:21:54Z"); err != nil {
				t.Fatal(err)
			}
			fa := changed(tc.res, emitting(st("CVE-1", 1), st("CVE-1", 2)))
			if err := runAdapter(context.Background(), fa, s, tc.opts); err != nil {
				t.Fatal(err)
			}
			got := storedFingerprints(t, s)
			if tc.name == "withdrawal refused" {
				// The documents read were replaced; only the withdrawal waits.
				if !maps.Equal(got, next) {
					t.Errorf("stored fingerprints = %v, want this run's %v", got, next)
				}
			} else if len(got) != 0 {
				t.Errorf("stored fingerprints = %v, want none", got)
			}
			if wm, _ := s.AdapterLastSynced("fake"); wm != "2026-10-14T06:21:54Z" {
				t.Errorf("watermark %q moved; want it held so the next run fetches again", wm)
			}
		})
	}
}

// uvDoc is a one-statement Canonical OpenVEX document naming products.
func uvDoc(t *testing.T, cve, status string, products ...string) []byte {
	t.Helper()
	var comps []openvex.Component
	for _, p := range products {
		comps = append(comps, openvex.Component{ID: p})
	}
	b, err := json.Marshal(openvex.Document{Context: openvex.Context, Author: "Canonical Ltd.", Timestamp: "2026-10-01T00:00:00Z", Version: 1,
		Statements: []openvex.Statement{{Vulnerability: openvex.Vulnerability{Name: cve}, Products: comps, Status: status, Timestamp: "2026-10-01T00:00:00Z"}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// uvTarball is Canonical's tarball shape: vex/cve/<year>/<CVE>.json per CVE.
func uvTarball(t *testing.T, docs map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	xw, err := xz.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(xw)
	for _, cve := range slices.Sorted(maps.Keys(docs)) {
		body := docs[cve]
		if err := tw.WriteHeader(&tar.Header{Name: "vex/cve/2026/" + cve + ".json", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := xw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// allRows is every stored row of cves, keyed by what identifies it and what
// it says. It fails on none, so two empty stores never compare equal.
func allRows(t *testing.T, s db.Store, cves ...string) map[string]bool {
	t.Helper()
	got, err := s.QueryStatements(db.QueryFilters{CVEs: cves})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatalf("no rows stored for %v", cves)
	}
	out := map[string]bool{}
	for _, r := range got {
		out[r.CVE+" "+r.ProductID+" "+r.BaseID+" "+r.IDType+" "+r.VersionKind+" "+r.Status+" "+r.Justification+" "+r.AdapterID+" "+string(mustJSONOf(t, r.Versions))] = true
	}
	return out
}

func mustJSONOf(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestChangedDocs_UbuntuPublishMatchesAFullRead drives the real ubuntu-vex
// adapter through two publishes and checks that the second, which leaves out
// what did not change, stores exactly what a cold read of it stores.
func TestChangedDocs_UbuntuPublishMatchesAFullRead(t *testing.T) {
	const (
		curl   = "pkg:deb/ubuntu/curl@8.5.0-2ubuntu10?arch=amd64&distro=ubuntu/noble"
		curlJ  = "pkg:deb/ubuntu/curl@7.81.0-1ubuntu1?arch=amd64&distro=ubuntu/jammy"
		kernel = "pkg:deb/ubuntu/linux-headers-6.8.0-45@6.8.0-45.45?arch=amd64&distro=ubuntu/noble"
		kNext  = "pkg:deb/ubuntu/linux-headers-6.8.0-47@6.8.0-47.47?arch=amd64&distro=ubuntu/noble"
	)
	day1 := map[string][]byte{
		"CVE-2026-1": uvDoc(t, "CVE-2026-1", "affected", curl, curlJ),
		"CVE-2026-2": uvDoc(t, "CVE-2026-2", "affected", kernel),
		"CVE-2026-3": uvDoc(t, "CVE-2026-3", "fixed", curl),
	}
	day2 := map[string][]byte{
		"CVE-2026-1": day1["CVE-2026-1"],                                  // unchanged
		"CVE-2026-2": uvDoc(t, "CVE-2026-2", "not_affected", kNext),       // kernel respun, verdict changed
		"CVE-2026-4": uvDoc(t, "CVE-2026-4", "under_investigation", curl), // new; CVE-2026-3 is gone
	}
	var payload []byte
	var modified time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", modified.Format(http.TimeFormat))
		if r.Method == http.MethodGet {
			w.Write(payload)
		}
	}))
	defer srv.Close()
	ad, err := ubuntuvex.New(source.AdapterConfig{Type: ubuntuvex.Type, ID: "ubuntu-vex", URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{SweepMaxFraction: 0.5}

	s := dbtest.New()
	payload, modified = uvTarball(t, day1), time.Date(2026, 10, 14, 6, 21, 54, 0, time.UTC)
	if err := runAdapter(context.Background(), ad, s, opts); err != nil {
		t.Fatal(err)
	}
	logs := captureLogs(t)
	payload, modified = uvTarball(t, day2), modified.Add(24*time.Hour)
	if err := runAdapter(context.Background(), ad, s, opts); err != nil {
		t.Fatal(err)
	}
	oneLine(t, logs, `"ubuntu-vex sync complete"`, "entries=3", "unchanged=1", "refreshed=2")
	oneLine(t, logs, `"adapter done"`, "complete=false", "refreshed=2", "live=3")

	// The watermark is the publish's Last-Modified, not the newest date among
	// the few documents re-read, so an unchanged feed is not fetched again.
	if wm, _ := s.AdapterLastSynced("ubuntu-vex"); wm != modified.Format(time.RFC3339) {
		t.Errorf("watermark %q, want the publish's Last-Modified %s", wm, modified.Format(time.RFC3339))
	}
	if err := runAdapter(context.Background(), ad, s, opts); err != nil {
		t.Fatal(err)
	}
	oneLine(t, logs, `"ubuntu-vex up to date, skipping GET"`)

	cold := dbtest.New()
	if err := runAdapter(context.Background(), ad, cold, opts); err != nil {
		t.Fatal(err)
	}
	all := []string{"CVE-2026-1", "CVE-2026-2", "CVE-2026-3", "CVE-2026-4"}
	got, want := allRows(t, s, all...), allRows(t, cold, all...)
	if !maps.Equal(got, want) {
		t.Errorf("after the changed-documents run:\n%v\na cold read of the same publish:\n%v", got, want)
	}
	fps, _ := s.DocumentFingerprints("ubuntu-vex")
	coldFps, _ := cold.DocumentFingerprints("ubuntu-vex")
	if !maps.Equal(fps, coldFps) || len(fps) != 3 {
		t.Errorf("fingerprints %v, cold read's %v", fps, coldFps)
	}
}

// TestChangedDocs_UbuntuRetriesAFailedSweep: a publish whose removal failed is
// fetched again on the next run, not found up to date, and that run leaves the
// store as a cold read of the publish would.
func TestChangedDocs_UbuntuRetriesAFailedSweep(t *testing.T) {
	const curl = "pkg:deb/ubuntu/curl@8.5.0-2ubuntu10?arch=amd64&distro=ubuntu/noble"
	day1 := map[string][]byte{
		"CVE-2026-1": uvDoc(t, "CVE-2026-1", "affected", curl),
		"CVE-2026-2": uvDoc(t, "CVE-2026-2", "affected", curl),
	}
	day2 := map[string][]byte{
		"CVE-2026-1": day1["CVE-2026-1"],
		"CVE-2026-2": uvDoc(t, "CVE-2026-2", "fixed", curl),
	}
	var payload []byte
	modified := time.Date(2026, 10, 14, 6, 21, 54, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", modified.Format(http.TimeFormat))
		if r.Method == http.MethodGet {
			w.Write(payload)
		}
	}))
	defer srv.Close()
	ad, err := ubuntuvex.New(source.AdapterConfig{Type: ubuntuvex.Type, ID: "ubuntu-vex", URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{SweepMaxFraction: 0.5}
	s := newFaultStore()
	payload = uvTarball(t, day1)
	if err := runAdapter(context.Background(), ad, s, opts); err != nil {
		t.Fatal(err)
	}
	day1Mark := modified.Format(time.RFC3339)

	payload, modified = uvTarball(t, day2), modified.Add(24*time.Hour)
	s.failFinish = true
	if err := runAdapter(context.Background(), ad, s, opts); err != nil {
		t.Fatal(err)
	}
	if wm, _ := s.AdapterLastSynced("ubuntu-vex"); wm != day1Mark {
		t.Errorf("watermark %q after a failed sweep, want it held at %s", wm, day1Mark)
	}
	if got := storedFingerprintsOf(t, s, "ubuntu-vex"); len(got) != 0 {
		t.Errorf("fingerprints %v after a failed sweep, want none", got)
	}

	s.failFinish = false
	logs := captureLogs(t)
	if err := runAdapter(context.Background(), ad, s, opts); err != nil {
		t.Fatal(err)
	}
	if n := len(logLines(logs, `"ubuntu-vex up to date, skipping GET"`)); n != 0 {
		t.Fatal("the retry found the feed up to date and removed nothing")
	}
	oneLine(t, logs, "sweep", "scope=all", "deleted=1")
	cold := dbtest.New()
	if err := runAdapter(context.Background(), ad, cold, opts); err != nil {
		t.Fatal(err)
	}
	if got, want := allRows(t, s, "CVE-2026-1", "CVE-2026-2"), allRows(t, cold, "CVE-2026-1", "CVE-2026-2"); !maps.Equal(got, want) {
		t.Errorf("after the retry:\n%v\na cold read:\n%v", got, want)
	}
}

// saveFailStore fails SaveDocumentFingerprints: every call when failAll, and
// a non-empty set (a save, not a clear) when failSave.
type saveFailStore struct {
	*dbtest.Store
	failSave, failAll bool
}

func (s *saveFailStore) SaveDocumentFingerprints(adapterID string, fps map[string]string) error {
	if s.failAll || (s.failSave && len(fps) > 0) {
		return errors.New("injected fingerprint save failure")
	}
	return s.Store.SaveDocumentFingerprints(adapterID, fps)
}

// TestChangedDocs_UbuntuRevertAfterAFailedSaveIsRead: the stored fingerprints
// are cleared before a run changes any row, so a run that could not store its
// own leaves none rather than the previous run's — and a document later
// reverted to the bytes an old fingerprint named is read, not left out.
func TestChangedDocs_UbuntuRevertAfterAFailedSaveIsRead(t *testing.T) {
	const (
		curl = "pkg:deb/ubuntu/curl@8.5.0-2ubuntu10?arch=amd64&distro=ubuntu/noble"
		wget = "pkg:deb/ubuntu/wget@1.21.4-1ubuntu4?arch=amd64&distro=ubuntu/noble"
	)
	day1 := map[string][]byte{
		"CVE-2026-1": uvDoc(t, "CVE-2026-1", "affected", curl),
		"CVE-2026-2": uvDoc(t, "CVE-2026-2", "affected", curl),
	}
	day2 := map[string][]byte{
		"CVE-2026-1": uvDoc(t, "CVE-2026-1", "affected", wget),
		"CVE-2026-2": day1["CVE-2026-2"],
	}
	var payload []byte
	modified := time.Date(2026, 10, 14, 6, 21, 54, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", modified.Format(http.TimeFormat))
		if r.Method == http.MethodGet {
			w.Write(payload)
		}
	}))
	defer srv.Close()
	ad, err := ubuntuvex.New(source.AdapterConfig{Type: ubuntuvex.Type, ID: "ubuntu-vex", URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{SweepMaxFraction: 0.5}
	s := &saveFailStore{Store: dbtest.New()}
	for i, day := range []map[string][]byte{day1, day2, day1} {
		payload, modified = uvTarball(t, day), modified.Add(24*time.Hour)
		s.failSave = i == 1
		if err := runAdapter(context.Background(), ad, s, opts); err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			if got := storedFingerprintsOf(t, s, "ubuntu-vex"); len(got) != 0 {
				t.Errorf("fingerprints %v after a run that could not store its own, want none", got)
			}
		}
	}
	cold := dbtest.New()
	if err := runAdapter(context.Background(), ad, cold, opts); err != nil {
		t.Fatal(err)
	}
	all := []string{"CVE-2026-1", "CVE-2026-2"}
	if got, want := allRows(t, s, all...), allRows(t, cold, all...); !maps.Equal(got, want) {
		t.Errorf("after the revert:\n%v\na cold read:\n%v", got, want)
	}

	// Fingerprints that cannot be cleared stop the run before it writes.
	s.failAll = true
	payload, modified = uvTarball(t, day2), modified.Add(24*time.Hour)
	if err := runAdapter(context.Background(), ad, s, opts); err == nil {
		t.Error("a run whose fingerprints could not be cleared wrote rows and succeeded")
	}
	if got, want := allRows(t, s, all...), allRows(t, cold, all...); !maps.Equal(got, want) {
		t.Errorf("rows changed although the fingerprints could not be cleared:\n%v", got)
	}
}
