package ingest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/getreeldev/reel-vex/pkg/db"
	"github.com/getreeldev/reel-vex/pkg/db/dbtest"
	"github.com/getreeldev/reel-vex/pkg/source"
)

// fakeAdapter is a minimal source.Adapter for exercising the orchestrator
// without any network or real feed. emitFn drives what Sync emits; when it
// returns nil, Sync returns res and err (which a test may set together, to
// break the adapter contract on purpose). gotSince records the watermark the
// orchestrator passed in.
type fakeAdapter struct {
	id, vendor, name, format, feedURL string
	emitFn                            func(emit func(source.Statement) error) error
	res                               source.SyncResult
	err                               error
	gotSince                          time.Time
}

func (f *fakeAdapter) ID() string           { return f.id }
func (f *fakeAdapter) Vendor() string       { return f.vendor }
func (f *fakeAdapter) Name() string         { return f.name }
func (f *fakeAdapter) SourceFormat() string { return f.format }

func (f *fakeAdapter) Discover(ctx context.Context) (*source.FeedInfo, error) {
	return &source.FeedInfo{FeedURL: f.feedURL}, nil
}

func (f *fakeAdapter) Sync(ctx context.Context, since time.Time, emit func(source.Statement) error) (source.SyncResult, error) {
	f.gotSince = since
	if err := f.emitFn(emit); err != nil {
		return source.SyncResult{}, err
	}
	return f.res, f.err
}

// TestRun_StoresTimestampsAsUTC is the regression guard for the lexicographic
// `updated` ordering: ingest stores `updated` as a TEXT column compared with
// `>=` (the ?since= filter and the incremental watermark), so every stored
// string must be in UTC or a non-zero offset (e.g. +05:30) would sort wrong
// against UTC's `Z`. If the `.UTC()` calls in emit()/runAdapter are dropped,
// the stored strings keep their source offset and these assertions fail.
func TestRun_StoresTimestampsAsUTC(t *testing.T) {
	store := dbtest.New()

	// Source feed emits in +05:30; the UTC equivalents end in Z.
	ist := time.FixedZone("IST", 5*3600+30*60)
	srcTimes := map[string]time.Time{
		"CVE-2026-0001": time.Date(2026, 6, 1, 10, 0, 0, 0, ist), // -> 2026-06-01T04:30:00Z
		"CVE-2026-0002": time.Date(2026, 6, 2, 9, 0, 0, 0, ist),  // -> 2026-06-02T03:30:00Z (latest)
	}
	fa := &fakeAdapter{
		id: "fake", vendor: "acme", name: "Acme", format: "csaf", feedURL: "https://example/feed",
		emitFn: func(emit func(source.Statement) error) error {
			for cve, ts := range srcTimes {
				if err := emit(source.Statement{
					CVE:       cve,
					ProductID: "pkg:rpm/acme/" + cve,
					BaseID:    "pkg:rpm/acme/" + cve,
					Status:    "fixed",
					Updated:   ts,
				}); err != nil {
					return err
				}
			}
			return nil
		},
	}

	if err := Run(context.Background(), []source.Adapter{fa}, nil, store, Options{}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	got, err := store.QueryStatements(db.QueryFilters{CVEs: []string{"CVE-2026-0001", "CVE-2026-0002"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 stored statements, got %d", len(got))
	}
	for _, s := range got {
		want := srcTimes[s.CVE].UTC().Format(time.RFC3339)
		if s.Updated != want {
			t.Errorf("%s: stored Updated = %q, want UTC %q", s.CVE, s.Updated, want)
		}
		if !strings.HasSuffix(s.Updated, "Z") {
			t.Errorf("%s: stored Updated = %q is not UTC (must end in Z)", s.CVE, s.Updated)
		}
	}

	// The incremental watermark is the latest source time, also forced to UTC.
	wm, err := store.AdapterLastSynced("fake")
	if err != nil {
		t.Fatal(err)
	}
	wantWM := srcTimes["CVE-2026-0002"].UTC().Format(time.RFC3339)
	if wm != wantWM {
		t.Errorf("watermark = %q, want UTC of latest %q", wm, wantWM)
	}
}

// TestRunAdapter_IncrementalSyncRoundTripsWatermark covers the core
// watermark loop the previously-untested package relied on integration tests
// for: a stored watermark is parsed back into the `since` handed to Sync, and a
// cycle that emits nothing preserves the prior watermark rather than clearing it.
func TestRunAdapter_IncrementalSyncRoundTripsWatermark(t *testing.T) {
	store := dbtest.New()
	const prior = "2026-05-01T00:00:00Z"
	if err := store.UpsertAdapterState("fake", "https://example/feed", prior); err != nil {
		t.Fatal(err)
	}

	fa := &fakeAdapter{
		id: "fake", vendor: "acme", name: "Acme", format: "csaf", feedURL: "https://example/feed",
		emitFn: func(emit func(source.Statement) error) error { return nil }, // up to date
	}
	if err := runAdapter(context.Background(), fa, store, Options{}); err != nil {
		t.Fatalf("runAdapter: %v", err)
	}

	want, _ := time.Parse(time.RFC3339, prior)
	if !fa.gotSince.Equal(want) {
		t.Errorf("Sync received since = %v, want stored watermark %v", fa.gotSince, want)
	}
	// Empty incoming watermark must preserve the prior one (no erase on a no-op cycle).
	wm, err := store.AdapterLastSynced("fake")
	if err != nil {
		t.Fatal(err)
	}
	if wm != prior {
		t.Errorf("watermark = %q, want preserved %q", wm, prior)
	}
}

// faultStore wraps the in-memory store with call counters and the failures
// dbtest cannot inject.
type faultStore struct {
	*dbtest.Store
	// failBulkInsertAt fails exactly that BulkInsert call (1-based); 0 never.
	failBulkInsertAt int
	// failFinish makes FinishSweep fail; like the real store it still ends
	// the session.
	failFinish bool

	bulkInserts, starts, records, finishes, withdraws int
}

func newFaultStore() *faultStore { return &faultStore{Store: dbtest.New()} }

func (s *faultStore) BulkInsert(stmts []db.Statement) error {
	s.bulkInserts++
	if s.bulkInserts == s.failBulkInsertAt {
		return errors.New("injected bulk insert failure")
	}
	return s.Store.BulkInsert(stmts)
}

func (s *faultStore) StartSweep(adapterID string) error {
	s.starts++
	return s.Store.StartSweep(adapterID)
}

func (s *faultStore) RecordSeen(adapterID string, keys []db.StatementKey) error {
	s.records++
	return s.Store.RecordSeen(adapterID, keys)
}

func (s *faultStore) FinishSweep(adapterID string, scope db.SweepScope, maxFraction float64) (db.SweepResult, error) {
	s.finishes++
	if s.failFinish {
		if err := s.Store.AbortSweep(adapterID); err != nil {
			return db.SweepResult{}, err
		}
		return db.SweepResult{}, errors.New("injected finish sweep failure")
	}
	return s.Store.FinishSweep(adapterID, scope, maxFraction)
}

func (s *faultStore) Withdraw(adapterID string, liveCVEs []string, maxFraction float64) (db.WithdrawResult, error) {
	s.withdraws++
	return s.Store.Withdraw(adapterID, liveCVEs, maxFraction)
}

// captureLogs routes slog's default logger into a buffer for the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// logLines returns the logged lines whose message is msg.
func logLines(buf *bytes.Buffer, msg string) []string {
	var out []string
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.Contains(l, " msg="+msg+" ") {
			out = append(out, l)
		}
	}
	return out
}

// oneLine asserts exactly one line with message msg, containing every want.
func oneLine(t *testing.T, buf *bytes.Buffer, msg string, want ...string) {
	t.Helper()
	lines := logLines(buf, msg)
	if len(lines) != 1 {
		t.Fatalf("want one %s line, got %d:\n%s", msg, len(lines), buf.String())
	}
	for _, w := range want {
		if !strings.Contains(lines[0], w) {
			t.Errorf("%s line %q lacks %q", msg, lines[0], w)
		}
	}
}

func pid(cve string, n int) string { return fmt.Sprintf("pkg:apk/alpine/p%d-%s", n, cve) }

// st is one emitted statement: not_affected for package n in cve.
func st(cve string, n int) source.Statement {
	return source.Statement{CVE: cve, ProductID: pid(cve, n), BaseID: pid(cve, n), Status: "not_affected"}
}

// seed stores rows as the adapter id would have written them (vendor acme,
// format oval). An empty owner seeds rows nobody owns.
func seed(t *testing.T, s db.Store, owner, cve string, ns ...int) {
	t.Helper()
	var rows []db.Statement
	for _, n := range ns {
		rows = append(rows, db.Statement{Vendor: "acme", CVE: cve, ProductID: pid(cve, n), BaseID: pid(cve, n),
			Status: "not_affected", SourceFormat: "oval", AdapterID: owner})
	}
	if err := s.BulkInsert(rows); err != nil {
		t.Fatal(err)
	}
}

// rowsIn returns the rows stored in cve, keyed "<product_id> <status>".
func rowsIn(t *testing.T, s db.Store, cve string) map[string]bool {
	t.Helper()
	got, err := s.QueryStatements(db.QueryFilters{CVEs: []string{cve}})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, r := range got {
		out[r.ProductID+" "+r.Status] = true
	}
	return out
}

func wantRows(t *testing.T, s db.Store, cve string, ns ...int) {
	t.Helper()
	got := rowsIn(t, s, cve)
	if len(got) != len(ns) {
		t.Errorf("%s: %d rows %v, want packages %v", cve, len(got), got, ns)
	}
	for _, n := range ns {
		if !got[pid(cve, n)+" not_affected"] {
			t.Errorf("%s: package %d gone, want kept (rows %v)", cve, n, got)
		}
	}
}

// emitting returns an emitFn that emits each statement in order and returns
// the first emit error.
func emitting(stmts ...source.Statement) func(func(source.Statement) error) error {
	return func(emit func(source.Statement) error) error {
		for _, s := range stmts {
			if err := emit(s); err != nil {
				return err
			}
		}
		return nil
	}
}

func fake(id string, res source.SyncResult, emitFn func(func(source.Statement) error) error) *fakeAdapter {
	return &fakeAdapter{id: id, vendor: "acme", name: "Acme", format: "oval", feedURL: "https://example/feed", emitFn: emitFn, res: res}
}

func TestSweep_CompleteDeletesUnseenOwnedRows(t *testing.T) {
	logs := captureLogs(t)
	s := dbtest.New()
	seed(t, s, "fake", "CVE-1", 1, 2, 3, 4, 5)
	seed(t, s, "other", "CVE-1", 6)
	seed(t, s, "", "CVE-1", 7)
	fa := fake("fake", source.SyncResult{Complete: true}, emitting(st("CVE-1", 1), st("CVE-1", 2), st("CVE-1", 3), st("CVE-1", 4)))
	if err := runAdapter(context.Background(), fa, s, Options{SweepMaxFraction: 0.2}); err != nil {
		t.Fatal(err)
	}
	wantRows(t, s, "CVE-1", 1, 2, 3, 4, 6, 7)
	oneLine(t, logs, "sweep", "adapter=fake", "scope=all", "seen=4", "owned=5", "deleted=1")
}

func TestSweep_RefreshedCVEsReplaceOnlyThoseDocuments(t *testing.T) {
	logs := captureLogs(t)
	s := dbtest.New()
	seed(t, s, "fake", "CVE-1", 1, 2)
	seed(t, s, "fake", "CVE-2", 1, 2)
	seed(t, s, "fake", "CVE-3", 1)
	// CVE-1 keeps what it emitted; CVE-2 was refreshed with no statements and
	// loses every row; CVE-3 was not refreshed and is untouched.
	fa := fake("fake", source.SyncResult{RefreshedCVEs: []string{"CVE-1", "CVE-2"}}, emitting(st("CVE-1", 1)))
	if err := runAdapter(context.Background(), fa, s, Options{SweepMaxFraction: 0.2}); err != nil {
		t.Fatal(err)
	}
	wantRows(t, s, "CVE-1", 1)
	wantRows(t, s, "CVE-2")
	wantRows(t, s, "CVE-3", 1)
	oneLine(t, logs, "sweep", "scope=cves:2", "seen=1", "owned=4", "deleted=3")
}

func TestSweep_IncompleteSweepsNothingButWithdraws(t *testing.T) {
	logs := captureLogs(t)
	s := newFaultStore()
	seed(t, s, "fake", "CVE-1", 1, 2)
	seed(t, s, "fake", "CVE-2", 1)
	fa := fake("fake", source.SyncResult{LiveCVEs: []string{"CVE-1"}}, emitting(st("CVE-1", 1)))
	if err := runAdapter(context.Background(), fa, s, Options{SweepMaxFraction: 0.5}); err != nil {
		t.Fatal(err)
	}
	wantRows(t, s, "CVE-1", 1, 2) // unseen package 2 stays: nothing proves it gone
	wantRows(t, s, "CVE-2")       // withdrawn: absent from the manifest
	if s.finishes != 0 {
		t.Errorf("FinishSweep ran %d times on an incomplete run", s.finishes)
	}
	oneLine(t, logs, "sweep", "scope=cves:0", "seen=1", "skipped=incomplete")
	oneLine(t, logs, "withdraw", "live=1", "held_cves=2", "withdrawn_cves=1", "deleted=1")
}

// full returns n statements in CVE-BIG, enough to fill whole batches.
func full(n int) []source.Statement {
	out := make([]source.Statement, n)
	for i := range out {
		out[i] = st("CVE-BIG", i)
	}
	return out
}

func TestSweep_SyncErrorRemovesNothing(t *testing.T) {
	logs := captureLogs(t)
	s := newFaultStore()
	seed(t, s, "fake", "CVE-BIG", 999999) // owned, never emitted
	seed(t, s, "fake", "CVE-GONE", 1)     // absent from the manifest
	// Complete together with an error breaks the adapter contract on purpose:
	// the orchestrator's own check is what must hold.
	fa := fake("fake", source.SyncResult{Complete: true, LiveCVEs: []string{"CVE-BIG"}}, emitting(full(5000)...))
	fa.err = errors.New("feed broke")
	if err := runAdapter(context.Background(), fa, s, Options{SweepMaxFraction: 0.5}); err == nil {
		t.Fatal("runAdapter succeeded on a Sync error")
	}
	if s.records == 0 {
		t.Fatal("no batch was recorded; the test proves nothing")
	}
	if got := rowsIn(t, s, "CVE-BIG"); !got[pid("CVE-BIG", 999999)+" not_affected"] {
		t.Error("a Sync error swept an unseen row")
	}
	wantRows(t, s, "CVE-GONE", 1)
	if s.finishes != 0 || s.withdraws != 0 {
		t.Errorf("FinishSweep %d, Withdraw %d after a Sync error; want neither", s.finishes, s.withdraws)
	}
	oneLine(t, logs, "sweep", "scope=cves:0", "seen=5000", `skipped="sync error"`)
	if n := len(logLines(logs, "withdraw")); n != 0 {
		t.Errorf("%d withdraw lines after a Sync error", n)
	}
}

func TestSweep_FlushErrorRemovesNothing(t *testing.T) {
	logs := captureLogs(t)
	s := newFaultStore()
	s.failBulkInsertAt = 2 // the second full batch; the final flush retries it
	seed(t, s, "fake", "CVE-BIG", 999999)
	s.bulkInserts = 0
	// The adapter swallows the failing emit, stops before the statement for
	// the seeded row, and claims Complete.
	stmts := append(full(10000), st("CVE-BIG", 999999))
	fa := fake("fake", source.SyncResult{Complete: true, LiveCVEs: []string{"CVE-BIG"}}, func(emit func(source.Statement) error) error {
		for _, x := range stmts {
			if err := emit(x); err != nil {
				return nil
			}
		}
		return nil
	})
	if err := runAdapter(context.Background(), fa, s, Options{SweepMaxFraction: 0.5}); err != nil {
		t.Fatalf("runAdapter: %v", err)
	}
	if s.bulkInserts != 3 {
		t.Fatalf("BulkInsert ran %d times, want 3 (ok, injected failure, final retry)", s.bulkInserts)
	}
	if got := rowsIn(t, s, "CVE-BIG"); !got[pid("CVE-BIG", 999999)+" not_affected"] {
		t.Error("a run with a failed flush swept an unseen row")
	}
	if s.finishes != 0 || s.withdraws != 0 {
		t.Errorf("FinishSweep %d, Withdraw %d after a flush error; want neither", s.finishes, s.withdraws)
	}
	oneLine(t, logs, "sweep", "scope=all", `skipped="flush error"`)
}

func TestSweep_LimitRemovesNothing(t *testing.T) {
	for _, swallow := range []bool{false, true} {
		t.Run(fmt.Sprintf("swallow=%v", swallow), func(t *testing.T) {
			logs := captureLogs(t)
			s := newFaultStore()
			seed(t, s, "fake", "CVE-1", 1, 2, 3)
			seed(t, s, "fake", "CVE-GONE", 1)
			fa := fake("fake", source.SyncResult{Complete: true, LiveCVEs: []string{"CVE-1"}}, func(emit func(source.Statement) error) error {
				for _, x := range []source.Statement{st("CVE-1", 1), st("CVE-1", 2)} {
					if err := emit(x); err != nil && !swallow {
						return err
					}
				}
				return nil
			})
			if err := runAdapter(context.Background(), fa, s, Options{Limit: 1, SweepMaxFraction: 1}); err != nil {
				t.Fatal(err)
			}
			wantRows(t, s, "CVE-1", 1, 2, 3)
			wantRows(t, s, "CVE-GONE", 1)
			if s.finishes != 0 || s.withdraws != 0 {
				t.Errorf("FinishSweep %d, Withdraw %d on a Limit run; want neither", s.finishes, s.withdraws)
			}
			oneLine(t, logs, "sweep", "scope=cves:0", "seen=1", "skipped=limit")
		})
	}
}

func TestSweep_GuardRefuses(t *testing.T) {
	logs := captureLogs(t)
	s := dbtest.New()
	seed(t, s, "fake", "CVE-1", 1, 2, 3, 4, 5)
	fa := fake("fake", source.SyncResult{Complete: true}, emitting(st("CVE-1", 1), st("CVE-1", 2)))
	if err := runAdapter(context.Background(), fa, s, Options{SweepMaxFraction: 0.2}); err != nil {
		t.Fatal(err)
	}
	wantRows(t, s, "CVE-1", 1, 2, 3, 4, 5)
	oneLine(t, logs, "sweep", "level=WARN", "scope=all", "seen=2", "owned=5", "deleted=0", "refused=")
}

func TestSweep_DisabledRecordsAndRemovesNothing(t *testing.T) {
	logs := captureLogs(t)
	s := newFaultStore()
	seed(t, s, "fake", "CVE-1", 1, 2)
	seed(t, s, "fake", "CVE-GONE", 1)
	fa := fake("fake", source.SyncResult{Complete: true, LiveCVEs: []string{"CVE-1"}}, emitting(st("CVE-1", 1)))
	if err := runAdapter(context.Background(), fa, s, Options{}); err != nil {
		t.Fatal(err)
	}
	wantRows(t, s, "CVE-1", 1, 2)
	wantRows(t, s, "CVE-GONE", 1)
	if s.starts+s.records+s.finishes+s.withdraws != 0 {
		t.Errorf("disabled removal called StartSweep %d, RecordSeen %d, FinishSweep %d, Withdraw %d",
			s.starts, s.records, s.finishes, s.withdraws)
	}
	oneLine(t, logs, "sweep", "scope=all", "seen=0", "skipped=disabled")
	if n := len(logLines(logs, "withdraw")); n != 0 {
		t.Errorf("%d withdraw lines with removal disabled", n)
	}
}

// TestSweep_AdaptersSharingVendorAndFormat: ownership is the adapter, not the
// (vendor, source_format) pair two adapters can share.
func TestSweep_AdaptersSharingVendorAndFormat(t *testing.T) {
	s := dbtest.New()
	a1 := fake("a1", source.SyncResult{Complete: true, LiveCVEs: []string{"CVE-1"}}, emitting(st("CVE-1", 1)))
	a2 := fake("a2", source.SyncResult{Complete: true, LiveCVEs: []string{"CVE-2"}}, emitting(st("CVE-2", 1)))
	for i := 0; i < 2; i++ {
		if err := Run(context.Background(), []source.Adapter{a1, a2}, nil, s, Options{SweepMaxFraction: 1}); err != nil {
			t.Fatal(err)
		}
	}
	wantRows(t, s, "CVE-1", 1)
	wantRows(t, s, "CVE-2", 1)
}

func TestSweep_FinishSweepFailureStillRecordsWatermark(t *testing.T) {
	logs := captureLogs(t)
	s := newFaultStore()
	s.failFinish = true
	seed(t, s, "fake", "CVE-1", 1, 2)
	x := st("CVE-1", 1)
	x.Updated = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	fa := fake("fake", source.SyncResult{Complete: true}, emitting(x))
	if err := runAdapter(context.Background(), fa, s, Options{SweepMaxFraction: 1}); err != nil {
		t.Fatalf("a FinishSweep error failed the adapter: %v", err)
	}
	wm, err := s.AdapterLastSynced("fake")
	if err != nil || wm == "" {
		t.Errorf("watermark = %q, %v; want it recorded", wm, err)
	}
	if err := s.RecordSeen("fake", nil); err == nil {
		t.Error("the session outlived the failed FinishSweep")
	}
	oneLine(t, logs, "sweep", "level=ERROR", "error=")
}

// TestSweep_RemovesRowsItsOwnSyncWrote proves emit sets AdapterID: rows only
// the orchestrator wrote are swept when a later sync drops them — including a
// row whose verdict changed, which is a new row.
func TestSweep_RemovesRowsItsOwnSyncWrote(t *testing.T) {
	s := dbtest.New()
	first := fake("fake", source.SyncResult{Complete: true}, emitting(st("CVE-1", 1), st("CVE-1", 2), st("CVE-1", 3), st("CVE-1", 4)))
	if err := runAdapter(context.Background(), first, s, Options{SweepMaxFraction: 0.5}); err != nil {
		t.Fatal(err)
	}
	fixed := st("CVE-1", 3)
	fixed.Status = "fixed"
	second := fake("fake", source.SyncResult{Complete: true}, emitting(st("CVE-1", 1), st("CVE-1", 2), fixed))
	if err := runAdapter(context.Background(), second, s, Options{SweepMaxFraction: 0.5}); err != nil {
		t.Fatal(err)
	}
	got := rowsIn(t, s, "CVE-1")
	want := map[string]bool{pid("CVE-1", 1) + " not_affected": true, pid("CVE-1", 2) + " not_affected": true, pid("CVE-1", 3) + " fixed": true}
	if len(got) != len(want) {
		t.Fatalf("rows = %v, want %v", got, want)
	}
	for k := range want {
		if !got[k] {
			t.Errorf("rows = %v, want %v", got, want)
		}
	}
}

func TestWithdraw_OnlyWithAManifest(t *testing.T) {
	for _, live := range [][]string{nil, {"CVE-1"}} {
		t.Run(fmt.Sprintf("live=%v", live), func(t *testing.T) {
			logs := captureLogs(t)
			s := newFaultStore()
			seed(t, s, "fake", "CVE-1", 1)
			seed(t, s, "fake", "CVE-GONE", 1)
			fa := fake("fake", source.SyncResult{LiveCVEs: live}, emitting(st("CVE-1", 1)))
			if err := runAdapter(context.Background(), fa, s, Options{SweepMaxFraction: 0.5}); err != nil {
				t.Fatal(err)
			}
			if live == nil {
				if s.withdraws != 0 || len(logLines(logs, "withdraw")) != 0 {
					t.Errorf("Withdraw ran with no manifest")
				}
				wantRows(t, s, "CVE-GONE", 1)
				return
			}
			if s.withdraws != 1 {
				t.Errorf("Withdraw ran %d times, want 1", s.withdraws)
			}
			wantRows(t, s, "CVE-GONE")
			oneLine(t, logs, "withdraw", "adapter=fake", "withdrawn_cves=1", "deleted=1")
		})
	}
}

func TestRun_ResetsLeftoverSessions(t *testing.T) {
	s := dbtest.New()
	if err := s.StartSweep("ghost"); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), nil, nil, s, Options{SweepMaxFraction: 0.2}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordSeen("ghost", nil); err == nil {
		t.Error("a leftover session survived Run")
	}
}

func TestSweep_PanicOutOfSyncAborts(t *testing.T) {
	logs := captureLogs(t)
	s := dbtest.New()
	seed(t, s, "fake", "CVE-1", 1, 2)
	fa := fake("fake", source.SyncResult{Complete: true}, func(emit func(source.Statement) error) error {
		if err := emit(st("CVE-1", 1)); err != nil {
			return err
		}
		panic("adapter bug")
	})
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the panic did not propagate")
			}
		}()
		runAdapter(context.Background(), fa, s, Options{SweepMaxFraction: 1})
	}()
	if err := s.RecordSeen("fake", nil); err == nil {
		t.Error("the session outlived the panic")
	}
	wantRows(t, s, "CVE-1", 1, 2)
	oneLine(t, logs, "sweep", "scope=cves:0", "skipped=aborted")
}

// TestExactLists_ChurnAcrossCompleteSyncs: an exact-list feed emits one row per
// verdict carrying its whole list, every complete sync. Across two syncs a
// version dropped from a list updates the row in place, a version whose verdict
// changed moves between rows, and a verdict whose list emptied is not emitted
// and the whole-feed sweep removes it.
func TestExactLists_ChurnAcrossCompleteSyncs(t *testing.T) {
	logs := captureLogs(t)
	s := dbtest.New()
	row := func(product, status string, versions ...string) source.Statement {
		return source.Statement{CVE: "CVE-1", ProductID: "pkg:deb/ubuntu/" + product + "?arch=amd64&distro=ubuntu-22.04",
			BaseID: "pkg:deb/ubuntu/" + product + "?distro=ubuntu-22.04", Versions: versions, VersionKind: "exact",
			Status: status, Updated: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)}
	}
	sync := func(stmts ...source.Statement) {
		t.Helper()
		if err := runAdapter(context.Background(), fake("ubuntu-vex", source.SyncResult{Complete: true}, emitting(stmts...)), s,
			Options{SweepMaxFraction: 0.5}); err != nil {
			t.Fatal(err)
		}
	}
	stored := func() []string {
		t.Helper()
		got, err := s.QueryStatements(db.QueryFilters{CVEs: []string{"CVE-1"}})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range got {
			out = append(out, fmt.Sprintf("%s %s %v", r.ProductID[len("pkg:deb/ubuntu/"):strings.IndexByte(r.ProductID, '?')], r.Status, r.Versions))
		}
		return out
	}

	sync(row("openssl", "fixed", "1.10", "1.11"), row("glibc", "affected", "2.35-1"), row("glibc", "fixed", "2.35-2"),
		row("curl", "affected", "7.81"))
	want := []string{"curl affected [7.81]", "glibc affected [2.35-1]", "glibc fixed [2.35-2]", "openssl fixed [1.10 1.11]"}
	if got := stored(); !slices.Equal(got, want) {
		t.Fatalf("after the first sync: %v, want %v", got, want)
	}

	// openssl 1.10 is dropped; glibc 2.35-1 is now fixed, so the affected list
	// is empty and that verdict is not emitted at all. Only that row is
	// deleted: the other two changed in place.
	logs.Reset()
	sync(row("openssl", "fixed", "1.11"), row("glibc", "fixed", "2.35-1", "2.35-2"), row("curl", "affected", "7.81"))
	want = []string{"curl affected [7.81]", "glibc fixed [2.35-1 2.35-2]", "openssl fixed [1.11]"}
	if got := stored(); !slices.Equal(got, want) {
		t.Fatalf("after the second sync: %v, want %v", got, want)
	}
	oneLine(t, logs, "sweep", "scope=all", "seen=3", "owned=4", "deleted=1")
}

// TestRun_OneAtATime: a Run beside one inside its sync returns
// db.ErrIngestRunning having touched nothing — no ResetSweeps, which would end
// the first run's session mid-sync, and no adapter — and the first run's sweep
// then works from its own seen keys.
func TestRun_OneAtATime(t *testing.T) {
	logs := captureLogs(t)
	s := dbtest.New()
	seed(t, s, "first", "CVE-1", 1, 2, 3, 4, 5)
	entered, release := make(chan struct{}), make(chan struct{})
	first := fake("first", source.SyncResult{Complete: true}, func(emit func(source.Statement) error) error {
		close(entered)
		<-release
		return emitting(st("CVE-1", 1), st("CVE-1", 2), st("CVE-1", 3), st("CVE-1", 4))(emit)
	})
	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), []source.Adapter{first}, nil, s, Options{SweepMaxFraction: 0.5})
	}()
	<-entered
	secondCalled := false
	second := fake("second", source.SyncResult{Complete: true}, func(emit func(source.Statement) error) error {
		secondCalled = true
		return nil
	})
	err := Run(context.Background(), []source.Adapter{second}, nil, s, Options{SweepMaxFraction: 0.5})
	close(release)
	if !errors.Is(err, db.ErrIngestRunning) {
		t.Errorf("a Run beside a running one = %v, want ErrIngestRunning", err)
	}
	if secondCalled {
		t.Error("the refused Run synced its adapter")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	wantRows(t, s, "CVE-1", 1, 2, 3, 4)
	oneLine(t, logs, "sweep", "adapter=first", "seen=4", "owned=5", "deleted=1")
	if err := Run(context.Background(), []source.Adapter{second}, nil, s, Options{SweepMaxFraction: 0.5}); err != nil {
		t.Fatalf("a Run after the first finished: %v", err)
	}
}

// TestSweep_SharedKeyStaysWithTheAdapterStillEmittingIt: Alpine main and
// community both emit a package's key while it moves between them. When main
// stops emitting it, main's sweep must leave it, because community still
// publishes it — the row belongs to whoever wrote it last.
func TestSweep_SharedKeyStaysWithTheAdapterStillEmittingIt(t *testing.T) {
	s := dbtest.New()
	sync := func(id string, stmts ...source.Statement) {
		t.Helper()
		if err := runAdapter(context.Background(), fake(id, source.SyncResult{Complete: true}, emitting(stmts...)), s,
			Options{SweepMaxFraction: 1}); err != nil {
			t.Fatal(err)
		}
	}
	sync("main", st("CVE-1", 1), st("CVE-1", 2))
	sync("community", st("CVE-1", 2), st("CVE-1", 3))
	sync("main", st("CVE-1", 1))
	wantRows(t, s, "CVE-1", 1, 2, 3)
	// Once community drops it too, community's sweep removes it.
	sync("community", st("CVE-1", 3))
	wantRows(t, s, "CVE-1", 1, 3)
}

// TestSweep_ForceLiftsTheGuardForNamedAdaptersOnly: a refused whole-feed sweep
// stays refused run after run, since its stale rows stay in the denominator;
// SweepForce lets one adapter's through, says so on its line, and leaves the
// guard on every other adapter and the nothing-seen refusal in place.
func TestSweep_ForceLiftsTheGuardForNamedAdaptersOnly(t *testing.T) {
	logs := captureLogs(t)
	s := newFaultStore()
	seed(t, s, "forced", "CVE-1", 1, 2, 3, 4, 5)
	seed(t, s, "guarded", "CVE-2", 1, 2, 3, 4, 5)
	seed(t, s, "forced", "CVE-GONE", 1)
	seed(t, s, "forced", "CVE-3", 1)
	seed(t, s, "silent", "CVE-4", 1)
	opts := Options{SweepMaxFraction: 0.2, SweepForce: []string{"forced", "silent"}}
	forced := fake("forced", source.SyncResult{Complete: true, LiveCVEs: []string{"CVE-1"}}, emitting(st("CVE-1", 1)))
	guarded := fake("guarded", source.SyncResult{Complete: true}, emitting(st("CVE-2", 1)))
	silent := fake("silent", source.SyncResult{Complete: true}, emitting())
	if err := Run(context.Background(), []source.Adapter{forced, guarded, silent}, nil, s, opts); err != nil {
		t.Fatal(err)
	}
	wantRows(t, s, "CVE-1", 1)
	wantRows(t, s, "CVE-2", 1, 2, 3, 4, 5)
	wantRows(t, s, "CVE-GONE")
	wantRows(t, s, "CVE-3")
	wantRows(t, s, "CVE-4", 1)
	var forcedLine, guardedLine, silentLine string
	for _, l := range logLines(logs, "sweep") {
		switch {
		case strings.Contains(l, "adapter=forced "):
			forcedLine = l
		case strings.Contains(l, "adapter=guarded "):
			guardedLine = l
		case strings.Contains(l, "adapter=silent "):
			silentLine = l
		}
	}
	if !strings.Contains(forcedLine, "forced=true") || !strings.Contains(forcedLine, "deleted=6") {
		t.Errorf("forced sweep line = %q; want forced=true deleted=6", forcedLine)
	}
	if strings.Contains(guardedLine, "forced") || !strings.Contains(guardedLine, "refused=") {
		t.Errorf("guarded sweep line = %q; want a refusal, not forced", guardedLine)
	}
	if !strings.Contains(silentLine, `refused="nothing seen"`) {
		t.Errorf("silent sweep line = %q; want the nothing-seen refusal", silentLine)
	}
	oneLine(t, logs, "withdraw", "adapter=forced", "forced=true")
}

// TestWithdraw_RefreshedDocumentsAreLive: a document this run fetched and
// stored is live even when the vendor's index.txt, which lags changes.csv,
// does not list it yet; withdrawing it would delete what the run just wrote.
func TestWithdraw_RefreshedDocumentsAreLive(t *testing.T) {
	logs := captureLogs(t)
	s := dbtest.New()
	seed(t, s, "fake", "CVE-1", 1)
	seed(t, s, "fake", "CVE-GONE", 1)
	fa := fake("fake", source.SyncResult{RefreshedCVEs: []string{"CVE-NEW"}, LiveCVEs: []string{"CVE-1"}}, emitting(st("CVE-NEW", 1)))
	if err := runAdapter(context.Background(), fa, s, Options{SweepMaxFraction: 1}); err != nil {
		t.Fatal(err)
	}
	wantRows(t, s, "CVE-NEW", 1)
	wantRows(t, s, "CVE-1", 1)
	wantRows(t, s, "CVE-GONE")
	oneLine(t, logs, "withdraw", "live=2", "held_cves=3", "withdrawn_cves=1", "deleted=1")

	// An empty manifest is still refused, whatever the run refreshed.
	logs.Reset()
	fa = fake("fake", source.SyncResult{RefreshedCVEs: []string{"CVE-NEW"}, LiveCVEs: []string{}}, emitting(st("CVE-NEW", 1)))
	if err := runAdapter(context.Background(), fa, s, Options{SweepMaxFraction: 1}); err != nil {
		t.Fatal(err)
	}
	wantRows(t, s, "CVE-1", 1)
	oneLine(t, logs, "withdraw", `refused="empty manifest"`)
}
