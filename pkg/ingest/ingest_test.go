package ingest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/getreeldev/reel-vex/pkg/db"
	"github.com/getreeldev/reel-vex/pkg/db/dbtest"
	"github.com/getreeldev/reel-vex/pkg/source"
)

// fakeAdapter is a minimal source.Adapter for exercising the orchestrator
// without any network or real feed. emitFn drives what Sync emits; gotSince
// records the watermark the orchestrator passed in.
type fakeAdapter struct {
	id, vendor, name, format, feedURL string
	emitFn                            func(emit func(source.Statement) error) error
	gotSince                          time.Time
}

func (f *fakeAdapter) ID() string           { return f.id }
func (f *fakeAdapter) Vendor() string       { return f.vendor }
func (f *fakeAdapter) Name() string         { return f.name }
func (f *fakeAdapter) SourceFormat() string { return f.format }

func (f *fakeAdapter) Discover(ctx context.Context) (*source.FeedInfo, error) {
	return &source.FeedInfo{FeedURL: f.feedURL}, nil
}

func (f *fakeAdapter) Sync(ctx context.Context, since time.Time, emit func(source.Statement) error) error {
	f.gotSince = since
	return f.emitFn(emit)
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
