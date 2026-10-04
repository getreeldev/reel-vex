package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/getreeldev/reel-vex/pkg/db/dbtest"
	"github.com/getreeldev/reel-vex/pkg/source"
)

// TestRunAdapter_RetryFromHoldsTheWatermark: a sync that failed to read a
// document dated before the newest one it emitted leaves the watermark a
// second before the failed one, so the next incremental sync fetches it
// again; a RetryFrom after everything emitted moves nothing.
func TestRunAdapter_RetryFromHoldsTheWatermark(t *testing.T) {
	newest := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	s := st("CVE-2026-0001", 1)
	s.Updated = newest
	for _, c := range []struct {
		name      string
		retryFrom time.Time
		want      string
	}{
		{"no failure", time.Time{}, "2026-10-04T12:00:00Z"},
		{"failure before the newest", time.Date(2026, 10, 3, 8, 30, 0, 0, time.UTC), "2026-10-03T08:29:59Z"},
		{"failure at the newest", newest, "2026-10-04T11:59:59Z"},
		{"failure after the newest", newest.Add(time.Hour), "2026-10-04T12:00:00Z"},
	} {
		t.Run(c.name, func(t *testing.T) {
			store := dbtest.New()
			fa := fake("fake", source.SyncResult{RetryFrom: c.retryFrom}, emitting(s))
			if err := runAdapter(context.Background(), fa, store, Options{}); err != nil {
				t.Fatalf("runAdapter: %v", err)
			}
			wm, err := store.AdapterLastSynced("fake")
			if err != nil {
				t.Fatal(err)
			}
			if wm != c.want {
				t.Errorf("watermark = %q, want %q", wm, c.want)
			}
		})
	}
}
