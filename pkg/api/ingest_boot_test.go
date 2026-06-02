package api

import (
	"testing"
	"time"
)

func TestShouldIngestOnBoot(t *testing.T) {
	const interval = 4 * time.Hour
	now := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name       string
		lastIngest time.Time
		want       bool
	}{
		{"never ingested (zero)", time.Time{}, true},
		{"fresh: 1h ago", now.Add(-1 * time.Hour), false},
		{"fresh: just under interval", now.Add(-interval + time.Minute), false},
		{"stale: exactly one interval", now.Add(-interval), true},
		{"stale: well past interval", now.Add(-9 * time.Hour), true},
		{"clock skew: last in the future", now.Add(time.Hour), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shouldIngestOnBoot(c.lastIngest, interval, now); got != c.want {
				t.Errorf("shouldIngestOnBoot(%v) = %v, want %v", c.lastIngest, got, c.want)
			}
		})
	}
}
