package ranchervex

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/getreeldev/reel-vex/pkg/source"
)

// liveFeedURL is the snapshot Rancher VEX Hub's vex-repository.json names: the
// GitHub archive tarball of the repository's main branch.
const liveFeedURL = "https://github.com/rancher/vexhub/archive/refs/heads/main.tar.gz"

// TestSmoke_LiveFeed hits the real Rancher VEX hub and checks the adapter's
// invariants against live data: it ingests end-to-end and Complete, every
// emitted row is CVE-named and scoped with a PURL identifier, and the volume
// is in the expected ballpark. It catches upstream restructuring that a
// committed fixture can't (see TestAdapter_RealSample for the offline
// counterpart).
//
// Opt-in only — it downloads the live ~8 MB snapshot, so it is skipped unless
// REEL_VEX_SMOKE is set and is never part of the default `go test ./...`. Run:
//
//	REEL_VEX_SMOKE=1 go test -run TestSmoke -v ./pkg/source/ranchervex/
func TestSmoke_LiveFeed(t *testing.T) {
	if os.Getenv("REEL_VEX_SMOKE") == "" {
		t.Skip("set REEL_VEX_SMOKE=1 to run the live-feed smoke test (downloads the live repository snapshot)")
	}

	a, err := New(source.AdapterConfig{Type: Type, ID: "rancher-vex", URL: liveFeedURL})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	feed, err := a.Discover(ctx)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if feed.FeedURL == "" {
		t.Error("expected FeedURL to be set")
	}

	var emitted, violations int
	scopes := make(map[string]struct{})
	res, err := a.Sync(ctx, time.Time{}, func(s source.Statement) error {
		emitted++
		if !strings.HasPrefix(s.CVE, "CVE-") || s.Scope == "" || !strings.HasPrefix(s.ProductID, "pkg:") {
			if violations < 5 { // cap the noise; the count below is the real signal
				t.Errorf("invariant violation: %+v", s)
			}
			violations++
		}
		scopes[s.Scope] = struct{}{}
		return nil
	})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	t.Logf("live feed: emitted=%d violations=%d distinct_scopes=%d complete=%v", emitted, violations, len(scopes), res.Complete)

	if !res.Complete {
		t.Error("the live snapshot should be Complete: every file index.json lists present and parsed")
	}
	// Sanity floor: the snapshot emits ~323K CVE-named rows from ~1,250 files
	// today. A collapse far below that signals an upstream restructuring worth
	// a human look.
	if emitted < 10000 {
		t.Errorf("emitted=%d is suspiciously low; the feed may have restructured", emitted)
	}
}
