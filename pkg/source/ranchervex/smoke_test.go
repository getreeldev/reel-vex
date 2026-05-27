package ranchervex

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/getreeldev/reel-vex/pkg/source"
)

// liveFeedURL is the production Rancher VEX hub repo index (non-LFS); the
// adapter walks it to the per-package documents.
const liveFeedURL = "https://raw.githubusercontent.com/rancher/vexhub/refs/heads/main/index.json"

// TestSmoke_LiveFeed hits the real Rancher VEX hub and checks the adapter's
// invariants against live data: it ingests end-to-end, every emitted row is
// CVE-named and scoped with a PURL identifier, and the volume is in the
// expected ballpark. It catches upstream restructuring that a committed
// fixture can't (see TestAdapter_RealSample for the offline counterpart).
//
// Opt-in only — it makes a real ~80 MB network fetch, so it is skipped unless
// REEL_VEX_SMOKE is set and is never part of the default `go test ./...`. Run:
//
//	REEL_VEX_SMOKE=1 go test -run TestSmoke -v ./pkg/source/ranchervex/
func TestSmoke_LiveFeed(t *testing.T) {
	if os.Getenv("REEL_VEX_SMOKE") == "" {
		t.Skip("set REEL_VEX_SMOKE=1 to run the live-feed smoke test (walks the live index + hundreds of per-package fetches)")
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
	if err := a.Sync(ctx, time.Time{}, func(s source.Statement) error {
		emitted++
		if !strings.HasPrefix(s.CVE, "CVE-") || s.Scope == "" || !strings.HasPrefix(s.ProductID, "pkg:") {
			if violations < 5 { // cap the noise; the count below is the real signal
				t.Errorf("invariant violation: %+v", s)
			}
			violations++
		}
		scopes[s.Scope] = struct{}{}
		return nil
	}); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	t.Logf("live feed: emitted=%d violations=%d distinct_scopes=%d", emitted, violations, len(scopes))

	// Sanity floor: the feed emits ~139k CVE-named rows today. A collapse far
	// below that signals an upstream restructuring worth a human look.
	if emitted < 10000 {
		t.Errorf("emitted=%d is suspiciously low; the feed may have restructured", emitted)
	}
}
