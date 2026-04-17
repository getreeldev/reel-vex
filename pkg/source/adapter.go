// Package source defines the Adapter interface that separates per-vendor
// feed fetching from the shared ingest orchestrator. Each adapter represents
// one vendor feed in one format (CSAF, OVAL, ...); the orchestrator drives
// them uniformly via Discover + Sync.
package source

import (
	"context"
	"time"
)

// Adapter is a source of VEX statements. The orchestrator first calls
// Discover to resolve the feed URL and confirm the adapter can reach it,
// then calls Sync to stream statements updated after the last-synced
// watermark. Statements emitted through the callback are tagged with the
// adapter's ID and SourceFormat when they land in the database.
type Adapter interface {
	// ID is the vendor identifier used as the key in the statements table
	// (e.g. "redhat", "suse"). Stable across adapter types — when a vendor
	// has both CSAF and OVAL adapters they share one ID and the resulting
	// statements are distinguished only by SourceFormat.
	ID() string

	// Name is the vendor's human-readable name (e.g. "Red Hat"). Adapters
	// may override an empty config-provided name with one discovered from
	// the upstream feed.
	Name() string

	// SourceFormat is the upstream feed format this adapter parses:
	// "csaf", "oval", ... Written to every emitted statement so callers can
	// filter or attribute by origin.
	SourceFormat() string

	// Discover resolves the feed URL and confirms the adapter can reach it.
	// Returns the canonical feed URL for display and storage on the vendor
	// row. Called once per ingest cycle before Sync.
	Discover(ctx context.Context) (*FeedInfo, error)

	// Sync streams statements updated after `since`. The adapter calls
	// `emit` once per statement; returning an error from emit stops the
	// sync and propagates that error back. Transient per-document errors
	// (network, parse) should be logged by the adapter and skipped rather
	// than returned — partial coverage is more useful than aborting.
	Sync(ctx context.Context, since time.Time, emit func(Statement) error) error
}

// FeedInfo is the post-discovery metadata about an adapter's feed.
type FeedInfo struct {
	// FeedURL is the canonical URL where the adapter fetches advisories.
	// Shown to users and stored as the vendor's feed_url.
	FeedURL string
}

// Statement is an adapter's per-item output. The adapter fills in the
// identifier and VEX fields; the orchestrator composes the final db.Statement
// by adding Vendor (from adapter.ID), SourceFormat (from adapter.SourceFormat),
// and the RFC3339 string encoding of Updated.
type Statement struct {
	CVE           string
	ProductID     string
	BaseID        string
	Version       string
	IDType        string
	Status        string
	Justification string
	Updated       time.Time
}
