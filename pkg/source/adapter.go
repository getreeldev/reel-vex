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
// adapter's Vendor and SourceFormat when they land in the database.
type Adapter interface {
	// ID is the adapter instance identifier, unique across all configured
	// adapters. Used as the key for this adapter's watermark entry in
	// adapter_state, so two adapters that share a vendor (e.g. an OpenVEX
	// and an OVAL adapter both scanning Ubuntu) need distinct IDs like
	// "ubuntu-vex" and "ubuntu-oval-noble".
	ID() string

	// Vendor is the vendor identifier written onto every statement this
	// adapter emits. Multiple adapters can share a vendor — a vendor with
	// both CSAF and OVAL adapters produces statements under one vendor
	// string; their provenance is distinguished by SourceFormat.
	Vendor() string

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
	// than returned — partial coverage is more useful than aborting — but a
	// run that skipped anything on error must report itself incomplete and
	// leave the skipped document out of RefreshedCVEs (see SyncResult). On
	// error Sync returns a zero SyncResult.
	Sync(ctx context.Context, since time.Time, emit func(Statement) error) (SyncResult, error)
}

// SyncResult reports what one successful Sync covered, so the orchestrator
// can tell which stored rows the vendor no longer publishes.
type SyncResult struct {
	// Complete is true when this call emitted the adapter's entire current
	// set: every statement the vendor publishes now went through emit, and
	// nothing was skipped on error (failed fetch, malformed entry, failed
	// extract). Skips by design — non-CVE names, missing or invalid
	// subcomponent identifiers, packages with no name — do not make a run
	// incomplete. A run that found the feed unchanged and fetched nothing
	// ("up to date, skipping GET") is not complete: it emitted nothing.
	Complete bool

	// RefreshedCVEs lists, for per-CVE document feeds (CSAF), the CVE ids of
	// the documents fetched and fully parsed this call, including documents
	// that yielded no statements. Each listed document's statements were all
	// emitted, so its stored rows that were not are no longer published. A
	// document that failed to fetch or parse is left out. Nil for whole-file
	// feeds.
	RefreshedCVEs []string

	// LiveCVEs is the vendor's manifest of live documents as CVE ids, when
	// the adapter read one this call (CSAF's index.txt). Nil when the
	// adapter has no manifest or could not read it — never an empty slice
	// standing in for "unknown".
	LiveCVEs []string
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
	// Scope, when non-empty, restricts the statement to a single product
	// context — an OpenVEX product @id such as a container image or Go module
	// (see pkg/csaf.NormalizeScope). The orchestrator stores it on the row and
	// the query layer only surfaces a scoped statement when the caller supplies
	// a matching scope, so a product-scoped not_affected never suppresses
	// findings for an unrelated product. Empty for package-level feeds (CSAF,
	// OVAL, Canonical OpenVEX); set by the Rancher VEX adapter.
	Scope string
}
