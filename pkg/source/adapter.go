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

// ChangedDocsAdapter is an Adapter whose feed is one file of per-CVE
// documents with no list of what changed (Canonical's OpenVEX tarball), which
// can leave out the documents that are byte-for-byte what its last run read.
// The orchestrator calls SyncChanged instead of Sync when it can replace a
// re-read document's rows; with a nil last it is Sync.
type ChangedDocsAdapter interface {
	Adapter
	// SyncChanged is Sync, given the fingerprints SyncResult.Fingerprints held
	// after the last run the orchestrator stored. A document whose
	// fingerprint is in last unchanged emits nothing; every other document is
	// emitted whole and listed in RefreshedCVEs. A run that left anything out
	// as unchanged is not Complete, and lists in LiveCVEs every CVE the feed
	// holds, so a document gone from the feed is withdrawn.
	SyncChanged(ctx context.Context, since time.Time, last map[string]string, emit func(Statement) error) (SyncResult, error)
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

	// RefreshedCVEs lists, for per-CVE document feeds (CSAF, and a
	// ChangedDocsAdapter's changed documents), the CVE ids of the documents
	// fetched and fully parsed this call, including documents that yielded no
	// statements. Each listed document's statements were all emitted, so its
	// stored rows that were not are no longer published. A document that
	// failed to fetch or parse is left out. Nil for whole-file feeds.
	RefreshedCVEs []string

	// LiveCVEs is the vendor's manifest of live documents as CVE ids, when
	// the adapter read one this call (CSAF's index.txt; the CVEs of a
	// ChangedDocsAdapter's whole feed). Nil when the
	// adapter has no manifest or could not read it — never an empty slice
	// standing in for "unknown".
	LiveCVEs []string

	// RetryFrom, when non-zero, is the feed timestamp (CSAF changes.csv) of
	// the earliest document this call failed to read and wants read again.
	// The orchestrator keeps the watermark before it, so the next incremental
	// sync fetches that document — and every one after it — again.
	RetryFrom time.Time

	// Watermark, when non-zero, is the watermark this call reached, recorded
	// in place of the newest statement date it emitted. A ChangedDocsAdapter
	// sets it to the feed's Last-Modified: a run that emits only the
	// documents that changed has no reason to have emitted the feed's newest
	// date, and a watermark that moved back would make the next run fetch a
	// feed that has not changed. The orchestrator records it only when the
	// run's removal finished (or removal is disabled); otherwise the
	// watermark stays put and the next run fetches the feed again.
	Watermark time.Time

	// Fingerprints, from a ChangedDocsAdapter that read its feed this call,
	// maps each document it read whole — emitted or left out as unchanged —
	// to a fingerprint of its content. A document that failed to read has
	// none, so the next run reads it again. The orchestrator stores it once
	// this run's rows are written and replaced, and hands it back as the next
	// SyncChanged's last; a run that wrote rows it did not replace clears the
	// stored set instead. Nil otherwise.
	Fingerprints map[string]string
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
	// Versions, when non-empty, replaces Version: every version the vendor
	// stated for this verdict, read as VersionKind says ('' legacy, 'exact',
	// 'boundary'; see db.Statement). The orchestrator stores Version as a
	// one-element list when Versions is empty. Stream is the vendor product
	// stream a boundary holds within (see db.Statement); empty for every
	// adapter today.
	Versions    []string
	VersionKind string
	Stream      string
	// Scope, when non-empty, restricts the statement to a single product
	// context — an OpenVEX product @id such as a container image or Go module
	// (see pkg/csaf.NormalizeScope). The orchestrator stores it on the row and
	// the query layer only surfaces a scoped statement when the caller supplies
	// a matching scope, so a product-scoped not_affected never suppresses
	// findings for an unrelated product. Empty for package-level feeds (CSAF,
	// OVAL, Canonical OpenVEX); set by the Rancher VEX adapter.
	Scope string
}
