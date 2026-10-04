package db

import (
	"errors"
	"slices"
)

// This file holds the backend-agnostic data types shared by every db.Store
// implementation and its consumers. The concrete store lives in a backend
// subpackage (pkg/db/postgres); pkg/db itself carries only types + the Store
// interface (see store.go), so it pulls in no database driver.

// ErrStatsWarming is returned by Stats when the cache is cold and another
// caller is already computing it. The aggregate scans take minutes on a
// prod-size table; a request that waited for them would hold its connection
// until the proxy gave up. Callers should surface "try again shortly" instead.
var ErrStatsWarming = errors.New("stats cache warming")

// Statement is a VEX assertion stored in the database.
type Statement struct {
	Vendor        string
	CVE           string
	ProductID     string
	BaseID        string
	IDType        string
	Status        string
	Justification string
	Updated       string
	SourceFormat  string // "csaf", "oval", ... — upstream feed format
	// Versions are the versions the vendor stated for this verdict, sorted and
	// de-duplicated at the store boundary (see NormalizeVersions). A row whose
	// VersionKind is '' was emitted with one version per statement and holds
	// zero or one.
	Versions []string
	// VersionKind says how Versions are read: '' (legacy, not yet converted),
	// 'exact' (VersionKindExact: the queried version must be in the list) or
	// 'boundary' (the versions are fixed-in boundaries).
	VersionKind string
	// Stream is the vendor product stream a boundary holds within (CSAF's
	// relates_to product). Part of the primary key; empty for every feed until
	// one records it. Not returned by QueryStatements.
	Stream string
	// Scope restricts a statement to one product context (an OpenVEX product
	// @id — e.g. a container image). Empty for every package-level feed; set
	// only for subcomponent-scoped sources (Rancher VEX). Part of the primary
	// key from schema v4 so the same package+CVE can carry different verdicts
	// under different products without colliding. Gated at query time —
	// QueryStatements only returns scoped rows when QueryFilters.Scopes names
	// a match.
	Scope string
	// AdapterID is the adapter that last inserted or changed the row (an
	// unchanged re-insert keeps the owner). Never part of the primary key, and
	// never returned by QueryStatements: it exists so a sweep or a withdrawal
	// can delete only the rows one adapter is responsible for. Empty is stored
	// as NULL, and a NULL-owned row is never swept.
	AdapterID string
	// Notes is transient conversion provenance (e.g. "converted_from=cyclonedx-vex;
	// original_justification=...; fidelity=lossy") for user-uploaded VEX that was
	// normalised on the way in. Never a DB column — empty for every stored row,
	// set only on in-memory user rows and appended to status_notes by the encoder.
	Notes string
}

// VersionKindExact marks a row whose Versions are the exact builds the vendor
// listed (Ubuntu OpenVEX, Rancher): a versioned query matches only a listed
// version, and the row is rendered once per version.
const VersionKindExact = "exact"

// NormalizeVersions returns vs sorted lexically, de-duplicated and without
// empty elements, or nil when nothing is left. Every store applies it to a
// row's Versions on write, so a list that differs only in order or repeats
// never reads as a change.
func NormalizeVersions(vs []string) []string {
	out := slices.DeleteFunc(slices.Clone(vs), func(v string) bool { return v == "" })
	if len(out) == 0 {
		return nil
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// StatementKey identifies a statement within one adapter's rows. Vendor and
// source_format are fixed per adapter, so (cve, product_id, scope, stream,
// status, justification) is the rest of the primary key: a verdict is part of
// a row's identity, so a changed verdict is a new row and the old one is swept.
type StatementKey struct{ CVE, ProductID, Scope, Stream, Status, Justification string }

// SweepScope says which of an adapter's rows a sweep may delete.
type SweepScope struct {
	// All sweeps the whole adapter (after a complete sync).
	All bool
	// CVEs, when All is false, restricts the sweep to these CVEs (the documents
	// an incremental sync refreshed). An empty list sweeps nothing.
	CVEs []string
}

// SweepResult reports a FinishSweep. Seen counts the keys recorded (duplicates
// included); Owned is the rows the adapter owned within the scope before the
// delete; Deleted is the rows removed, or on a guard refusal the rows that
// would have been. Refused means nothing was deleted, and Reason says why.
type SweepResult struct {
	Seen, Owned, Deleted int64
	Refused              bool
	Reason               string
}

// WithdrawResult reports a Withdraw. Live is the distinct CVEs in the vendor's
// manifest, HeldCVEs the distinct CVEs the adapter owns, WithdrawnCVEs the
// held CVEs absent from the manifest, and Deleted the rows removed. Refused
// means nothing was deleted, and Reason says why.
type WithdrawResult struct {
	Live, HeldCVEs, WithdrawnCVEs, Deleted int64
	Refused                                bool
	Reason                                 string
}

// Stats holds database coverage statistics.
type Stats struct {
	Vendors     int    `json:"vendors"`
	CVEs        int    `json:"cves"`
	Statements  int    `json:"statements"`
	Aliases     int    `json:"aliases"`
	LastUpdated string `json:"last_updated,omitempty"`
}

// QueryFilters specifies the WHERE-clause inputs for QueryStatements.
//
// At least one of CVEs or ProductBaseIDs must be non-empty; if both are empty
// the query returns no rows (it would otherwise be an unbounded full-table
// scan). This admits two shapes: CVE-scoped (the classic path) and broad mode
// (product-scoped, no CVE filter — used when a caller wants every vendor
// opinion touching an image's components for `trivy --vex`). Every other field
// is optional. An empty slice (or empty Since) means "no filter on this
// dimension" — that dimension contributes no clause to the query.
//
// Within a non-empty slice, IN semantics. Across populated dimensions, AND
// semantics. So:
//
//	QueryFilters{
//	    CVEs:    []string{"CVE-X", "CVE-Y"},
//	    Vendors: []string{"redhat", "suse"},
//	    Statuses:[]string{"not_affected"},
//	}
//
// reads as: cve IN (CVE-X, CVE-Y) AND vendor IN (redhat, suse) AND
// status IN (not_affected).
//
// ProductBaseIDs callers should pass already-normalized base IDs (PURLs
// without @version and most qualifiers; CPEs as-is). Higher-level handler
// code is expected to run user-supplied PURLs through the resolver before
// passing them here.
//
// Since is an RFC3339 timestamp; rows whose `updated` is lexicographically
// greater than or equal to it are returned. RFC3339 string ordering
// matches chronological ordering, so no parsing is required.
//
// Limit caps the number of rows returned (0 = no cap); Offset skips that many
// rows for pagination. Results are ordered deterministically (base_id, cve,
// product_id, source_format, vendor, scope, status, justification) so a
// paged/limited slice is stable across calls and an emitted VEX document is
// byte-stable when the data hasn't changed. The columns after source_format
// matter because a verdict is part of a row's key: one product_id can hold
// several rows (an affected and a fixed list, one verdict per scope), and
// without them two such rows could swap places between pages. stream is the
// one key column left out: it is not in the covering index, and it is empty
// for every feed today.
type QueryFilters struct {
	CVEs           []string
	ProductBaseIDs []string
	Vendors        []string
	SourceFormats  []string
	Statuses       []string
	Justifications []string
	Since          string
	// Scopes authorises product-scoped statements. Empty (the default) returns
	// only unscoped rows — every package-level feed — so a product-scoped
	// not_affected (Rancher VEX) is withheld unless the caller names the
	// product/image it is scanning. When set, a row matches if it is unscoped
	// OR its scope is in the list. Callers pass already-normalised scopes (see
	// pkg/csaf.NormalizeScope).
	Scopes []string
	// ArchAllow narrows matching to a set of CPU architectures. Empty (the
	// default) means arch-blind matching — the historical behaviour, and the
	// right default because the feeds disagree about whether to qualify at all.
	// When set, a row matches if its product_id carries no arch qualifier, or
	// an architecture-independent one (see csaf.ArchIndependent), or one named
	// here.
	//
	// The backends apply this as a cheap superset filter only; the exact
	// qualifier-boundary check is the caller's (pkg/api), which re-parses
	// product_id. Filtering here rather than only in the caller is what keeps
	// Limit honest — a narrowed query would otherwise spend its whole page cap
	// on rows it then discards, and report truncation that isn't real.
	ArchAllow []string
	// ExactVersions pairs each queried base identifier with the version the
	// caller named for it (csaf.MatchVersion form; empty when none). It
	// narrows only rows whose VersionKind is 'exact'; every other row passes
	// through. A base named at least once without a version, and a base not
	// listed here, keep every exact row with its whole list. A base named only
	// with versions keeps an exact row when one of those versions is in the
	// row's list, or when the list is empty (the vendor stated the verdict with
	// no version), and the returned row's Versions are narrowed to the
	// versions matched. Each row is judged against its own list, so a version
	// listed on one row (another CVE, another architecture) never admits
	// another row. Applied in the query, like ArchAllow, so Limit counts rows
	// the caller keeps.
	ExactVersions []BaseVersion
	// SourceBases are base identifiers the caller reached only through a
	// binary package's source package (pkg/api's via_source_package). An
	// exact row under one never matches: an exact list names the builds the
	// vendor listed for that package, and a source package's name and version
	// say nothing about them. Every other row passes through. Applied in the
	// query, like ExactVersions.
	SourceBases []string
	Limit       int
	Offset      int
}

// BaseVersion is one queried product: a base identifier it resolved to and
// the version the caller named, empty for none.
type BaseVersion struct{ Base, Version string }

// ExactFilter is QueryFilters.ExactVersions resolved per base: the bases the
// caller named only with versions, each with the set of versions named.
type ExactFilter map[string]map[string]bool

// NewExactFilter resolves pairs into an ExactFilter. A base named at least
// once without a version is left out: it keeps every exact row whole.
func NewExactFilter(pairs []BaseVersion) ExactFilter {
	open := make(map[string]bool)
	f := make(ExactFilter)
	for _, p := range pairs {
		if p.Version == "" {
			open[p.Base] = true
			continue
		}
		if f[p.Base] == nil {
			f[p.Base] = make(map[string]bool)
		}
		f[p.Base][p.Version] = true
	}
	for b := range open {
		delete(f, b)
	}
	return f
}

// Apply is the one exact-list rule every store calls on a row it read: it
// reports whether the row survives and returns it with Versions narrowed to
// the versions matched. Rows that are not 'exact', rows with an empty list and
// rows whose base the filter does not name are returned unchanged.
func (f ExactFilter) Apply(s Statement) (Statement, bool) {
	want, ok := f[s.BaseID]
	if !ok || s.VersionKind != VersionKindExact || len(s.Versions) == 0 {
		return s, true
	}
	var matched []string
	for _, v := range s.Versions {
		if want[v] {
			matched = append(matched, v)
		}
	}
	if len(matched) == 0 {
		return s, false
	}
	s.Versions = matched
	return s, true
}

// Alias is a mapping from one identifier namespace to another, as published
// by a vendor (e.g. Red Hat's repository-to-cpe.json).
type Alias struct {
	Vendor   string
	SourceNS string
	SourceID string
	TargetNS string
	TargetID string
	Updated  string
}
