package db

// This file holds the backend-agnostic data types shared by every db.Store
// implementation and its consumers. The concrete store lives in a backend
// subpackage (pkg/db/postgres); pkg/db itself carries only types + the Store
// interface (see store.go), so it pulls in no database driver.

// Statement is a VEX assertion stored in the database.
type Statement struct {
	Vendor        string
	CVE           string
	ProductID     string
	BaseID        string
	Version       string
	IDType        string
	Status        string
	Justification string
	Updated       string
	SourceFormat  string // "csaf", "oval", ... — upstream feed format
	// Scope restricts a statement to one product context (an OpenVEX product
	// @id — e.g. a container image). Empty for every package-level feed; set
	// only for subcomponent-scoped sources (Rancher VEX). Part of the primary
	// key from schema v4 so the same package+CVE can carry different verdicts
	// under different products without colliding. Gated at query time —
	// QueryStatements only returns scoped rows when QueryFilters.Scopes names
	// a match.
	Scope string
	// Notes is transient conversion provenance (e.g. "converted_from=cyclonedx-vex;
	// original_justification=...; fidelity=lossy") for user-uploaded VEX that was
	// normalised on the way in. Never a DB column — empty for every stored row,
	// set only on in-memory user rows and appended to status_notes by the encoder.
	Notes string
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
// product_id, source_format) so a paged/limited slice is stable across calls
// and an emitted VEX document is byte-stable when the data hasn't changed.
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
	Limit  int
	Offset int
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
