package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// defaultQueryTimeout is the out-of-the-box ceiling on a single statement
// query. It bounds the blast radius of an over-broad request (e.g. a large
// user-VEX analyze that expands to thousands of CVEs) so no one request can pin
// the DB indefinitely. Override per-instance with SetQueryTimeout (wired from
// the -query-timeout server flag); a self-hoster on dedicated hardware can
// raise it freely.
const defaultQueryTimeout = 20 * time.Second

// DB wraps a SQLite database for VEX statement storage.
type DB struct {
	db *sql.DB

	// queryTimeout caps a single QueryStatements call. Defaults to
	// defaultQueryTimeout; SetQueryTimeout overrides it.
	queryTimeout time.Duration

	// statsMu guards cachedStats. statsCompute serialises the slow COUNT
	// queries — without it, multiple concurrent Stats() / RefreshStats()
	// calls would each kick off their own scan, multiplying the time.
	// See Stats / RefreshStats for semantics.
	statsMu      sync.RWMutex
	cachedStats  *Stats
	statsCompute sync.Mutex
}

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

// Open opens or creates a SQLite database at the given path.
func Open(path string) (*DB, error) {
	// PRAGMAs are set in the DSN (via modernc's _pragma= form) rather than a
	// one-off Exec so they apply to *every* connection database/sql opens in
	// its pool. synchronous in particular is per-connection and does not
	// persist, so an Exec on a single pooled connection would leave the rest
	// on the default. The read-tuning pragmas (cache, mmap, temp_store) matter
	// because /v1/statements broad mode can return tens of thousands of rows
	// from a multi-GB DB; busy_timeout lets reads wait out the ingest writer
	// instead of erroring "database is locked".
	dsn := path
	if !strings.Contains(dsn, "?") {
		dsn += "?" + strings.Join([]string{
			"_pragma=journal_mode(WAL)",
			"_pragma=synchronous(NORMAL)",
			"_pragma=busy_timeout(5000)",
			"_pragma=cache_size(-262144)",   // 256 MB page cache (negative = KiB)
			"_pragma=mmap_size(2147483648)", // 2 GB memory-mapped I/O
			"_pragma=temp_store(MEMORY)",    // ORDER BY sorts / temp btrees in RAM
		}, "&")
	}
	d, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db := &DB{db: d, queryTimeout: defaultQueryTimeout}
	if err := db.migrate(); err != nil {
		d.Close()
		return nil, err
	}
	return db, nil
}

// Close closes the database.
func (db *DB) Close() error {
	return db.db.Close()
}

// SetQueryTimeout overrides the per-query ceiling (default defaultQueryTimeout).
// Production wires this from the -query-timeout server flag. d <= 0 is ignored,
// preserving the default.
func (db *DB) SetQueryTimeout(d time.Duration) {
	if d > 0 {
		db.queryTimeout = d
	}
}

func (db *DB) migrate() error {
	return runMigrations(db.db)
}

// UpsertVendor inserts or updates a vendor row. From v3 onward the vendors
// table is pure display metadata — feed URL and watermark moved to
// adapter_state so multiple adapters under one vendor can't stomp on each
// other.
func (db *DB) UpsertVendor(id, name string) error {
	_, err := db.db.Exec(`
		INSERT INTO vendors (id, name) VALUES (?, ?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name
	`, id, name)
	return err
}

// UpsertAdapterState records an adapter's feed URL + current watermark.
// Called at the end of each Sync cycle. timestamp should be the newest
// Updated field we saw on emitted statements this cycle ("" if nothing
// was emitted — keeps existing watermark intact).
func (db *DB) UpsertAdapterState(adapterID, feedURL, lastSynced string) error {
	// If lastSynced is empty, preserve the prior watermark (we didn't see
	// new data this cycle). feed_url is always refreshed since Discover
	// re-resolves it each cycle. `updated` is the real wall-clock time of this
	// write (NOT the watermark) — it's the "this adapter ran a cycle now"
	// signal that LastIngestAt() aggregates to gate the boot-time ingest.
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.db.Exec(`
		INSERT INTO adapter_state (adapter_id, feed_url, last_synced, updated)
		VALUES (?, ?, NULLIF(?, ''), ?)
		ON CONFLICT(adapter_id) DO UPDATE SET
			feed_url = excluded.feed_url,
			last_synced = COALESCE(NULLIF(excluded.last_synced, ''), adapter_state.last_synced),
			updated = excluded.updated
	`, adapterID, feedURL, lastSynced, now)
	return err
}

// AdapterLastSynced returns the last_synced timestamp for an adapter, or
// "" if the adapter has never successfully synced.
func (db *DB) AdapterLastSynced(adapterID string) (string, error) {
	var ts sql.NullString
	err := db.db.QueryRow("SELECT last_synced FROM adapter_state WHERE adapter_id = ?", adapterID).Scan(&ts)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return ts.String, nil
}

// LastIngestAt returns the wall-clock time of the most recent adapter_state
// write across all adapters (MAX(updated)) — i.e. roughly when the last ingest
// cycle ran. Returns the zero time when no adapter has run yet, or when the
// stored value can't be parsed (e.g. a legacy pre-fix watermark string) — the
// caller treats either as "stale", so the next boot ingests once and the value
// self-corrects. Used to gate the boot-time ingest (see IngestRunner).
func (db *DB) LastIngestAt() (time.Time, error) {
	var ts sql.NullString
	if err := db.db.QueryRow("SELECT MAX(updated) FROM adapter_state").Scan(&ts); err != nil {
		return time.Time{}, err
	}
	if !ts.Valid || ts.String == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, ts.String)
	if err != nil {
		return time.Time{}, nil
	}
	return t, nil
}

// BulkInsert inserts statements in a single transaction.
func (db *DB) BulkInsert(stmts []Statement) error {
	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Conditional upsert: rewrite a row only when a verdict-bearing column
	// actually changed. INSERT OR REPLACE rewrote every row unconditionally,
	// so re-walking a monolithic feed (Canonical's tarball, Rancher) re-upserted
	// all ~164M rows even on a no-op republish — hours of WAL churn for nothing.
	// The WHERE makes an unchanged row a true no-op (no write, no index update).
	//
	// `updated` is deliberately NOT in the change-test: vendors may bump every
	// statement's timestamp on each republish, which would defeat the skip. So
	// `updated` here means "when the verdict last materially changed", and a
	// timestamp-only bump is skipped. `IS NOT` (not `!=`) is null-safe — version
	// and justification are nullable, and `!=` would miss NULL<->value changes.
	prepared, err := tx.Prepare(`
		INSERT INTO statements (vendor, cve, product_id, base_id, version, id_type, status, justification, updated, source_format, scope)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(vendor, cve, product_id, source_format, scope) DO UPDATE SET
			base_id=excluded.base_id,
			version=excluded.version,
			id_type=excluded.id_type,
			status=excluded.status,
			justification=excluded.justification,
			updated=excluded.updated
		WHERE statements.status        IS NOT excluded.status
		   OR statements.justification IS NOT excluded.justification
		   OR statements.base_id       IS NOT excluded.base_id
		   OR statements.version       IS NOT excluded.version
		   OR statements.id_type       IS NOT excluded.id_type
	`)
	if err != nil {
		return err
	}
	defer prepared.Close()

	for _, s := range stmts {
		base := s.BaseID
		if base == "" {
			base = s.ProductID
		}
		var version any
		if s.Version != "" {
			version = s.Version
		}
		sourceFormat := s.SourceFormat
		if sourceFormat == "" {
			sourceFormat = "csaf"
		}
		if _, err := prepared.Exec(s.Vendor, s.CVE, s.ProductID, base, version, s.IDType, s.Status, s.Justification, s.Updated, sourceFormat, s.Scope); err != nil {
			return err
		}
	}
	return tx.Commit()
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

// QueryStatements is the unified VEX statement query primitive — replaces
// the v0.3.0 QueryResolve + QueryByCVE pair. At least one of CVEs or
// ProductBaseIDs must be set; everything else narrows the result set further.
func (db *DB) QueryStatements(f QueryFilters) ([]Statement, error) {
	if len(f.CVEs) == 0 && len(f.ProductBaseIDs) == 0 {
		return nil, nil
	}

	clauses := make([]string, 0, 8)
	args := make([]any, 0)

	addIn := func(col string, vals []string) {
		if len(vals) == 0 {
			return
		}
		placeholders := strings.Repeat("?,", len(vals))
		placeholders = placeholders[:len(placeholders)-1]
		clauses = append(clauses, fmt.Sprintf("%s IN (%s)", col, placeholders))
		for _, v := range vals {
			args = append(args, v)
		}
	}

	addIn("cve", f.CVEs)
	addIn("base_id", f.ProductBaseIDs)
	addIn("vendor", f.Vendors)
	addIn("source_format", f.SourceFormats)
	addIn("status", f.Statuses)
	addIn("justification", f.Justifications)

	if f.Since != "" {
		clauses = append(clauses, "updated >= ?")
		args = append(args, f.Since)
	}

	// Scope gate. Scoped statements (scope != '') only apply when the caller
	// names a matching scope — the product/image being analysed. With no scope
	// context, only unscoped rows (every package-level feed) are returned, so a
	// product-scoped not_affected can never suppress a finding for an unrelated
	// product. See pkg/csaf.NormalizeScope and pkg/source/ranchervex.
	if len(f.Scopes) == 0 {
		clauses = append(clauses, "scope = ''")
	} else {
		ph := strings.Repeat("?,", len(f.Scopes))
		ph = ph[:len(ph)-1]
		clauses = append(clauses, fmt.Sprintf("(scope = '' OR scope IN (%s))", ph))
		for _, sc := range f.Scopes {
			args = append(args, sc)
		}
	}

	// Deterministic order: makes LIMIT/OFFSET paging stable and the emitted
	// VEX document byte-identical across refetches when data is unchanged.
	// Broad mode filters on base_id via idx_statements_base_id; the sort is a
	// separate step (acceptable for the fetch-once-and-cache path).
	query := fmt.Sprintf(`
		SELECT vendor, cve, product_id, base_id, version, id_type, status, justification, updated, source_format, scope
		FROM statements
		WHERE %s
		ORDER BY base_id, cve, product_id, source_format
	`, strings.Join(clauses, " AND "))
	// SQLite only accepts OFFSET alongside a LIMIT, so when an offset is set
	// without a real limit we pass LIMIT -1 (unbounded) to keep the OFFSET valid.
	switch {
	case f.Limit > 0:
		query += " LIMIT ?"
		args = append(args, f.Limit)
	case f.Offset > 0:
		query += " LIMIT -1"
	}
	if f.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, f.Offset)
	}

	ctx, cancel := context.WithTimeout(context.Background(), db.queryTimeout)
	defer cancel()
	rows, err := db.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanStatements(rows)
}

// Stats returns the cached coverage statistics. Computes on first call;
// thereafter served from an in-memory cache that is invalidated only by an
// explicit RefreshStats call (hooked at the end of each ingest cycle).
//
// Why caching: on the production-scale DB (~145M rows after v0.4.2's
// Canonical OpenVEX adapter lands) the underlying COUNT(*) and
// COUNT(DISTINCT cve) queries take 30-60+ seconds — too slow for the
// browser-polled `/v1/stats` endpoint. Stats are coarse summary numbers
// (vendor/cve/statement counts), so serving slightly-stale-since-last-ingest
// is fine: the website doesn't need second-fresh totals.
func (db *DB) Stats() (Stats, error) {
	// Fast path: cache hit, no locks beyond the RWMutex read.
	db.statsMu.RLock()
	cached := db.cachedStats
	db.statsMu.RUnlock()
	if cached != nil {
		return *cached, nil
	}
	// Slow path: serialise concurrent computers; first one wins, the rest
	// see the populated cache after the unique compute returns.
	db.statsCompute.Lock()
	defer db.statsCompute.Unlock()
	db.statsMu.RLock()
	cached = db.cachedStats
	db.statsMu.RUnlock()
	if cached != nil {
		return *cached, nil
	}
	return db.computeAndCache()
}

// RefreshStats recomputes coverage statistics and updates the cache.
// Called from the ingest orchestrator at the end of each cycle and from a
// background goroutine at server startup. Tests that mutate the DB and
// expect updated stats must call this between mutation and read.
//
// Holds the statsCompute mutex so it can't run concurrently with a cache
// miss in Stats() — only one COUNT scan is ever in flight.
func (db *DB) RefreshStats() (Stats, error) {
	db.statsCompute.Lock()
	defer db.statsCompute.Unlock()
	return db.computeAndCache()
}

// Optimize runs `PRAGMA optimize` so the query planner has fresh statistics
// for index selection — notably for broad mode, where base_id is combined
// with optional vendor/status/justification filters. It analyses only what
// has changed and is a no-op otherwise, so it's cheap to call after each
// ingest cycle and at startup.
func (db *DB) Optimize() error {
	_, err := db.db.Exec("PRAGMA optimize")
	return err
}

// computeAndCache runs the slow SQL and updates the cache atomically.
// Caller must hold statsCompute.
func (db *DB) computeAndCache() (Stats, error) {
	s, err := db.computeStats()
	if err != nil {
		return s, err
	}
	db.statsMu.Lock()
	cp := s
	db.cachedStats = &cp
	db.statsMu.Unlock()
	return s, nil
}

// computeStats runs the slow COUNT queries against the live DB.
func (db *DB) computeStats() (Stats, error) {
	var s Stats
	err := db.db.QueryRow("SELECT COUNT(DISTINCT id) FROM vendors").Scan(&s.Vendors)
	if err != nil {
		return s, err
	}
	err = db.db.QueryRow("SELECT COUNT(DISTINCT cve) FROM statements").Scan(&s.CVEs)
	if err != nil {
		return s, err
	}
	err = db.db.QueryRow("SELECT COUNT(*) FROM statements").Scan(&s.Statements)
	if err != nil {
		return s, err
	}
	err = db.db.QueryRow("SELECT COUNT(*) FROM product_aliases").Scan(&s.Aliases)
	if err != nil {
		return s, err
	}
	var lastUpdated sql.NullString
	err = db.db.QueryRow("SELECT MAX(last_synced) FROM adapter_state").Scan(&lastUpdated)
	if err != nil && err != sql.ErrNoRows {
		return s, err
	}
	if lastUpdated.Valid {
		s.LastUpdated = lastUpdated.String
	}
	return s, nil
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

// BulkUpsertAliases replaces or inserts each alias row. Idempotent — safe to
// re-run with fresh data; rows for the same PK get their Updated refreshed.
func (db *DB) BulkUpsertAliases(aliases []Alias) error {
	if len(aliases) == 0 {
		return nil
	}
	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	prepared, err := tx.Prepare(`
		INSERT OR REPLACE INTO product_aliases
			(vendor, source_ns, source_id, target_ns, target_id, confidence, updated)
		VALUES (?, ?, ?, ?, ?, 1.0, ?)
	`)
	if err != nil {
		return err
	}
	defer prepared.Close()

	for _, a := range aliases {
		if _, err := prepared.Exec(a.Vendor, a.SourceNS, a.SourceID, a.TargetNS, a.TargetID, a.Updated); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LookupAliases returns all target identifiers in targetNS reached from the
// given source identifier, scanning across all vendors. Order is stable but
// not semantically meaningful; callers should treat the result as a set.
func (db *DB) LookupAliases(sourceNS, sourceID, targetNS string) ([]string, error) {
	rows, err := db.db.Query(`
		SELECT target_id FROM product_aliases
		WHERE source_ns = ? AND source_id = ? AND target_ns = ?
		ORDER BY vendor, target_id
	`, sourceNS, sourceID, targetNS)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// AliasCount returns the total number of rows in product_aliases. Used by
// stats + smoke tests.
func (db *DB) AliasCount() (int, error) {
	var n int
	err := db.db.QueryRow("SELECT COUNT(*) FROM product_aliases").Scan(&n)
	return n, err
}

func scanStatements(rows *sql.Rows) ([]Statement, error) {
	var stmts []Statement
	for rows.Next() {
		var s Statement
		var just, version sql.NullString
		if err := rows.Scan(&s.Vendor, &s.CVE, &s.ProductID, &s.BaseID, &version, &s.IDType, &s.Status, &just, &s.Updated, &s.SourceFormat, &s.Scope); err != nil {
			return nil, err
		}
		s.Justification = just.String
		s.Version = version.String
		stmts = append(stmts, s)
	}
	return stmts, rows.Err()
}
