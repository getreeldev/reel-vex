// Package postgres is the PostgreSQL implementation of db.Store — the only
// backend reel-vex ships. Notable design points:
//
//   - IN-lists bind as `= ANY($n::text[])` — pgx binds a Go slice directly, so
//     there's no expanded `?,?,…` placeholder list to build.
//   - The upsert skip-test uses `IS DISTINCT FROM` (Postgres' null-safe
//     comparison) so a NULL↔value change on a nullable column still counts.
//   - `updated` is a TEXT column holding RFC3339 strings; the query layer
//     compares it lexicographically, which equals chronological order because
//     ingest always stores UTC (see pkg/ingest).
//
// The covering index (see migrations.go) is what makes broad-mode queries
// index-only scans, eliminating the per-row heap fetches that would otherwise
// dominate broad-mode at production scale.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/getreeldev/reel-vex/pkg/db"
)

// defaultQueryTimeout is the per-query ceiling; overridable via
// SetQueryTimeout (wired from the -query-timeout server flag).
const defaultQueryTimeout = 20 * time.Second

// DB is the PostgreSQL-backed db.Store implementation.
type DB struct {
	pool         *pgxpool.Pool
	queryTimeout time.Duration

	// Stats caching: a cached struct refreshed at the end of each ingest cycle,
	// since the COUNT(DISTINCT) scans are slow on the production-size table.
	// statsCompute serialises the slow path.
	statsMu      sync.RWMutex
	cachedStats  *db.Stats
	statsCompute sync.Mutex
}

// Compile-time assertion that *DB satisfies the persistence contract.
var _ db.Store = (*DB)(nil)

// Open connects to Postgres (dsn is a libpq/pgx URL or keyword string),
// applies migrations, and returns a ready Store.
func Open(dsn string) (*DB, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	d := &DB{pool: pool, queryTimeout: defaultQueryTimeout}
	if err := d.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return d, nil
}

// Close releases the connection pool.
func (p *DB) Close() error {
	p.pool.Close()
	return nil
}

// SetQueryTimeout overrides the per-query ceiling. d <= 0 is ignored.
func (p *DB) SetQueryTimeout(d time.Duration) {
	if d > 0 {
		p.queryTimeout = d
	}
}

// UpsertVendor inserts or updates a vendor display row.
func (p *DB) UpsertVendor(id, name string) error {
	_, err := p.pool.Exec(context.Background(), `
		INSERT INTO vendors (id, name) VALUES ($1, $2)
		ON CONFLICT (id) DO UPDATE SET name = excluded.name
	`, id, name)
	return err
}

// UpsertAdapterState records an adapter's feed URL + watermark. An empty
// lastSynced preserves the prior watermark; `updated` is the real wall-clock
// time of this write (the LastIngestAt signal).
func (p *DB) UpsertAdapterState(adapterID, feedURL, lastSynced string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := p.pool.Exec(context.Background(), `
		INSERT INTO adapter_state (adapter_id, feed_url, last_synced, updated)
		VALUES ($1, $2, NULLIF($3, ''), $4)
		ON CONFLICT (adapter_id) DO UPDATE SET
			feed_url = excluded.feed_url,
			last_synced = COALESCE(NULLIF(excluded.last_synced, ''), adapter_state.last_synced),
			updated = excluded.updated
	`, adapterID, feedURL, lastSynced, now)
	return err
}

// AdapterLastSynced returns the watermark for an adapter, or "" if it has
// never synced.
func (p *DB) AdapterLastSynced(adapterID string) (string, error) {
	var ts *string
	err := p.pool.QueryRow(context.Background(),
		`SELECT last_synced FROM adapter_state WHERE adapter_id = $1`, adapterID).Scan(&ts)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if ts == nil {
		return "", nil
	}
	return *ts, nil
}

// LastIngestAt returns MAX(adapter_state.updated) as a time, or the zero time
// when nothing has run or the value can't be parsed (treated as stale).
func (p *DB) LastIngestAt() (time.Time, error) {
	var ts *string
	if err := p.pool.QueryRow(context.Background(),
		`SELECT MAX(updated) FROM adapter_state`).Scan(&ts); err != nil {
		return time.Time{}, err
	}
	if ts == nil || *ts == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, *ts)
	if err != nil {
		return time.Time{}, nil
	}
	return t, nil
}

// BulkInsert applies the conditional upsert in one transaction: a row is
// rewritten only when a verdict-bearing column actually changed (IS DISTINCT
// FROM is null-safe, so a NULL↔value change still counts). `updated` is
// intentionally not part of the change-test so a timestamp-only republish is a
// true no-op.
//
// At ingest scale per-row INSERTs are far too slow (one network round-trip
// each). Instead the batch is bulk-loaded into a temp table via COPY (binary,
// index-free), then merged into statements with the conditional upsert in a
// single set-based statement. DISTINCT ON dedups rows that share a PK within
// the same batch (keeping the last by ctid), since the set-based upsert — unlike
// per-row — can't touch the same conflict target twice in one statement.
var bulkCols = []string{"vendor", "cve", "product_id", "base_id", "version", "id_type", "status", "justification", "updated", "source_format", "scope"}

func (p *DB) BulkInsert(stmts []db.Statement) error {
	if len(stmts) == 0 {
		return nil
	}
	ctx := context.Background()
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE _ingest (LIKE statements) ON COMMIT DROP`); err != nil {
		return err
	}

	rows := make([][]any, 0, len(stmts))
	for _, s := range stmts {
		base := s.BaseID
		if base == "" {
			base = s.ProductID
		}
		var version any // nil -> NULL
		if s.Version != "" {
			version = s.Version
		}
		sourceFormat := s.SourceFormat
		if sourceFormat == "" {
			sourceFormat = "csaf"
		}
		rows = append(rows, []any{s.Vendor, s.CVE, s.ProductID, base, version, s.IDType, s.Status, s.Justification, s.Updated, sourceFormat, s.Scope})
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"_ingest"}, bulkCols, pgx.CopyFromRows(rows)); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO statements (vendor, cve, product_id, base_id, version, id_type, status, justification, updated, source_format, scope)
		SELECT DISTINCT ON (vendor, cve, product_id, source_format, scope)
			vendor, cve, product_id, base_id, version, id_type, status, justification, updated, source_format, scope
		FROM _ingest
		ORDER BY vendor, cve, product_id, source_format, scope, ctid DESC
		ON CONFLICT (vendor, cve, product_id, source_format, scope) DO UPDATE SET
			base_id = excluded.base_id,
			version = excluded.version,
			id_type = excluded.id_type,
			status = excluded.status,
			justification = excluded.justification,
			updated = excluded.updated
		WHERE statements.status        IS DISTINCT FROM excluded.status
		   OR statements.justification IS DISTINCT FROM excluded.justification
		   OR statements.base_id       IS DISTINCT FROM excluded.base_id
		   OR statements.version       IS DISTINCT FROM excluded.version
		   OR statements.id_type       IS DISTINCT FROM excluded.id_type`); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// QueryStatements is the unified query primitive: AND across populated
// dimensions, IN within each, the scope gate, then order/limit/offset. IN-lists
// bind as text arrays.
func (p *DB) QueryStatements(f db.QueryFilters) ([]db.Statement, error) {
	if len(f.CVEs) == 0 && len(f.ProductBaseIDs) == 0 {
		return nil, nil
	}

	clauses := make([]string, 0, 8)
	args := make([]any, 0)

	addIn := func(col string, vals []string) {
		if len(vals) == 0 {
			return
		}
		args = append(args, vals)
		clauses = append(clauses, fmt.Sprintf("%s = ANY($%d::text[])", col, len(args)))
	}
	addIn("cve", f.CVEs)
	addIn("base_id", f.ProductBaseIDs)
	addIn("vendor", f.Vendors)
	addIn("source_format", f.SourceFormats)
	addIn("status", f.Statuses)
	addIn("justification", f.Justifications)

	if f.Since != "" {
		args = append(args, f.Since)
		clauses = append(clauses, fmt.Sprintf("updated >= $%d", len(args)))
	}

	// Scope gate: with no scope context only unscoped rows are returned, so a
	// product-scoped not_affected can't suppress an unrelated product's finding.
	if len(f.Scopes) == 0 {
		clauses = append(clauses, "scope = ''")
	} else {
		args = append(args, f.Scopes)
		clauses = append(clauses, fmt.Sprintf("(scope = '' OR scope = ANY($%d::text[]))", len(args)))
	}

	query := `
		SELECT vendor, cve, product_id, base_id, version, id_type, status, justification, updated, source_format, scope
		FROM statements
		WHERE ` + strings.Join(clauses, " AND ") + `
		ORDER BY base_id, cve, product_id, source_format`
	if f.Limit > 0 {
		args = append(args, f.Limit)
		query += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	if f.Offset > 0 {
		args = append(args, f.Offset)
		query += fmt.Sprintf(" OFFSET $%d", len(args))
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.queryTimeout)
	defer cancel()
	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanStatements(rows)
}

// scanStatements reads result rows into Statements. version and justification
// are the only nullable columns.
func scanStatements(rows pgx.Rows) ([]db.Statement, error) {
	var out []db.Statement
	for rows.Next() {
		var s db.Statement
		var version, justification *string
		if err := rows.Scan(
			&s.Vendor, &s.CVE, &s.ProductID, &s.BaseID, &version, &s.IDType,
			&s.Status, &justification, &s.Updated, &s.SourceFormat, &s.Scope); err != nil {
			return nil, err
		}
		if version != nil {
			s.Version = *version
		}
		if justification != nil {
			s.Justification = *justification
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Stats returns cached coverage stats, computing on first call. Cached because
// the COUNT(DISTINCT) scans are slow on the big table (see the statsMu fields).
func (p *DB) Stats() (db.Stats, error) {
	p.statsMu.RLock()
	cached := p.cachedStats
	p.statsMu.RUnlock()
	if cached != nil {
		return *cached, nil
	}
	p.statsCompute.Lock()
	defer p.statsCompute.Unlock()
	p.statsMu.RLock()
	cached = p.cachedStats
	p.statsMu.RUnlock()
	if cached != nil {
		return *cached, nil
	}
	return p.computeAndCache()
}

// RefreshStats recomputes and caches coverage stats. Called at the end of each
// ingest cycle and at startup.
func (p *DB) RefreshStats() (db.Stats, error) {
	p.statsCompute.Lock()
	defer p.statsCompute.Unlock()
	return p.computeAndCache()
}

func (p *DB) computeAndCache() (db.Stats, error) {
	s, err := p.computeStats()
	if err != nil {
		return s, err
	}
	p.statsMu.Lock()
	cp := s
	p.cachedStats = &cp
	p.statsMu.Unlock()
	return s, nil
}

func (p *DB) computeStats() (db.Stats, error) {
	ctx := context.Background()
	var s db.Stats
	var vendors, cves, statements, aliases int64
	if err := p.pool.QueryRow(ctx, `SELECT COUNT(DISTINCT id) FROM vendors`).Scan(&vendors); err != nil {
		return s, err
	}
	if err := p.pool.QueryRow(ctx, `SELECT COUNT(DISTINCT cve) FROM statements`).Scan(&cves); err != nil {
		return s, err
	}
	if err := p.pool.QueryRow(ctx, `SELECT COUNT(*) FROM statements`).Scan(&statements); err != nil {
		return s, err
	}
	if err := p.pool.QueryRow(ctx, `SELECT COUNT(*) FROM product_aliases`).Scan(&aliases); err != nil {
		return s, err
	}
	var lastUpdated *string
	if err := p.pool.QueryRow(ctx, `SELECT MAX(last_synced) FROM adapter_state`).Scan(&lastUpdated); err != nil {
		return s, err
	}
	s.Vendors, s.CVEs, s.Statements, s.Aliases = int(vendors), int(cves), int(statements), int(aliases)
	if lastUpdated != nil {
		s.LastUpdated = *lastUpdated
	}
	return s, nil
}

// EnsureCoveringIndex builds the broad-mode covering index if it is missing.
// A plain (non-CONCURRENT) build is acceptable because real work only happens on
// the cold first ingest, when the box has no traffic; on every later cycle the
// index already exists and IF NOT EXISTS makes this an instant no-op. Building it
// here (after the index-free bulk load) instead of in the migration keeps the
// cold load fast. The key/INCLUDE columns must stay aligned with the broad-mode
// query in QueryStatements (key = its WHERE/ORDER-BY tuple; INCLUDE = the rest
// of the SELECTed columns) so the scan stays index-only.
func (p *DB) EnsureCoveringIndex() error {
	_, err := p.pool.Exec(context.Background(), `
		CREATE INDEX IF NOT EXISTS idx_statements_broad
			ON statements (base_id, cve, product_id, source_format)
			INCLUDE (vendor, version, id_type, status, justification, updated, scope)`)
	return err
}

// Optimize refreshes planner statistics (Postgres' autovacuum also does this in
// the background; an explicit ANALYZE after ingest keeps plans current).
func (p *DB) Optimize() error {
	_, err := p.pool.Exec(context.Background(), `ANALYZE statements`)
	return err
}

// aliasCols is the COPY column order for the alias bulk load. confidence is
// always 1.0 (we only store confirmed vendor mappings), supplied per row so the
// temp table's NOT NULL is satisfied without relying on a copied default.
var aliasCols = []string{"vendor", "source_ns", "source_id", "target_ns", "target_id", "confidence", "updated"}

// BulkUpsertAliases inserts or refreshes alias rows in one transaction. Like
// BulkInsert it bulk-loads via COPY into a temp table, then merges with a single
// set-based upsert — one round-trip instead of one per row, which matters for
// the Red Hat repository-to-cpe feed (thousands of rows). DISTINCT ON dedups
// rows that share the alias PK within the same batch (keeping the last by ctid),
// since the set-based upsert can't touch the same conflict target twice.
func (p *DB) BulkUpsertAliases(aliases []db.Alias) error {
	if len(aliases) == 0 {
		return nil
	}
	ctx := context.Background()
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE _ingest_aliases (LIKE product_aliases) ON COMMIT DROP`); err != nil {
		return err
	}

	rows := make([][]any, 0, len(aliases))
	for _, a := range aliases {
		rows = append(rows, []any{a.Vendor, a.SourceNS, a.SourceID, a.TargetNS, a.TargetID, 1.0, a.Updated})
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"_ingest_aliases"}, aliasCols, pgx.CopyFromRows(rows)); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO product_aliases (vendor, source_ns, source_id, target_ns, target_id, confidence, updated)
		SELECT DISTINCT ON (vendor, source_ns, source_id, target_ns, target_id)
			vendor, source_ns, source_id, target_ns, target_id, confidence, updated
		FROM _ingest_aliases
		ORDER BY vendor, source_ns, source_id, target_ns, target_id, ctid DESC
		ON CONFLICT (vendor, source_ns, source_id, target_ns, target_id) DO UPDATE SET
			confidence = 1.0,
			updated = excluded.updated`); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// LookupAliases returns all target identifiers in targetNS reached from the
// given source identifier, across all vendors. Treat the result as a set.
func (p *DB) LookupAliases(sourceNS, sourceID, targetNS string) ([]string, error) {
	rows, err := p.pool.Query(context.Background(), `
		SELECT target_id FROM product_aliases
		WHERE source_ns = $1 AND source_id = $2 AND target_ns = $3
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

// AliasCount returns the total number of alias rows.
func (p *DB) AliasCount() (int, error) {
	var n int64
	err := p.pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM product_aliases`).Scan(&n)
	return int(n), err
}
