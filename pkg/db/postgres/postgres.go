// Package postgres is the PostgreSQL implementation of db.Store. It mirrors the
// SQLite backend's behaviour exactly — same query shapes, same conditional
// upsert, same stats caching — with three deliberate dialect changes that the
// Phase-2 dry-run identified:
//
//   - IN-lists bind as `= ANY($n::text[])` (pgx binds a Go slice directly)
//     instead of an expanded `?,?,…` placeholder list.
//   - The upsert skip-test uses `IS DISTINCT FROM` (Postgres' null-safe
//     comparison) where SQLite uses `IS NOT`.
//   - `updated` stays a TEXT column so RFC3339 lexicographic comparison keeps
//     identical semantics to SQLite — no behaviour change.
//
// The covering index (see migrations.go) is the reason this backend exists:
// broad-mode queries become index-only scans, eliminating the per-row heap
// fetches that capped the SQLite backend's broad-mode speedup.
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

// defaultQueryTimeout matches the SQLite backend's default; overridable via
// SetQueryTimeout (wired from the -query-timeout server flag).
const defaultQueryTimeout = 20 * time.Second

// DB is the PostgreSQL-backed db.Store implementation.
type DB struct {
	pool         *pgxpool.Pool
	queryTimeout time.Duration

	// Stats caching mirrors the SQLite backend: a cached struct refreshed at
	// the end of each ingest cycle, since the COUNT(DISTINCT) scans are slow on
	// the production-size table. statsCompute serialises the slow path.
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
// FROM is null-safe, matching SQLite's IS NOT). `updated` is intentionally not
// part of the change-test so a timestamp-only republish is a true no-op.
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

	const q = `
		INSERT INTO statements (vendor, cve, product_id, base_id, version, id_type, status, justification, updated, source_format, scope)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
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
		   OR statements.id_type       IS DISTINCT FROM excluded.id_type`

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
		if _, err := tx.Exec(ctx, q,
			s.Vendor, s.CVE, s.ProductID, base, version, s.IDType,
			s.Status, s.Justification, s.Updated, sourceFormat, s.Scope); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// QueryStatements is the unified query primitive — same filter/scope/order/
// limit semantics as the SQLite backend. IN-lists bind as text arrays.
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

// Stats returns cached coverage stats, computing on first call. See SQLite
// backend for the caching rationale (slow COUNT(DISTINCT) on the big table).
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

// Optimize refreshes planner statistics (Postgres' autovacuum also does this in
// the background; an explicit ANALYZE after ingest keeps plans current).
func (p *DB) Optimize() error {
	_, err := p.pool.Exec(context.Background(), `ANALYZE statements`)
	return err
}

// BulkUpsertAliases inserts or refreshes alias rows in one transaction.
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

	const q = `
		INSERT INTO product_aliases (vendor, source_ns, source_id, target_ns, target_id, confidence, updated)
		VALUES ($1,$2,$3,$4,$5,1.0,$6)
		ON CONFLICT (vendor, source_ns, source_id, target_ns, target_id) DO UPDATE SET
			confidence = 1.0,
			updated = excluded.updated`
	for _, a := range aliases {
		if _, err := tx.Exec(ctx, q, a.Vendor, a.SourceNS, a.SourceID, a.TargetNS, a.TargetID, a.Updated); err != nil {
			return err
		}
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
