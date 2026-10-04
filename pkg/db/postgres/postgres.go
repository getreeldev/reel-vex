// Package postgres is the PostgreSQL implementation of db.Store — the only
// backend reel-vex ships. Notable design points:
//
//   - IN-lists bind as `= ANY($n::text[])` — pgx binds a Go slice directly, so
//     there's no expanded `?,?,…` placeholder list to build.
//   - The upsert skip-test uses `IS DISTINCT FROM` (Postgres' null-safe
//     comparison): adapter_id is nullable, so a NULL↔value change of owner
//     still counts.
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
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
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

	// Open sweep sessions: adapter id -> keys recorded so far (see sweep.go).
	sweepMu   sync.Mutex
	sweepSeen map[string]int64

	// ingestConn is the pooled connection holding the ingest lock, nil when
	// this process does not hold it (see TryLockIngest).
	ingestMu   sync.Mutex
	ingestConn *pgxpool.Conn
}

// Compile-time assertion that *DB satisfies the persistence contract.
var _ db.Store = (*DB)(nil)

// Open connects to Postgres (dsn is a libpq/pgx URL or keyword string),
// applies migrations, and returns a ready Store. Connecting is bounded by 30 s;
// the migrations are not, because one that rewrites a populated table runs
// for as long as the table takes.
func Open(dsn string) (*DB, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	d := &DB{pool: pool, queryTimeout: defaultQueryTimeout}
	if err := d.migrate(context.Background()); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return d, nil
}

// Close releases the connection pool. A held ingest lock is released first:
// the pool's Close waits for every acquired connection to come back.
func (p *DB) Close() error {
	p.UnlockIngest()
	p.pool.Close()
	return nil
}

// Ping checks the pool can reach the database.
func (p *DB) Ping(ctx context.Context) error {
	return p.pool.Ping(ctx)
}

// ingestLockKey is the advisory-lock key of the ingest lock: the first 8 bytes
// of sha256 of a fixed string, so it cannot collide with a small key some
// other tool sharing the database might pick.
var ingestLockKey = func() int64 {
	sum := sha256.Sum256([]byte("reel-vex ingest"))
	return int64(binary.BigEndian.Uint64(sum[:8]))
}()

// TryLockIngest takes a session-level advisory lock on one pooled connection
// and keeps that connection out of the pool until UnlockIngest. A session lock
// outlives transactions, so the run's own transactions on other connections
// never release it, and it ends with the session, so a crashed process cannot
// leave it behind. Session locks are re-entrant, which is why a second call in
// this process is refused here rather than by Postgres.
func (p *DB) TryLockIngest() error {
	p.ingestMu.Lock()
	defer p.ingestMu.Unlock()
	if p.ingestConn != nil {
		return db.ErrIngestRunning
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("ingest lock: %w", err)
	}
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, ingestLockKey).Scan(&ok); err != nil {
		// Whether the lock was taken is unknown: closing the session drops it.
		conn.Hijack().Close(context.Background())
		return fmt.Errorf("ingest lock: %w", err)
	}
	if !ok {
		conn.Release()
		return db.ErrIngestRunning
	}
	p.ingestConn = conn
	return nil
}

// UnlockIngest releases the ingest lock and returns its connection to the
// pool. When the unlock cannot be confirmed the connection is closed instead,
// which ends the session and the lock with it.
func (p *DB) UnlockIngest() error {
	p.ingestMu.Lock()
	defer p.ingestMu.Unlock()
	conn := p.ingestConn
	if conn == nil {
		return nil
	}
	p.ingestConn = nil
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT pg_advisory_unlock($1)`, ingestLockKey).Scan(&ok); err != nil || !ok {
		conn.Hijack().Close(context.Background())
		if err == nil {
			err = errors.New("lock was not held")
		}
		return fmt.Errorf("ingest unlock: %w", err)
	}
	conn.Release()
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

// contentChanged is the upsert's change-test on content, which alone moves
// `updated`.
const contentChanged = `(statements.versions     IS DISTINCT FROM excluded.versions
		   OR statements.base_id      IS DISTINCT FROM excluded.base_id
		   OR statements.id_type      IS DISTINCT FROM excluded.id_type
		   OR statements.version_kind IS DISTINCT FROM excluded.version_kind)`

// BulkInsert applies the conditional upsert in one transaction. A row is keyed
// by its stream and verdict (stream, status and justification are in the
// primary key), so a changed verdict is a new row; an existing row's content
// is rewritten only when its version list, base_id, id_type or version_kind
// changed (IS DISTINCT FROM is null-safe). Versions are normalised first
// (db.NormalizeVersions), so a list that differs only in order or repeats is
// not a change. `updated` is intentionally not part of the change-test so a timestamp-only republish is a
// true no-op for the same writer. A row whose owner differs from the writer's
// is rewritten too, moving adapter_id and nothing else (`updated` keeps its
// value unless the content changed): two adapters can emit the same key — an
// Alpine package that moved between the main and community repositories —
// and when the first writer stops emitting it, its sweep must not delete a
// row the other still publishes. The row belongs to whoever wrote it last.
// That includes a NULL owner: a row nobody owned is adopted by the adapter
// that emits it, which may then sweep it like any row it writes; and a write
// with no owner leaves the row ownerless, which only ever keeps it.
//
// At ingest scale per-row INSERTs are far too slow (one network round-trip
// each). Instead the batch is bulk-loaded into a temp table via COPY (binary,
// index-free), then merged into statements with the conditional upsert in a
// single set-based statement. DISTINCT ON dedups rows that share a PK within
// the same batch (keeping the last by ctid, lists not merged), since the
// set-based upsert — unlike per-row — can't touch the same conflict target
// twice in one statement.
var bulkCols = []string{"vendor", "cve", "product_id", "base_id", "versions", "version_kind", "id_type", "status", "justification", "updated", "source_format", "scope", "stream", "adapter_id"}

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
		versions := db.NormalizeVersions(s.Versions)
		if versions == nil {
			versions = []string{} // a nil slice copies as NULL; the column is NOT NULL
		}
		sourceFormat := s.SourceFormat
		if sourceFormat == "" {
			sourceFormat = "csaf"
		}
		var adapterID any // nil -> NULL
		if s.AdapterID != "" {
			adapterID = s.AdapterID
		}
		rows = append(rows, []any{s.Vendor, s.CVE, s.ProductID, base, versions, s.VersionKind, s.IDType, s.Status, s.Justification, s.Updated, sourceFormat, s.Scope, s.Stream, adapterID})
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"_ingest"}, bulkCols, pgx.CopyFromRows(rows)); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO statements (vendor, cve, product_id, base_id, versions, version_kind, id_type, status, justification, updated, source_format, scope, stream, adapter_id)
		SELECT DISTINCT ON (vendor, cve, product_id, source_format, scope, stream, status, justification)
			vendor, cve, product_id, base_id, versions, version_kind, id_type, status, justification, updated, source_format, scope, stream, adapter_id
		FROM _ingest
		ORDER BY vendor, cve, product_id, source_format, scope, stream, status, justification, ctid DESC
		ON CONFLICT (vendor, cve, product_id, source_format, scope, stream, status, justification) DO UPDATE SET
			versions = excluded.versions,
			base_id = excluded.base_id,
			id_type = excluded.id_type,
			version_kind = excluded.version_kind,
			updated = CASE WHEN `+contentChanged+` THEN excluded.updated ELSE statements.updated END,
			adapter_id = excluded.adapter_id
		WHERE `+contentChanged+`
		   OR statements.adapter_id   IS DISTINCT FROM excluded.adapter_id`); err != nil {
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
	query, args, exact := statementsQuery(f)

	ctx, cancel := context.WithTimeout(context.Background(), p.queryTimeout)
	defer cancel()
	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out, err := scanStatements(rows)
	if err != nil || len(exact) == 0 {
		return out, err
	}
	// The predicate kept only rows the filter keeps; this narrows each one's
	// list to the versions matched.
	for i := range out {
		out[i], _ = exact.Apply(out[i])
	}
	return out, nil
}

// statementsQuery builds QueryStatements' SQL and arguments, and returns the
// exact-list filter whose matched versions the caller narrows after the scan.
func statementsQuery(f db.QueryFilters) (string, []any, db.ExactFilter) {
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

	// Arch narrowing: keep rows with no arch qualifier at all, plus rows whose
	// product_id contains one of the allowed values. Deliberately a superset —
	// LIKE can't see qualifier boundaries, so '%arch=amd64%' would also match a
	// hypothetical arch=amd64_v2. pkg/api re-parses the qualifier and does the
	// exact check; this pass exists so LIMIT applies to rows the caller will
	// actually keep. The predicate rides the existing (base_id, cve, product_id,
	// source_format) covering index as an index filter — verified on prod: no
	// additional heap fetches, no new index.
	if len(f.ArchAllow) > 0 {
		patterns := make([]string, 0, len(f.ArchAllow))
		for _, a := range f.ArchAllow {
			if a == "" {
				continue
			}
			patterns = append(patterns, "%arch="+a+"%")
		}
		args = append(args, patterns)
		clauses = append(clauses, fmt.Sprintf("(position('arch=' in product_id) = 0 OR product_id LIKE ANY($%d::text[]))", len(args)))
	}

	// Exact-list matching: for a base the caller named only with versions, an
	// exact row survives only when one of those versions is in its list (or
	// the list is empty). The versions bind as ONE jsonb object keyed by base
	// ({"<base>": ["<version>", ...]}), so each row is tested against its own
	// base's versions and its own list: `?` and `->` find the base in the
	// object, `?|` tests the row's list against it. Do not rewrite this as a
	// correlated EXISTS over unnested (base, version) arrays: inside the OR it
	// becomes a per-row SubPlan (measured 1m44s against 0.43s at 1M exact rows
	// and 5,000 queried products). Every column read is in the covering index,
	// so the predicate filters inside the index scan and Limit counts rows the
	// caller keeps.
	exact := db.NewExactFilter(f.ExactVersions)
	if len(exact) > 0 {
		m := make(map[string][]string, len(exact))
		for b, vs := range exact {
			m[b] = slices.Sorted(maps.Keys(vs))
		}
		j, _ := json.Marshal(m) // a map of string slices always marshals
		args = append(args, string(j))
		clauses = append(clauses, fmt.Sprintf(
			"(version_kind <> 'exact' OR cardinality(versions) = 0 OR NOT ($%[1]d::jsonb ? base_id) OR ($%[1]d::jsonb -> base_id) ?| versions)", len(args)))
	}
	// A base reached only through a source package admits no exact row.
	if len(f.SourceBases) > 0 {
		args = append(args, f.SourceBases)
		clauses = append(clauses, fmt.Sprintf("NOT (version_kind = 'exact' AND base_id = ANY($%d::text[]))", len(args)))
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
		SELECT vendor, cve, product_id, base_id, versions, version_kind, id_type, status, justification, updated, source_format, scope
		FROM statements
		WHERE ` + strings.Join(clauses, " AND ") + `
		ORDER BY base_id, cve, product_id, source_format, vendor, scope, status, justification`
	if f.Limit > 0 {
		args = append(args, f.Limit)
		query += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	if f.Offset > 0 {
		args = append(args, f.Offset)
		query += fmt.Sprintf(" OFFSET $%d", len(args))
	}
	return query, args, exact
}

// scanStatements reads result rows into Statements. No selected column is
// nullable; an empty version list reads as nil, as NormalizeVersions writes it.
func scanStatements(rows pgx.Rows) ([]db.Statement, error) {
	var out []db.Statement
	for rows.Next() {
		var s db.Statement
		if err := rows.Scan(
			&s.Vendor, &s.CVE, &s.ProductID, &s.BaseID, &s.Versions, &s.VersionKind, &s.IDType,
			&s.Status, &s.Justification, &s.Updated, &s.SourceFormat, &s.Scope); err != nil {
			return nil, err
		}
		if len(s.Versions) == 0 {
			s.Versions = nil
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Stats returns cached coverage stats, computing on first call. Cached because
// the aggregate scans are slow on the big table (see the statsMu fields).
//
// A caller never queues behind an in-flight computation. The startup warm-up
// (cmd/server) holds statsCompute for as long as the scans take — minutes on a
// prod-size table — and a request that blocked on that mutex would hang until
// the fronting proxy timed it out, reporting nothing after 30s of waiting.
// db.ErrStatsWarming says "ask again shortly", which the caller can turn into a
// fast 503 instead of a stalled connection.
func (p *DB) Stats() (db.Stats, error) {
	p.statsMu.RLock()
	cached := p.cachedStats
	p.statsMu.RUnlock()
	if cached != nil {
		return *cached, nil
	}
	if !p.statsCompute.TryLock() {
		return db.Stats{}, db.ErrStatsWarming
	}
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

// statsTimeout bounds the whole stats computation. It is a backstop against a
// pathological plan, not a normal-path budget: the queries below run in a few
// minutes on a prod-size table, and if one ever takes an hour we want it dead
// rather than holding a pooled connection and spilling temp files. (An earlier
// unbounded COUNT(DISTINCT) ran ~30 minutes on 382M rows and spilled GBs.)
const statsTimeout = 20 * time.Minute

// statsTimeoutSQL is statsTimeout as a Postgres literal, applied server-side
// with SET LOCAL so the database enforces it even if this process is gone.
// Kept next to statsTimeout so the two can't drift.
const statsTimeoutSQL = `'20min'`

// distinctCVEQuery counts distinct CVEs with a loose ("skip") index scan rather
// than COUNT(DISTINCT cve).
//
// Postgres has no native loose index scan, and plans COUNT(DISTINCT cve) as a
// single-threaded Seq Scan over every row followed by a full Sort — on 382M
// rows that is ~30 minutes and gigabytes of temp spill, every process restart.
// This recursive form walks idx_statements_cve one distinct value at a time, so
// the work tracks the number of *distinct* CVEs (~336k) instead of the number
// of rows. Measured on production: 30 min -> 1m59s, same answer.
//
// It depends on an index leading with `cve` (idx_statements_cve). Without one,
// each step degrades to a full scan and this becomes far worse than the query
// it replaced — so do not drop that index without revisiting this.
const distinctCVEQuery = `
	WITH RECURSIVE t AS (
	    (SELECT cve FROM statements ORDER BY cve LIMIT 1)
	  UNION ALL
	    SELECT (SELECT s.cve FROM statements s WHERE s.cve > t.cve ORDER BY s.cve LIMIT 1)
	    FROM t WHERE t.cve IS NOT NULL
	)
	SELECT count(*) FROM t WHERE cve IS NOT NULL`

func (p *DB) computeStats() (db.Stats, error) {
	ctx, cancel := context.WithTimeout(context.Background(), statsTimeout)
	defer cancel()
	var s db.Stats

	// Run inside a transaction so `SET LOCAL statement_timeout` scopes to these
	// queries and unwinds on its own — a plain SET would ride the pooled
	// connection back into the pool and silently cap unrelated work later.
	//
	// The Go context above is not enough on its own. If this process dies
	// mid-scan (a container recreate, say), Postgres does not notice the client
	// is gone until the query tries to return rows, so an aggregate over the
	// whole table keeps running to completion with nothing to return to,
	// competing for I/O with the replacement process doing the same work.
	// Observed on a v0.12.0 -> v0.12.1 swap: an orphaned count was still going
	// eleven minutes after the container that asked for it had exited. Only a
	// server-side timeout can end that, because only the server is still there.
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return s, err
	}
	defer tx.Rollback(context.Background()) // read-only; rollback is the cheap exit
	if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout = `+statsTimeoutSQL); err != nil {
		return s, err
	}

	var vendors, cves, statements, aliases int64
	if err := tx.QueryRow(ctx, `SELECT COUNT(DISTINCT id) FROM vendors`).Scan(&vendors); err != nil {
		return s, err
	}
	if err := tx.QueryRow(ctx, distinctCVEQuery).Scan(&cves); err != nil {
		return s, err
	}
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM statements`).Scan(&statements); err != nil {
		return s, err
	}
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM product_aliases`).Scan(&aliases); err != nil {
		return s, err
	}
	var lastUpdated *string
	if err := tx.QueryRow(ctx, `SELECT MAX(last_synced) FROM adapter_state`).Scan(&lastUpdated); err != nil {
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
// query in QueryStatements (key = its WHERE tuple and the leading ORDER BY
// columns, the rest of the order sorted from INCLUDE columns; INCLUDE = the
// rest of the SELECTed and filtered columns) so the scan stays index-only.
// INCLUDEing the version list keeps the entries small: a list holds the
// versions of one package identity for one verdict, and a btree entry is
// limited to ~2,700 bytes. Measured on the live feeds (Ubuntu 2026-10-02,
// Rancher 2026-10-03): Ubuntu lists hold at most 7 versions and at most 163
// bytes of text, Rancher lists at most 30 versions and 421 bytes of text
// (~504 bytes as stored).
func (p *DB) EnsureCoveringIndex() error {
	_, err := p.pool.Exec(context.Background(), `
		CREATE INDEX IF NOT EXISTS idx_statements_broad
			ON statements (base_id, cve, product_id, source_format)
			INCLUDE (vendor, versions, version_kind, id_type, status, justification, updated, scope)`)
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
