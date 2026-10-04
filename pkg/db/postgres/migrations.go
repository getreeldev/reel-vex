package postgres

import (
	"context"
	"fmt"
)

// migration is one forward-only schema step; schema_version records the last
// one applied. v1 declares the original shape and each later step alters the
// table in place, so every step is written to be correct on the table its
// predecessor left, populated or not, although deploys start from an empty
// database.
type migration struct {
	version    int
	statements []string
}

var migrations = []migration{
	{version: 1, statements: []string{
		`CREATE TABLE IF NOT EXISTS vendors (
			id   TEXT PRIMARY KEY,
			name TEXT NOT NULL
		)`,
		// statements: all columns TEXT (version/justification nullable) to match
		// the query layer's ordering requirement — notably `updated` stays TEXT so
		// RFC3339 lexicographic comparison equals time order (ingest stores UTC).
		`CREATE TABLE IF NOT EXISTS statements (
			vendor         TEXT NOT NULL,
			cve            TEXT NOT NULL,
			product_id     TEXT NOT NULL,
			base_id        TEXT NOT NULL,
			version        TEXT,
			id_type        TEXT NOT NULL,
			status         TEXT NOT NULL,
			justification  TEXT,
			updated        TEXT NOT NULL,
			source_format  TEXT NOT NULL DEFAULT 'csaf',
			scope          TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (vendor, cve, product_id, source_format, scope)
		)`,
		`CREATE TABLE IF NOT EXISTS product_aliases (
			vendor     TEXT NOT NULL,
			source_ns  TEXT NOT NULL,
			source_id  TEXT NOT NULL,
			target_ns  TEXT NOT NULL,
			target_id  TEXT NOT NULL,
			confidence REAL NOT NULL DEFAULT 1.0,
			updated    TEXT NOT NULL,
			PRIMARY KEY (vendor, source_ns, source_id, target_ns, target_id)
		)`,
		`CREATE TABLE IF NOT EXISTS adapter_state (
			adapter_id  TEXT PRIMARY KEY,
			feed_url    TEXT,
			last_synced TEXT,
			updated     TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_statements_cve ON statements (cve)`,
		`CREATE INDEX IF NOT EXISTS idx_statements_source ON statements (source_format)`,
		`CREATE INDEX IF NOT EXISTS idx_aliases_source ON product_aliases (vendor, source_ns, source_id)`,
		`CREATE INDEX IF NOT EXISTS idx_aliases_target ON product_aliases (vendor, target_ns, target_id)`,
		// NOTE: the big covering index (idx_statements_broad) is deliberately NOT
		// created here. It is built/ensured at the END of each ingest cycle by
		// EnsureCoveringIndex (see ingest.Run). That way the cold first load runs
		// index-free (fast bulk COPY) and the index is built once afterwards;
		// later incremental cycles find it already present and just maintain it,
		// and the create no-ops. Creating it on the empty table here would force
		// the slow maintain-during-bulk-load path.
	}},
	{version: 2, statements: []string{
		// adapter_id: the adapter that last wrote the row; never part of the
		// primary key. It is what lets a sweep delete only one adapter's rows.
		// Rows that exist before this migration keep a NULL owner until an
		// adapter writes them again, so a row no adapter emits any more is
		// never removed — acceptable only because every deploy starts from a
		// fresh database.
		`ALTER TABLE statements ADD COLUMN IF NOT EXISTS adapter_id TEXT`,
		// (adapter_id, cve) rather than (adapter_id): Withdraw's held-CVE set
		// and the CVE-scoped sweep read the index instead of scanning every row
		// an adapter owns (~11M for Red Hat CSAF, every cycle). A plain CREATE
		// INDEX is fine: production applies this to an empty table.
		`CREATE INDEX IF NOT EXISTS idx_statements_adapter ON statements (adapter_id, cve)`,
		// Removal deletes millions of rows per cycle. With the default scale
		// factor (0.2 of ~200M+ rows) autovacuum would not run for about a
		// month, so freed space would not be reused and the table would keep
		// growing; 1% plus a 100k floor vacuums after every real sweep.
		`ALTER TABLE statements SET (autovacuum_vacuum_scale_factor = 0.01, autovacuum_vacuum_threshold = 100000)`,
	}},
	{version: 3, statements: []string{
		// One row per verdict. status and justification join the key, so one
		// versionless package the vendor lists at several versions with
		// different verdicts has one row per verdict, each carrying the sorted
		// list of versions stated for it (versions), and a package rebuild
		// changes a row's list instead of writing a new row. version_kind says
		// how the list is read: '' (legacy: one version per statement, not yet
		// converted), 'exact' or 'boundary'. stream joins the key too: a CSAF
		// fixed-in boundary holds only within the vendor product stream it is
		// stated for (relates_to), so one package can carry a boundary per
		// stream. It is '' until a feed records it, and is keyed now so that
		// doing so never changes the primary key of a populated table. Deploys
		// start from a fresh database; the UPDATEs exist so this is also
		// correct on a populated one, where it rewrites every row (migrate runs
		// without a deadline for that reason).
		//
		// The covering index INCLUDEs version, which is dropped below;
		// EnsureCoveringIndex rebuilds it with the new columns.
		`DROP INDEX IF EXISTS idx_statements_broad`,
		`ALTER TABLE statements ADD COLUMN versions TEXT[] NOT NULL DEFAULT '{}'`,
		`UPDATE statements SET versions = ARRAY[version] WHERE version IS NOT NULL AND version <> ''`,
		`ALTER TABLE statements ADD COLUMN version_kind TEXT NOT NULL DEFAULT ''`,
		// A key column cannot be NULL.
		`UPDATE statements SET justification = '' WHERE justification IS NULL`,
		`ALTER TABLE statements ALTER COLUMN justification SET DEFAULT '', ALTER COLUMN justification SET NOT NULL`,
		`ALTER TABLE statements ADD COLUMN stream TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE statements DROP CONSTRAINT statements_pkey`,
		`ALTER TABLE statements ADD PRIMARY KEY (vendor, cve, product_id, source_format, scope, stream, status, justification)`,
		`ALTER TABLE statements DROP COLUMN version`,
	}},
}

// migrate ensures schema_version exists, then applies each pending migration in
// its own transaction, bumping schema_version as the last statement. Open
// passes a context with no deadline: a step that rewrites a populated table
// takes as long as the table does.
func (p *DB) migrate(ctx context.Context) error {
	if _, err := p.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("create schema_version: %w", err)
	}
	var count int
	if err := p.pool.QueryRow(ctx, `SELECT COUNT(*) FROM schema_version`).Scan(&count); err != nil {
		return fmt.Errorf("count schema_version: %w", err)
	}
	if count == 0 {
		if _, err := p.pool.Exec(ctx, `INSERT INTO schema_version (version) VALUES (0)`); err != nil {
			return fmt.Errorf("seed schema_version: %w", err)
		}
	}
	var current int
	if err := p.pool.QueryRow(ctx, `SELECT version FROM schema_version`).Scan(&current); err != nil {
		return fmt.Errorf("read schema_version: %w", err)
	}

	for _, m := range migrations {
		if current >= m.version {
			continue
		}
		tx, err := p.pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration v%d: %w", m.version, err)
		}
		for _, stmt := range m.statements {
			if _, err := tx.Exec(ctx, stmt); err != nil {
				tx.Rollback(ctx)
				return fmt.Errorf("apply migration v%d: %w", m.version, err)
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE schema_version SET version = $1`, m.version); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("bump schema_version to %d: %w", m.version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration v%d: %w", m.version, err)
		}
		current = m.version
	}
	return nil
}
