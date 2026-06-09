package postgres

import (
	"context"
	"fmt"
)

// migration is one forward-only schema step. The schema is greenfield: v1
// declares the current shape directly, so there's no historical table-rebuild
// dance. schema_version tracks applied steps so future migrations append cleanly.
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
}

// migrate ensures schema_version exists, then applies each pending migration in
// its own transaction, bumping schema_version as the last statement.
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
