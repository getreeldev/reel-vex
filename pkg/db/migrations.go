package db

import (
	"database/sql"
	"fmt"
)

// currentSchemaVersion is the schema version this binary expects. Each migration
// brings the database up to the next version; on Open() we apply every
// migration whose target is higher than the stored version.
const currentSchemaVersion = 2

// migrations lists every forward-only schema migration in order. The index
// doesn't matter; we use target versions to decide what to run. A migration
// runs inside a transaction and is responsible for bumping schema_version as
// its last statement.
var migrations = []migration{
	{version: 1, apply: migrateV0ToV1},
	{version: 2, apply: migrateV1ToV2},
}

type migration struct {
	version int
	apply   func(*sql.Tx) error
}

// runMigrations ensures the schema_version table exists, reads the current
// version, and applies each pending migration. Migrations are forward-only —
// there is no downgrade path; rollback means restoring from a backup taken
// before the upgrade.
func runMigrations(d *sql.DB) error {
	if _, err := d.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("create schema_version: %w", err)
	}
	var count int
	if err := d.QueryRow("SELECT COUNT(*) FROM schema_version").Scan(&count); err != nil {
		return fmt.Errorf("count schema_version: %w", err)
	}
	if count == 0 {
		if _, err := d.Exec(`INSERT INTO schema_version (version) VALUES (0)`); err != nil {
			return fmt.Errorf("seed schema_version: %w", err)
		}
	}

	var current int
	if err := d.QueryRow("SELECT version FROM schema_version").Scan(&current); err != nil {
		return fmt.Errorf("read schema_version: %w", err)
	}

	for _, m := range migrations {
		if current >= m.version {
			continue
		}
		tx, err := d.Begin()
		if err != nil {
			return fmt.Errorf("begin migration v%d: %w", m.version, err)
		}
		if err := m.apply(tx); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration v%d: %w", m.version, err)
		}
		if _, err := tx.Exec("UPDATE schema_version SET version = ?", m.version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("bump schema_version to %d: %w", m.version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration v%d: %w", m.version, err)
		}
		current = m.version
	}
	return nil
}

// migrateV0ToV1 establishes the v1 schema:
//   - vendors table (unchanged shape)
//   - statements table with source_format column added to both the row and
//     the primary key (vendor, cve, product_id, source_format)
//
// Fresh databases get the v1 schema created directly. Existing v0 databases
// (pre-source_format) keep all their rows — we rebuild the statements table
// and backfill source_format='csaf' since the only source up to this point
// has been CSAF providers.
func migrateV0ToV1(tx *sql.Tx) error {
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS vendors (
		id          TEXT PRIMARY KEY,
		name        TEXT NOT NULL,
		feed_url    TEXT NOT NULL,
		last_synced TEXT
	)`); err != nil {
		return err
	}

	var exists int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='statements'`).Scan(&exists); err != nil {
		return err
	}

	if exists > 0 {
		if _, err := tx.Exec(`CREATE TABLE statements_v1 (
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
			PRIMARY KEY (vendor, cve, product_id, source_format)
		)`); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO statements_v1
			(vendor, cve, product_id, base_id, version, id_type, status, justification, updated, source_format)
			SELECT vendor, cve, product_id, base_id, version, id_type, status, justification, updated, 'csaf'
			FROM statements`); err != nil {
			return err
		}
		if _, err := tx.Exec(`DROP TABLE statements`); err != nil {
			return err
		}
		if _, err := tx.Exec(`ALTER TABLE statements_v1 RENAME TO statements`); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(`CREATE TABLE statements (
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
			PRIMARY KEY (vendor, cve, product_id, source_format)
		)`); err != nil {
			return err
		}
	}

	for _, idx := range []string{
		`CREATE INDEX IF NOT EXISTS idx_statements_cve ON statements(cve)`,
		`CREATE INDEX IF NOT EXISTS idx_statements_base_id ON statements(base_id)`,
		`CREATE INDEX IF NOT EXISTS idx_statements_source ON statements(source_format)`,
	} {
		if _, err := tx.Exec(idx); err != nil {
			return err
		}
	}
	return nil
}

// migrateV1ToV2 adds the product_aliases table used by the translation layer.
// Each row maps a (vendor, source) identifier to an equivalent (target)
// identifier — e.g. a Red Hat repository_id to its CPE. The table is keyed
// bidirectionally so we can answer both "what CPE does this repo_id map to?"
// and (later) "what repos map to this CPE?".
//
// Purely additive migration — no existing data is touched.
func migrateV1ToV2(tx *sql.Tx) error {
	for _, ddl := range []string{
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
		`CREATE INDEX IF NOT EXISTS idx_aliases_source ON product_aliases(vendor, source_ns, source_id)`,
		`CREATE INDEX IF NOT EXISTS idx_aliases_target ON product_aliases(vendor, target_ns, target_id)`,
	} {
		if _, err := tx.Exec(ddl); err != nil {
			return err
		}
	}
	return nil
}
