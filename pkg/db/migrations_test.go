package db

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// TestMigrateV0ToV1_PreservesData is the data-preservation guard. A user's
// existing SQLite DB (v0 schema, no schema_version table) gets opened by the
// new binary; every row must survive the migration, source_format must be
// backfilled to 'csaf', and the schema_version must advance to 1.
func TestMigrateV0ToV1_PreservesData(t *testing.T) {
	dbPath := t.TempDir() + "/legacy.db"

	// Recreate the pre-Phase-1 schema exactly.
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, ddl := range []string{
		`CREATE TABLE vendors (
			id TEXT PRIMARY KEY, name TEXT NOT NULL, feed_url TEXT NOT NULL, last_synced TEXT
		)`,
		`CREATE TABLE statements (
			vendor TEXT NOT NULL, cve TEXT NOT NULL, product_id TEXT NOT NULL,
			base_id TEXT NOT NULL, version TEXT, id_type TEXT NOT NULL,
			status TEXT NOT NULL, justification TEXT, updated TEXT NOT NULL,
			PRIMARY KEY (vendor, cve, product_id)
		)`,
		`CREATE INDEX idx_statements_cve ON statements(cve)`,
		`CREATE INDEX idx_statements_base_id ON statements(base_id)`,
		`INSERT INTO vendors VALUES ('redhat', 'Red Hat', 'https://example/feed', '2024-07-01T00:00:00Z')`,
		`INSERT INTO statements VALUES ('redhat', 'CVE-2024-1111', 'pkg:rpm/redhat/openssl@3.0', 'pkg:rpm/redhat/openssl', '3.0', 'purl', 'fixed', NULL, '2024-07-01T00:00:00Z')`,
		`INSERT INTO statements VALUES ('redhat', 'CVE-2024-2222', 'cpe:/o:redhat:enterprise_linux:8', 'cpe:/o:redhat:enterprise_linux:8', NULL, 'cpe', 'affected', NULL, '2024-07-02T00:00:00Z')`,
	} {
		if _, err := raw.Exec(ddl); err != nil {
			t.Fatalf("prepare legacy schema: %v\nSQL: %s", err, ddl)
		}
	}
	raw.Close()

	// Open via the new code path — triggers the migration.
	d, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()

	// schema_version must be 1.
	var v int
	if err := d.db.QueryRow("SELECT version FROM schema_version").Scan(&v); err != nil {
		t.Fatalf("read schema_version: %v", err)
	}
	if v != currentSchemaVersion {
		t.Fatalf("schema_version: got %d, want %d", v, currentSchemaVersion)
	}

	// Statement count unchanged.
	stats, err := d.Stats()
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.Statements != 2 {
		t.Fatalf("statements count: got %d, want 2", stats.Statements)
	}
	if stats.Vendors != 1 {
		t.Fatalf("vendor count: got %d, want 1", stats.Vendors)
	}

	// Pre-existing rows come back with source_format='csaf' backfilled.
	rows, err := d.QueryByCVE("CVE-2024-1111")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("CVE-2024-1111: got %d statements, want 1", len(rows))
	}
	if rows[0].SourceFormat != "csaf" {
		t.Errorf("source_format backfill: got %q, want csaf", rows[0].SourceFormat)
	}
	if rows[0].ProductID != "pkg:rpm/redhat/openssl@3.0" {
		t.Errorf("product_id preserved: got %q", rows[0].ProductID)
	}

	// Running Open again is a no-op; rows remain intact.
	d.Close()
	d2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer d2.Close()
	if err := d2.db.QueryRow("SELECT version FROM schema_version").Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != currentSchemaVersion {
		t.Fatalf("reopen schema_version: got %d, want %d", v, currentSchemaVersion)
	}
	stats2, _ := d2.Stats()
	if stats2.Statements != 2 {
		t.Fatalf("reopen statements count: got %d, want 2", stats2.Statements)
	}
}

// TestMigrateV0ToV1_FreshDB verifies that a brand-new DB comes up with v1
// schema directly — no statements table to rebuild, just create.
func TestMigrateV0ToV1_FreshDB(t *testing.T) {
	dbPath := t.TempDir() + "/fresh.db"
	d, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()

	var v int
	if err := d.db.QueryRow("SELECT version FROM schema_version").Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != currentSchemaVersion {
		t.Fatalf("schema_version: got %d, want %d", v, currentSchemaVersion)
	}

	// Inserting a statement with the v1 PK (source_format in key) must work,
	// and two rows differing only by source_format must coexist (Phase 5
	// prerequisite).
	stmts := []Statement{
		{Vendor: "redhat", CVE: "CVE-1", ProductID: "cpe:/o:redhat:enterprise_linux:8", IDType: "cpe", Status: "affected", Updated: "2024-01-01T00:00:00Z", SourceFormat: "csaf"},
		{Vendor: "redhat", CVE: "CVE-1", ProductID: "cpe:/o:redhat:enterprise_linux:8", IDType: "cpe", Status: "affected", Updated: "2024-01-01T00:00:00Z", SourceFormat: "oval"},
	}
	if err := d.BulkInsert(stmts); err != nil {
		t.Fatalf("BulkInsert: %v", err)
	}
	rows, err := d.QueryByCVE("CVE-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("coexistence: got %d rows, want 2 (csaf + oval)", len(rows))
	}
}

// TestMigrateV1ToV2_AddsAliasesTable confirms the v1 → v2 migration adds
// product_aliases without touching existing statement rows. The test
// drives from v1 all the way to the current schema, so v2 → v3 is also
// exercised end-to-end: v1 statements stay intact, product_aliases
// starts empty, and vendors loses its feed_url/last_synced columns.
func TestMigrateV1ToV2_AddsAliasesTable(t *testing.T) {
	dbPath := t.TempDir() + "/v1-to-v2.db"

	// Produce a v1 database with data, then simulate pre-v2 by setting
	// schema_version back to 1, dropping product_aliases, dropping
	// adapter_state, and re-adding the v1-era vendors columns that later
	// migrations removed.
	d, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.BulkInsert([]Statement{
		{Vendor: "redhat", CVE: "CVE-1", ProductID: "cpe:/o:redhat:rhel:8", IDType: "cpe", Status: "affected", Updated: "2024-01-01T00:00:00Z", SourceFormat: "csaf"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.db.Exec("UPDATE schema_version SET version = 1"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.db.Exec("DROP TABLE product_aliases"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.db.Exec("DROP TABLE adapter_state"); err != nil {
		t.Fatal(err)
	}
	// Re-add the v1-era vendors columns that later migrations dropped.
	for _, sql := range []string{
		`ALTER TABLE vendors ADD COLUMN feed_url TEXT`,
		`ALTER TABLE vendors ADD COLUMN last_synced TEXT`,
	} {
		if _, err := d.db.Exec(sql); err != nil {
			t.Fatalf("rebuild v1 vendors shape: %v", err)
		}
	}
	d.Close()

	// Re-open triggers the v1 → v2 → v3 migrations in sequence.
	d2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer d2.Close()

	var v int
	if err := d2.db.QueryRow("SELECT version FROM schema_version").Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != currentSchemaVersion {
		t.Fatalf("schema_version after migrations: got %d, want %d", v, currentSchemaVersion)
	}

	n, err := d2.AliasCount()
	if err != nil {
		t.Fatalf("AliasCount: %v", err)
	}
	if n != 0 {
		t.Errorf("fresh aliases table: got %d rows, want 0", n)
	}

	// Statement data preserved across the migration.
	stats, _ := d2.Stats()
	if stats.Statements != 1 {
		t.Errorf("statements preserved: got %d, want 1", stats.Statements)
	}
}

// TestMigrateV2ToV3_CarryForward confirms the v2 → v3 migration creates
// adapter_state and copies existing per-adapter watermarks + feed URLs
// into it, then drops those columns from vendors. This is the workflow
// Phase 5 will trigger on the hosted deployment's first boot.
func TestMigrateV2ToV3_CarryForward(t *testing.T) {
	dbPath := t.TempDir() + "/v2-to-v3.db"

	// Build a v2-shaped DB with a vendor row carrying feed_url + last_synced.
	d, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.db.Exec("UPDATE schema_version SET version = 2"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.db.Exec("DROP TABLE adapter_state"); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		`ALTER TABLE vendors ADD COLUMN feed_url TEXT`,
		`ALTER TABLE vendors ADD COLUMN last_synced TEXT`,
		`INSERT INTO vendors (id, name, feed_url, last_synced) VALUES ('redhat', 'Red Hat', 'https://example/feed', '2024-07-01T00:00:00Z')`,
		`INSERT INTO vendors (id, name, feed_url, last_synced) VALUES ('suse', 'SUSE', 'https://example/suse', NULL)`,
	} {
		if _, err := d.db.Exec(sql); err != nil {
			t.Fatalf("rebuild v2 state: %v\nSQL: %s", err, sql)
		}
	}
	d.Close()

	// Re-open runs v2 → v3.
	d2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer d2.Close()

	// Watermark carried forward for redhat.
	lastSynced, err := d2.AdapterLastSynced("redhat")
	if err != nil {
		t.Fatal(err)
	}
	if lastSynced != "2024-07-01T00:00:00Z" {
		t.Errorf("adapter_state carry-forward for redhat: got %q, want 2024-07-01T00:00:00Z", lastSynced)
	}

	// suse had NULL last_synced; should carry forward as empty.
	suseSynced, err := d2.AdapterLastSynced("suse")
	if err != nil {
		t.Fatal(err)
	}
	if suseSynced != "" {
		t.Errorf("adapter_state carry-forward for suse (NULL): got %q, want empty", suseSynced)
	}

	// vendors table should no longer have feed_url or last_synced columns.
	if _, err := d2.db.Exec("SELECT feed_url FROM vendors LIMIT 1"); err == nil {
		t.Error("expected feed_url column dropped from vendors after v3")
	}
	if _, err := d2.db.Exec("SELECT last_synced FROM vendors LIMIT 1"); err == nil {
		t.Error("expected last_synced column dropped from vendors after v3")
	}
}
