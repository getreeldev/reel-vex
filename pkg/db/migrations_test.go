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
	if v != 1 {
		t.Fatalf("schema_version: got %d, want 1", v)
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
	if v != 1 {
		t.Fatalf("reopen schema_version: got %d, want 1", v)
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
	if v != 1 {
		t.Fatalf("schema_version: got %d, want 1", v)
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
