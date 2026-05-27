package db

import "testing"

func upsertTestDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(t.TempDir() + "/upsert.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// oneRow fetches the single statement for a CVE and fails otherwise.
func oneRow(t *testing.T, d *DB, cve string) Statement {
	t.Helper()
	rows, err := d.QueryStatements(QueryFilters{CVEs: []string{cve}})
	if err != nil {
		t.Fatalf("QueryStatements(%s): %v", cve, err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 row for %s, got %d", cve, len(rows))
	}
	return rows[0]
}

// TestConditionalUpsert_SkipsTimestampOnlyChange is the property that makes a
// no-op feed re-walk cheap: a re-ingest that bumps only `updated` (same verdict)
// must NOT rewrite the row, so `updated` stays at the last *material* change.
func TestConditionalUpsert_SkipsTimestampOnlyChange(t *testing.T) {
	d := upsertTestDB(t)
	const cve = "CVE-2024-0001"
	base := Statement{Vendor: "ubuntu", CVE: cve, ProductID: "pkg:deb/ubuntu/openssl", BaseID: "pkg:deb/ubuntu/openssl", IDType: "purl", Status: "affected", Updated: "2024-01-01T00:00:00Z", SourceFormat: "openvex"}
	if err := d.BulkInsert([]Statement{base}); err != nil {
		t.Fatal(err)
	}
	bumped := base
	bumped.Updated = "2024-06-01T00:00:00Z" // same verdict, newer timestamp
	if err := d.BulkInsert([]Statement{bumped}); err != nil {
		t.Fatal(err)
	}
	if got := oneRow(t, d, cve); got.Updated != "2024-01-01T00:00:00Z" {
		t.Errorf("timestamp-only change rewrote the row: updated=%q, want the original (skip)", got.Updated)
	}
}

// TestConditionalUpsert_RewritesVerdictChange: a real verdict change is written,
// carrying its new timestamp.
func TestConditionalUpsert_RewritesVerdictChange(t *testing.T) {
	d := upsertTestDB(t)
	const cve = "CVE-2024-0002"
	base := Statement{Vendor: "ubuntu", CVE: cve, ProductID: "pkg:deb/ubuntu/curl", BaseID: "pkg:deb/ubuntu/curl", IDType: "purl", Status: "affected", Updated: "2024-01-01T00:00:00Z", SourceFormat: "openvex"}
	if err := d.BulkInsert([]Statement{base}); err != nil {
		t.Fatal(err)
	}
	changed := base
	changed.Status = "fixed"
	changed.Updated = "2024-06-01T00:00:00Z"
	if err := d.BulkInsert([]Statement{changed}); err != nil {
		t.Fatal(err)
	}
	got := oneRow(t, d, cve)
	if got.Status != "fixed" || got.Updated != "2024-06-01T00:00:00Z" {
		t.Errorf("verdict change not applied: status=%q updated=%q, want fixed / 2024-06-01", got.Status, got.Updated)
	}
}

// TestConditionalUpsert_NullSafety guards the sharp edge: NULL<->value
// transitions on a nullable column (version) must be detected. A naive `!=`
// would miss these (NULL comparisons yield NULL, never true), silently keeping
// a stale value — both directions are exercised.
func TestConditionalUpsert_NullSafety(t *testing.T) {
	d := upsertTestDB(t)

	// NULL -> value.
	const cveA = "CVE-2024-0003"
	a := Statement{Vendor: "ubuntu", CVE: cveA, ProductID: "pkg:deb/ubuntu/a", BaseID: "pkg:deb/ubuntu/a", IDType: "purl", Status: "affected", Version: "", Updated: "2024-01-01T00:00:00Z", SourceFormat: "openvex"}
	if err := d.BulkInsert([]Statement{a}); err != nil {
		t.Fatal(err)
	}
	a2 := a
	a2.Version = "1.2.3"
	a2.Updated = "2024-06-01T00:00:00Z"
	if err := d.BulkInsert([]Statement{a2}); err != nil {
		t.Fatal(err)
	}
	if got := oneRow(t, d, cveA); got.Version != "1.2.3" {
		t.Errorf("NULL->value not detected: version=%q, want 1.2.3", got.Version)
	}

	// value -> NULL.
	const cveB = "CVE-2024-0004"
	b := Statement{Vendor: "ubuntu", CVE: cveB, ProductID: "pkg:deb/ubuntu/b", BaseID: "pkg:deb/ubuntu/b", IDType: "purl", Status: "affected", Version: "1.2.3", Updated: "2024-01-01T00:00:00Z", SourceFormat: "openvex"}
	if err := d.BulkInsert([]Statement{b}); err != nil {
		t.Fatal(err)
	}
	b2 := b
	b2.Version = ""
	b2.Updated = "2024-06-01T00:00:00Z"
	if err := d.BulkInsert([]Statement{b2}); err != nil {
		t.Fatal(err)
	}
	if got := oneRow(t, d, cveB); got.Version != "" {
		t.Errorf("value->NULL not detected: version=%q, want empty", got.Version)
	}
}
