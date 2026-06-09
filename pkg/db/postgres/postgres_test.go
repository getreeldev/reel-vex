package postgres

import (
	"os"
	"testing"

	"github.com/getreeldev/reel-vex/pkg/db"
)

// TestPG exercises the Postgres backend against a real server. It is skipped
// unless REEL_VEX_TEST_PG_DSN is set, so the default `go test ./...` (no Docker)
// stays green. Run locally/CI with:
//
//	REEL_VEX_TEST_PG_DSN='postgres://user:pass@localhost:5432/db?sslmode=disable' \
//	  go test -run TestPG ./pkg/db/postgres/
//
// It validates the dialect ports that the dry-run flagged: ANY-array IN lists,
// the IS DISTINCT FROM conditional-upsert skip, the scope gate, nullable scans,
// and the migration set (including the covering index).
func TestPG(t *testing.T) {
	dsn := os.Getenv("REEL_VEX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set REEL_VEX_TEST_PG_DSN to run the Postgres backend test")
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()

	// Clean slate (Open ran migrations; wipe rows so reruns are deterministic).
	if _, err := d.pool.Exec(t.Context(), `TRUNCATE statements, vendors, product_aliases, adapter_state`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	// Vendor + adapter_state watermark round-trips.
	if err := d.UpsertVendor("redhat", "Red Hat"); err != nil {
		t.Fatalf("UpsertVendor: %v", err)
	}
	if err := d.UpsertAdapterState("redhat", "https://example/feed", "2026-06-01T00:00:00Z"); err != nil {
		t.Fatalf("UpsertAdapterState: %v", err)
	}
	if ls, err := d.AdapterLastSynced("redhat"); err != nil || ls != "2026-06-01T00:00:00Z" {
		t.Fatalf("AdapterLastSynced = %q, %v", ls, err)
	}
	if _, err := d.LastIngestAt(); err != nil {
		t.Fatalf("LastIngestAt: %v", err)
	}

	// Statements: one plain, one with empty version/justification (NULL path),
	// one product-scoped (Rancher-style) to exercise the scope gate.
	stmts := []db.Statement{
		{Vendor: "redhat", CVE: "CVE-2024-0001", ProductID: "pkg:rpm/redhat/bash", BaseID: "pkg:rpm/redhat/bash", Version: "5.1", IDType: "purl", Status: "not_affected", Justification: "vulnerable_code_not_present", Updated: "2026-06-01T00:00:00Z", SourceFormat: "csaf"},
		{Vendor: "redhat", CVE: "CVE-2024-0002", ProductID: "pkg:rpm/redhat/curl", BaseID: "pkg:rpm/redhat/curl", IDType: "purl", Status: "fixed", Updated: "2026-06-01T00:00:00Z", SourceFormat: "csaf"},
		{Vendor: "rancher", CVE: "CVE-2024-0001", ProductID: "pkg:rpm/redhat/bash", BaseID: "pkg:rpm/redhat/bash", IDType: "purl", Status: "not_affected", Justification: "inline_mitigations_already_exist", Updated: "2026-06-01T00:00:00Z", SourceFormat: "openvex", Scope: "pkg:oci/rancher/some-image"},
	}
	if err := d.BulkInsert(stmts); err != nil {
		t.Fatalf("BulkInsert: %v", err)
	}

	// CVE query (ANY-array IN list). Unscoped query: the scoped Rancher row must
	// be withheld, so only the redhat CVE-0001 row comes back.
	got, err := d.QueryStatements(db.QueryFilters{CVEs: []string{"CVE-2024-0001"}})
	if err != nil {
		t.Fatalf("QueryStatements cve: %v", err)
	}
	if len(got) != 1 || got[0].Vendor != "redhat" {
		t.Fatalf("scope gate (no scope): want 1 redhat row, got %d: %+v", len(got), got)
	}
	if got[0].Justification != "vulnerable_code_not_present" {
		t.Fatalf("nullable scan: justification = %q", got[0].Justification)
	}

	// Naming the scope reveals the scoped row too (2 rows now).
	got, err = d.QueryStatements(db.QueryFilters{CVEs: []string{"CVE-2024-0001"}, Scopes: []string{"pkg:oci/rancher/some-image"}})
	if err != nil {
		t.Fatalf("QueryStatements scoped: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("scope gate (with scope): want 2 rows, got %d", len(got))
	}

	// Broad mode (base_id, no CVE) + vendor filter.
	got, err = d.QueryStatements(db.QueryFilters{ProductBaseIDs: []string{"pkg:rpm/redhat/bash", "pkg:rpm/redhat/curl"}, Vendors: []string{"redhat"}})
	if err != nil {
		t.Fatalf("QueryStatements broad: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("broad mode: want 2 redhat rows, got %d", len(got))
	}

	// Conditional-upsert skip: re-inserting the SAME verdict with a newer
	// `updated` must NOT rewrite the row (IS DISTINCT FROM => WHERE false), so
	// `updated` stays the original value.
	same := stmts[1]
	same.Updated = "2026-12-31T00:00:00Z"
	if err := d.BulkInsert([]db.Statement{same}); err != nil {
		t.Fatalf("BulkInsert no-op: %v", err)
	}
	got, _ = d.QueryStatements(db.QueryFilters{CVEs: []string{"CVE-2024-0002"}})
	if len(got) != 1 || got[0].Updated != "2026-06-01T00:00:00Z" {
		t.Fatalf("conditional upsert should have skipped; updated = %q", got[0].Updated)
	}

	// A real verdict change DOES update.
	changed := stmts[1]
	changed.Status = "affected"
	changed.Updated = "2026-12-31T00:00:00Z"
	if err := d.BulkInsert([]db.Statement{changed}); err != nil {
		t.Fatalf("BulkInsert change: %v", err)
	}
	got, _ = d.QueryStatements(db.QueryFilters{CVEs: []string{"CVE-2024-0002"}})
	if got[0].Status != "affected" || got[0].Updated != "2026-12-31T00:00:00Z" {
		t.Fatalf("verdict change not applied: %+v", got[0])
	}

	// Aliases. The bulk load goes through COPY + a set-based upsert (like
	// BulkInsert), so exercise the multi-row path, within-batch duplicate-PK
	// dedup (DISTINCT ON — a single statement can't touch the same conflict
	// target twice), and the re-upsert (ON CONFLICT) path — not just one row.
	if err := d.BulkUpsertAliases([]db.Alias{
		{Vendor: "redhat", SourceNS: "repo", SourceID: "rhel-9", TargetNS: "cpe", TargetID: "cpe:/o:redhat:9", Updated: "2026-06-01T00:00:00Z"},
		{Vendor: "redhat", SourceNS: "repo", SourceID: "rhel-8", TargetNS: "cpe", TargetID: "cpe:/o:redhat:8", Updated: "2026-06-01T00:00:00Z"},
		// Duplicate PK within the same batch (later updated value should win via ctid DESC).
		{Vendor: "redhat", SourceNS: "repo", SourceID: "rhel-9", TargetNS: "cpe", TargetID: "cpe:/o:redhat:9", Updated: "2026-06-02T00:00:00Z"},
	}); err != nil {
		t.Fatalf("BulkUpsertAliases (multi/dup): %v", err)
	}
	if tgts, err := d.LookupAliases("repo", "rhel-9", "cpe"); err != nil || len(tgts) != 1 {
		t.Fatalf("LookupAliases rhel-9 = %v, %v", tgts, err)
	}
	if n, err := d.AliasCount(); err != nil || n != 2 {
		t.Fatalf("AliasCount = %d, %v; want 2 (the within-batch duplicate must collapse)", n, err)
	}

	// Re-upsert an existing PK: row count is unchanged, updated is refreshed.
	if err := d.BulkUpsertAliases([]db.Alias{
		{Vendor: "redhat", SourceNS: "repo", SourceID: "rhel-9", TargetNS: "cpe", TargetID: "cpe:/o:redhat:9", Updated: "2026-07-01T00:00:00Z"},
	}); err != nil {
		t.Fatalf("BulkUpsertAliases (re-upsert): %v", err)
	}
	if n, err := d.AliasCount(); err != nil || n != 2 {
		t.Fatalf("AliasCount after re-upsert = %d, %v; want 2 (no new row on conflict)", n, err)
	}

	// Stats.
	s, err := d.RefreshStats()
	if err != nil {
		t.Fatalf("RefreshStats: %v", err)
	}
	if s.Statements < 2 || s.Vendors < 1 || s.Aliases != 2 {
		t.Fatalf("Stats looks wrong: %+v", s)
	}

	// Covering index is built post-ingest (not in the migration). EnsureCoveringIndex
	// creates it, and is idempotent on a second call.
	if err := d.EnsureCoveringIndex(); err != nil {
		t.Fatalf("EnsureCoveringIndex: %v", err)
	}
	var idxExists bool
	if err := d.pool.QueryRow(t.Context(),
		`SELECT EXISTS(SELECT 1 FROM pg_indexes WHERE indexname = 'idx_statements_broad')`).Scan(&idxExists); err != nil {
		t.Fatalf("index existence check: %v", err)
	}
	if !idxExists {
		t.Fatal("EnsureCoveringIndex did not create idx_statements_broad")
	}
	if err := d.EnsureCoveringIndex(); err != nil {
		t.Fatalf("EnsureCoveringIndex (idempotent): %v", err)
	}
}
