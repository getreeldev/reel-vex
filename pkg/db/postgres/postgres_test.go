package postgres

import (
	"context"
	"fmt"
	"math"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

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
// the IS DISTINCT FROM conditional-upsert skip, the scope gate, the row scan,
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

	// Statements: one plain, one with no versions or justification (empty
	// list and empty string), one product-scoped (Rancher-style) to exercise the scope gate.
	stmts := []db.Statement{
		{Vendor: "redhat", CVE: "CVE-2024-0001", ProductID: "pkg:rpm/redhat/bash", BaseID: "pkg:rpm/redhat/bash", Versions: []string{"5.1"}, IDType: "purl", Status: "not_affected", Justification: "vulnerable_code_not_present", Updated: "2026-06-01T00:00:00Z", SourceFormat: "csaf"},
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
		t.Fatalf("scan: justification = %q", got[0].Justification)
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

	// A changed version list DOES update, in place.
	changed := stmts[1]
	changed.Versions = []string{"8.0"}
	changed.Updated = "2026-12-31T00:00:00Z"
	if err := d.BulkInsert([]db.Statement{changed}); err != nil {
		t.Fatalf("BulkInsert change: %v", err)
	}
	got, _ = d.QueryStatements(db.QueryFilters{CVEs: []string{"CVE-2024-0002"}})
	if len(got) != 1 || !slices.Equal(got[0].Versions, []string{"8.0"}) || got[0].Updated != "2026-12-31T00:00:00Z" {
		t.Fatalf("version change not applied: %+v", got)
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

	testSweeps(t, d, dsn)
}

// sweepRow builds a statement owned by adapter (empty = NULL owner). Every row
// shares vendor redhat and source_format csaf, so two adapters' rows differ
// only by owner — the case a sweep must tell apart.
func sweepRow(adapter, cve, product, scope string) db.Statement {
	return db.Statement{Vendor: "redhat", CVE: cve, ProductID: product, BaseID: product, IDType: "purl",
		Status: "not_affected", Updated: "2026-06-01T00:00:00Z", SourceFormat: "csaf", Scope: scope, AdapterID: adapter}
}

// testSweeps runs the removal subtests: sweep, replace (scoped sweep),
// withdraw, the session lifecycle, the owner column and migration v2.
func testSweeps(t *testing.T, d *DB, dsn string) {
	ctx := t.Context()
	reset := func(t *testing.T) {
		t.Helper()
		if _, err := d.pool.Exec(ctx, `TRUNCATE statements`); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		if err := d.ResetSweeps(); err != nil {
			t.Fatalf("ResetSweeps: %v", err)
		}
	}
	insert := func(t *testing.T, rows ...db.Statement) {
		t.Helper()
		if err := d.BulkInsert(rows); err != nil {
			t.Fatalf("BulkInsert: %v", err)
		}
	}
	start := func(t *testing.T, adapter string, keys ...db.StatementKey) {
		t.Helper()
		if err := d.StartSweep(adapter); err != nil {
			t.Fatalf("StartSweep: %v", err)
		}
		if err := d.RecordSeen(adapter, keys); err != nil {
			t.Fatalf("RecordSeen: %v", err)
		}
	}
	// remaining lists every row as "owner|cve|product|scope", owner "-" for NULL.
	remaining := func(t *testing.T) map[string]bool {
		t.Helper()
		rows, err := d.pool.Query(ctx, `SELECT coalesce(adapter_id, '-') || '|' || cve || '|' || product_id || '|' || scope FROM statements`)
		if err != nil {
			t.Fatalf("list rows: %v", err)
		}
		got, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatalf("list rows: %v", err)
		}
		out := map[string]bool{}
		for _, r := range got {
			out[r] = true
		}
		return out
	}
	wantRows := func(t *testing.T, want ...string) {
		t.Helper()
		got := remaining(t)
		if len(got) != len(want) {
			t.Fatalf("rows = %v, want %v", got, want)
		}
		for _, w := range want {
			if !got[w] {
				t.Fatalf("rows = %v, missing %q", got, w)
			}
		}
	}
	seenExists := func(t *testing.T, adapter string) bool {
		t.Helper()
		var ok bool
		if err := d.pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, pgx.Identifier{seenTable(adapter)}.Sanitize()).Scan(&ok); err != nil {
			t.Fatalf("seen table lookup: %v", err)
		}
		return ok
	}
	owner := func(t *testing.T, cve, product string) *string {
		t.Helper()
		var o *string
		if err := d.pool.QueryRow(ctx, `SELECT adapter_id FROM statements WHERE cve = $1 AND product_id = $2`, cve, product).Scan(&o); err != nil {
			t.Fatalf("owner: %v", err)
		}
		return o
	}
	// key is the seen key of a sweepRow: not_affected, no justification.
	key := func(cve, product, scope string) db.StatementKey {
		return db.StatementKey{CVE: cve, ProductID: product, Scope: scope, Status: "not_affected"}
	}

	t.Run("sweep all deletes only the owner's unseen rows", func(t *testing.T) {
		reset(t)
		insert(t,
			sweepRow("a", "CVE-1", "p1", ""),
			sweepRow("a", "CVE-1", "p1", "img"), // same key but for scope: unseen
			sweepRow("a", "CVE-1", "p2", ""),
			sweepRow("a", "CVE-2", "p1", ""),
			sweepRow("a", "CVE-9", "p9", ""), // unseen
			sweepRow("b", "CVE-3", "p1", ""), // same vendor+source_format, other adapter
			sweepRow("", "CVE-4", "p1", ""),  // NULL owner
		)
		start(t, "a", key("CVE-1", "p1", ""), key("CVE-1", "p2", ""), key("CVE-2", "p1", ""), key("CVE-2", "p1", ""))
		res, err := d.FinishSweep("a", db.SweepScope{All: true}, 0.5)
		if err != nil {
			t.Fatalf("FinishSweep: %v", err)
		}
		if res != (db.SweepResult{Seen: 4, Owned: 5, Deleted: 2}) {
			t.Fatalf("result = %+v", res)
		}
		wantRows(t, "a|CVE-1|p1|", "a|CVE-1|p2|", "a|CVE-2|p1|", "b|CVE-3|p1|", "-|CVE-4|p1|")
		if seenExists(t, "a") {
			t.Fatal("seen table left after finish")
		}
	})

	t.Run("guard refuses, rolls back and keeps rows", func(t *testing.T) {
		reset(t)
		var rows []db.Statement
		var keys []db.StatementKey
		for i := 0; i < 10; i++ {
			p := fmt.Sprintf("p%d", i)
			rows = append(rows, sweepRow("a", "CVE-1", p, ""))
			if i < 5 {
				keys = append(keys, key("CVE-1", p, ""))
			}
		}
		insert(t, rows...)
		start(t, "a", keys...)
		res, err := d.FinishSweep("a", db.SweepScope{All: true}, 0.3)
		if err != nil {
			t.Fatalf("FinishSweep: %v", err)
		}
		if !res.Refused || res.Seen != 5 || res.Owned != 10 || res.Deleted != 5 || res.Reason == "" {
			t.Fatalf("result = %+v, want a refusal of 5 of 10", res)
		}
		if n := len(remaining(t)); n != 10 {
			t.Fatalf("%d rows after a refused sweep, want 10", n)
		}
		if seenExists(t, "a") {
			t.Fatal("seen table left after refusal")
		}
		// At exactly the limit the sweep runs.
		start(t, "a", keys...)
		res, err = d.FinishSweep("a", db.SweepScope{All: true}, 0.5)
		if err != nil || res.Refused || res.Deleted != 5 {
			t.Fatalf("at the limit: %+v, %v", res, err)
		}
		if n := len(remaining(t)); n != 5 {
			t.Fatalf("%d rows after the sweep, want 5", n)
		}
	})

	t.Run("nothing seen and disabled refuse", func(t *testing.T) {
		reset(t)
		insert(t, sweepRow("a", "CVE-1", "p1", ""))
		start(t, "a")
		res, err := d.FinishSweep("a", db.SweepScope{All: true}, 1)
		if err != nil || res != (db.SweepResult{Refused: true, Reason: "nothing seen"}) {
			t.Fatalf("nothing seen: %+v, %v", res, err)
		}
		if seenExists(t, "a") {
			t.Fatal("seen table left after nothing-seen refusal")
		}
		for _, mf := range []float64{0, -1, math.NaN()} {
			for _, sc := range []db.SweepScope{{All: true}, {CVEs: []string{"CVE-1"}}} {
				start(t, "a", key("CVE-2", "p1", ""), key("CVE-2", "p1", ""))
				res, err := d.FinishSweep("a", sc, mf)
				if err != nil || res != (db.SweepResult{Seen: 2, Refused: true, Reason: "sweep disabled"}) {
					t.Fatalf("disabled (%v, %+v): %+v, %v", mf, sc, res, err)
				}
				if seenExists(t, "a") {
					t.Fatal("seen table left after disabled refusal")
				}
			}
		}
		wantRows(t, "a|CVE-1|p1|")
	})

	t.Run("session errors and abort", func(t *testing.T) {
		reset(t)
		insert(t, sweepRow("a", "CVE-1", "p1", ""))
		if err := d.StartSweep(""); err == nil {
			t.Error("StartSweep(\"\") succeeded")
		}
		if err := d.RecordSeen("", nil); err == nil {
			t.Error("RecordSeen(\"\") succeeded")
		}
		if _, err := d.FinishSweep("", db.SweepScope{All: true}, 1); err == nil {
			t.Error("FinishSweep(\"\") succeeded")
		}
		if err := d.AbortSweep(""); err == nil {
			t.Error("AbortSweep(\"\") succeeded")
		}
		if _, err := d.Withdraw("", []string{"CVE-1"}, 1); err == nil {
			t.Error("Withdraw(\"\") succeeded")
		}
		if err := d.RecordSeen("a", []db.StatementKey{key("CVE-1", "p1", "")}); err == nil {
			t.Error("RecordSeen with no session succeeded")
		}
		if _, err := d.FinishSweep("a", db.SweepScope{All: true}, 1); err == nil {
			t.Error("FinishSweep with no session succeeded")
		}
		if err := d.AbortSweep("a"); err != nil {
			t.Errorf("AbortSweep with no session: %v", err)
		}
		start(t, "a", key("CVE-1", "p2", ""))
		if !seenExists(t, "a") {
			t.Fatal("StartSweep made no seen table")
		}
		if err := d.AbortSweep("a"); err != nil {
			t.Fatalf("AbortSweep: %v", err)
		}
		if seenExists(t, "a") {
			t.Fatal("seen table left after abort")
		}
		if _, err := d.FinishSweep("a", db.SweepScope{All: true}, 1); err == nil {
			t.Error("FinishSweep after abort succeeded")
		}
		wantRows(t, "a|CVE-1|p1|")
	})

	t.Run("an unchanged re-insert keeps the owner, a changed one moves it", func(t *testing.T) {
		reset(t)
		insert(t, sweepRow("a", "CVE-1", "p1", ""))
		insert(t, sweepRow("b", "CVE-1", "p1", ""))
		if o := owner(t, "CVE-1", "p1"); o == nil || *o != "a" {
			t.Fatalf("owner after unchanged re-insert = %v, want a", o)
		}
		changed := sweepRow("b", "CVE-1", "p1", "")
		changed.Versions = []string{"1.0"}
		insert(t, changed)
		if o := owner(t, "CVE-1", "p1"); o == nil || *o != "b" {
			t.Fatalf("owner after changed re-insert = %v, want b", o)
		}
		insert(t, sweepRow("", "CVE-2", "p1", ""))
		if o := owner(t, "CVE-2", "p1"); o != nil {
			t.Fatalf("empty AdapterID stored as %q, want NULL", *o)
		}
	})

	t.Run("scoped sweep replaces only the listed CVEs, with no guard", func(t *testing.T) {
		reset(t)
		insert(t,
			sweepRow("a", "CVE-1", "p1", ""),
			sweepRow("a", "CVE-1", "p2", ""),
			sweepRow("a", "CVE-2", "p1", ""),
			sweepRow("a", "CVE-2", "p2", ""),
			sweepRow("a", "CVE-3", "p1", ""),
			sweepRow("b", "CVE-1", "p3", ""),
			sweepRow("", "CVE-2", "p3", ""),
		)
		start(t, "a", key("CVE-1", "p1", ""))
		// 3 of the 4 rows in scope go: far over 1%, and allowed.
		res, err := d.FinishSweep("a", db.SweepScope{CVEs: []string{"CVE-1", "CVE-2"}}, 0.01)
		if err != nil {
			t.Fatalf("FinishSweep: %v", err)
		}
		if res != (db.SweepResult{Seen: 1, Owned: 4, Deleted: 3}) {
			t.Fatalf("result = %+v", res)
		}
		wantRows(t, "a|CVE-1|p1|", "a|CVE-3|p1|", "b|CVE-1|p3|", "-|CVE-2|p3|")
		if seenExists(t, "a") {
			t.Fatal("seen table left after scoped finish")
		}

		// A refreshed document that emitted nothing: every owned row of its CVE goes.
		start(t, "a")
		res, err = d.FinishSweep("a", db.SweepScope{CVEs: []string{"CVE-3"}}, 0.01)
		if err != nil || res != (db.SweepResult{Owned: 1, Deleted: 1}) {
			t.Fatalf("empty document: %+v, %v", res, err)
		}
		wantRows(t, "a|CVE-1|p1|", "b|CVE-1|p3|", "-|CVE-2|p3|")

		// No refreshed CVEs: nothing to do, not a refusal.
		start(t, "a", key("CVE-9", "p1", ""))
		res, err = d.FinishSweep("a", db.SweepScope{}, 0.5)
		if err != nil || res != (db.SweepResult{Seen: 1}) {
			t.Fatalf("empty CVE list: %+v, %v", res, err)
		}
		if seenExists(t, "a") {
			t.Fatal("seen table left after an empty CVE list")
		}
		wantRows(t, "a|CVE-1|p1|", "b|CVE-1|p3|", "-|CVE-2|p3|")
	})

	t.Run("withdraw deletes only the absent CVEs", func(t *testing.T) {
		reset(t)
		var rows []db.Statement
		for i := 1; i <= 10; i++ {
			rows = append(rows, sweepRow("a", fmt.Sprintf("CVE-%d", i), "p1", ""))
		}
		rows = append(rows,
			sweepRow("a", "CVE-9", "p2", ""),
			sweepRow("b", "CVE-9", "p3", ""),
			sweepRow("", "CVE-10", "p3", ""),
		)
		insert(t, rows...)
		for _, live := range [][]string{nil, {}} {
			res, err := d.Withdraw("a", live, 1)
			if err != nil || !res.Refused || res.Reason != "empty manifest" {
				t.Fatalf("empty manifest: %+v, %v", res, err)
			}
		}
		for _, mf := range []float64{0, math.NaN()} {
			res, err := d.Withdraw("a", []string{"CVE-1"}, mf)
			if err != nil || !res.Refused || res.Reason != "withdraw disabled" {
				t.Fatalf("disabled: %+v, %v", res, err)
			}
		}
		// Nine of ten held CVEs absent: over the fraction, nothing goes.
		res, err := d.Withdraw("a", []string{"CVE-1"}, 0.5)
		if err != nil || !res.Refused || res.HeldCVEs != 10 || res.WithdrawnCVEs != 9 || res.Deleted != 0 {
			t.Fatalf("over the fraction: %+v, %v", res, err)
		}
		if n := len(remaining(t)); n != 13 {
			t.Fatalf("%d rows after a refused withdrawal, want 13", n)
		}

		live := []string{"CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5", "CVE-6", "CVE-7", "CVE-8", "CVE-8", "CVE-1", "CVE-99"}
		res, err = d.Withdraw("a", live, 0.2)
		if err != nil {
			t.Fatalf("Withdraw: %v", err)
		}
		if res != (db.WithdrawResult{Live: 9, HeldCVEs: 10, WithdrawnCVEs: 2, Deleted: 3}) {
			t.Fatalf("result = %+v", res)
		}
		got := remaining(t)
		if len(got) != 10 || got["a|CVE-9|p1|"] || got["a|CVE-9|p2|"] || got["a|CVE-10|p1|"] ||
			!got["b|CVE-9|p3|"] || !got["-|CVE-10|p3|"] || !got["a|CVE-8|p1|"] {
			t.Fatalf("rows after withdrawal = %v", got)
		}
	})

	t.Run("reset drops seen tables and keeps a near miss", func(t *testing.T) {
		reset(t)
		start(t, "a", key("CVE-1", "p1", ""))
		start(t, "b")
		for _, q := range []string{
			`CREATE UNLOGGED TABLE sweep_seen_orphan (cve TEXT)`,
			`CREATE TABLE sweepxseenxkeep (cve TEXT)`,
		} {
			if _, err := d.pool.Exec(ctx, q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		defer d.pool.Exec(ctx, `DROP TABLE IF EXISTS sweepxseenxkeep`)
		if err := d.ResetSweeps(); err != nil {
			t.Fatalf("ResetSweeps: %v", err)
		}
		var left []string
		rows, err := d.pool.Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname = current_schema() AND tablename LIKE 'sweep%' ORDER BY 1`)
		if err != nil {
			t.Fatalf("list tables: %v", err)
		}
		if left, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
			t.Fatalf("list tables: %v", err)
		}
		if len(left) != 1 || left[0] != "sweepxseenxkeep" {
			t.Fatalf("tables after reset = %v, want only sweepxseenxkeep", left)
		}
		if err := d.RecordSeen("a", []db.StatementKey{key("CVE-1", "p1", "")}); err == nil {
			t.Fatal("RecordSeen after reset succeeded: the session should have ended")
		}
	})

	// seedPlan inserts 3,000 rows owned by a (300 CVEs x 10 products) and
	// 27,000 owned by b on the same CVEs, and returns 90% of a's keys. a is the
	// minority owner of shared CVEs, as one adapter is in production, so the
	// adapter index is the cheap way to its rows. Below ~1,000 owned rows the
	// planner scans for the delete instead of a Tid Scan: do not shrink it.
	seedPlan := func(t *testing.T) []db.StatementKey {
		t.Helper()
		var rows []db.Statement
		var keys []db.StatementKey
		for i := 0; i < 3000; i++ {
			cve, p := fmt.Sprintf("CVE-%d", i/10), fmt.Sprintf("p%d", i%10)
			rows = append(rows, sweepRow("a", cve, p, ""))
			if i%10 != 0 {
				keys = append(keys, key(cve, p, ""))
			}
		}
		for i := 0; i < 27000; i++ {
			rows = append(rows, sweepRow("b", fmt.Sprintf("CVE-%d", i/90), fmt.Sprintf("q%d", i%90), ""))
		}
		insert(t, rows...)
		if _, err := d.pool.Exec(ctx, `ANALYZE statements`); err != nil {
			t.Fatalf("analyze: %v", err)
		}
		return keys
	}

	t.Run("sweep plan reads the owned rows once and deletes by ctid", func(t *testing.T) {
		reset(t)
		start(t, "a", seedPlan(t)...)
		if _, err := d.pool.Exec(ctx, `ANALYZE `+pgx.Identifier{seenTable("a")}.Sanitize()); err != nil {
			t.Fatalf("analyze seen: %v", err)
		}
		all := explain(t, d, sweepSQL(seenTable("a"), false), "a")
		t.Logf("whole-adapter sweep plan:\n%s", all)
		assertSweepPlan(t, all)
		scoped := explain(t, d, sweepSQL(seenTable("a"), true), "a", []string{"CVE-1", "CVE-2"})
		t.Logf("scoped sweep plan:\n%s", scoped)
		// Which index serves `cve = ANY` (this one or idx_statements_cve) is a
		// cost coin-flip at test scale, so only the shape is asserted.
		assertSweepPlan(t, scoped)

		res, err := d.FinishSweep("a", db.SweepScope{All: true}, 0.2)
		if err != nil || res != (db.SweepResult{Seen: 2700, Owned: 3000, Deleted: 300}) {
			t.Fatalf("FinishSweep: %+v, %v", res, err)
		}
		if n := len(remaining(t)); n != 29700 {
			t.Fatalf("%d rows after the sweep, want 29,700", n)
		}
	})

	t.Run("withdraw plan reads held CVEs from the index and anti-joins the manifest", func(t *testing.T) {
		reset(t)
		seedPlan(t)
		tx, err := d.pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `CREATE TEMP TABLE _live_cves (cve TEXT NOT NULL) ON COMMIT DROP`); err != nil {
			t.Fatalf("create: %v", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO _live_cves SELECT 'CVE-' || g FROM generate_series(0, 250) g`); err != nil {
			t.Fatalf("load: %v", err)
		}
		if _, err := tx.Exec(ctx, `ANALYZE _live_cves`); err != nil {
			t.Fatalf("analyze: %v", err)
		}
		plan := explainTx(t, tx, withdrawSQL, "a")
		t.Logf("withdraw plan:\n%s", plan)
		if !strings.Contains(plan, "Anti Join") || strings.Contains(plan, "SubPlan") {
			t.Errorf("withdraw plan: want an anti join and no SubPlan:\n%s", plan)
		}
		if !strings.Contains(plan, "idx_statements_adapter") || strings.Contains(plan, "Seq Scan on statements") {
			t.Errorf("withdraw plan: want held read from idx_statements_adapter, not a seq scan:\n%s", plan)
		}
	})

	// versionsOf reads one row's stored version list and updated.
	versionsOf := func(t *testing.T, cve, product, status string) ([]string, string) {
		t.Helper()
		var vs []string
		var updated string
		if err := d.pool.QueryRow(ctx, `SELECT versions, updated FROM statements WHERE cve = $1 AND product_id = $2 AND status = $3`,
			cve, product, status).Scan(&vs, &updated); err != nil {
			t.Fatalf("versions: %v", err)
		}
		return vs, updated
	}

	t.Run("one row per verdict: two statuses of one key coexist", func(t *testing.T) {
		reset(t)
		affected := sweepRow("a", "CVE-1", "p1", "")
		affected.Status = "affected"
		mitigated := sweepRow("a", "CVE-1", "p1", "")
		mitigated.Justification = "inline_mitigations_already_exist"
		insert(t, sweepRow("a", "CVE-1", "p1", ""), affected, mitigated)
		got, err := d.QueryStatements(db.QueryFilters{CVEs: []string{"CVE-1"}})
		if err != nil || len(got) != 3 {
			t.Fatalf("QueryStatements = %+v, %v; want three verdicts", got, err)
		}
	})

	t.Run("two rows differing only by stream coexist", func(t *testing.T) {
		reset(t)
		rhel9 := sweepRow("a", "CVE-1", "p1", "")
		rhel9.Stream = "rhel-9"
		insert(t, sweepRow("a", "CVE-1", "p1", ""), rhel9)
		var streams []string
		if err := d.pool.QueryRow(ctx, `SELECT array_agg(stream ORDER BY stream) FROM statements WHERE cve = 'CVE-1'`).Scan(&streams); err != nil {
			t.Fatalf("streams: %v", err)
		}
		if !slices.Equal(streams, []string{"", "rhel-9"}) {
			t.Fatalf("streams = %q, want both", streams)
		}
	})

	t.Run("version lists are normalised and guarded", func(t *testing.T) {
		reset(t)
		first := sweepRow("a", "CVE-1", "p1", "")
		first.Versions = []string{"2.0", "1.0", "2.0", ""}
		insert(t, first)
		if vs, _ := versionsOf(t, "CVE-1", "p1", "not_affected"); !slices.Equal(vs, []string{"1.0", "2.0"}) {
			t.Fatalf("stored versions = %q, want [1.0 2.0]", vs)
		}
		// The same list in another order with a newer timestamp and another
		// writer: not a change, so nothing is rewritten.
		same := sweepRow("b", "CVE-1", "p1", "")
		same.Versions = []string{"2.0", "1.0"}
		same.Updated = "2026-12-31T00:00:00Z"
		insert(t, same)
		if _, updated := versionsOf(t, "CVE-1", "p1", "not_affected"); updated != "2026-06-01T00:00:00Z" {
			t.Fatalf("an unchanged list rewrote the row: updated = %s", updated)
		}
		if o := owner(t, "CVE-1", "p1"); o == nil || *o != "a" {
			t.Fatalf("owner after an unchanged list = %v, want a", o)
		}
		// A changed list is written in place: still one row.
		grown := same
		grown.Versions = []string{"3.0", "1.0", "2.0"}
		insert(t, grown)
		vs, updated := versionsOf(t, "CVE-1", "p1", "not_affected")
		if !slices.Equal(vs, []string{"1.0", "2.0", "3.0"}) || updated != "2026-12-31T00:00:00Z" {
			t.Fatalf("changed list not written: %q, %s", vs, updated)
		}
		wantRows(t, "b|CVE-1|p1|")
		// No versions is an empty list, not NULL, and reads back as nil.
		insert(t, sweepRow("a", "CVE-2", "p1", ""))
		if vs, _ := versionsOf(t, "CVE-2", "p1", "not_affected"); vs == nil || len(vs) != 0 {
			t.Fatalf("empty versions stored as %#v, want {}", vs)
		}
		got, err := d.QueryStatements(db.QueryFilters{CVEs: []string{"CVE-2"}})
		if err != nil || len(got) != 1 || got[0].Versions != nil {
			t.Fatalf("QueryStatements = %+v, %v; want nil Versions", got, err)
		}
	})

	t.Run("the seen key includes the verdict", func(t *testing.T) {
		reset(t)
		old := sweepRow("a", "CVE-1", "p1", "")
		old.Status = "affected"
		insert(t, old, sweepRow("a", "CVE-1", "p1", ""))
		other := sweepRow("a", "CVE-1", "p1", "")
		other.Stream = "rhel-9"
		insert(t, other)
		start(t, "a", key("CVE-1", "p1", ""))
		res, err := d.FinishSweep("a", db.SweepScope{All: true}, 1)
		if err != nil || res != (db.SweepResult{Seen: 1, Owned: 3, Deleted: 2}) {
			t.Fatalf("FinishSweep = %+v, %v", res, err)
		}
		var left []string
		if err := d.pool.QueryRow(ctx, `SELECT array_agg(status || '|' || stream) FROM statements`).Scan(&left); err != nil {
			t.Fatalf("rows: %v", err)
		}
		if !slices.Equal(left, []string{"not_affected|"}) {
			t.Fatalf("rows = %q; want only the not_affected successor on no stream", left)
		}
	})

	t.Run("migration v2 applies on top of v1 data", func(t *testing.T) {
		const schema = "reel_vex_v1_test"
		if _, err := d.pool.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE; CREATE SCHEMA `+schema); err != nil {
			t.Fatalf("create schema: %v", err)
		}
		defer d.pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
		cfg, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatalf("parse dsn: %v", err)
		}
		cfg.ConnConfig.RuntimeParams["search_path"] = schema
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatalf("pool: %v", err)
		}
		defer pool.Close()
		v1 := &DB{pool: pool}

		all := migrations
		migrations = all[:1]
		err = v1.migrate(ctx)
		migrations = all
		if err != nil {
			t.Fatalf("migrate to v1: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO statements (vendor, cve, product_id, base_id, id_type, status, updated)
			VALUES ('redhat', 'CVE-1', 'p1', 'p1', 'purl', 'fixed', '2026-06-01T00:00:00Z')`); err != nil {
			t.Fatalf("insert v1 row: %v", err)
		}
		migrations = all[:2]
		err = v1.migrate(ctx)
		migrations = all
		if err != nil {
			t.Fatalf("migrate to v2: %v", err)
		}
		var version int
		if err := pool.QueryRow(ctx, `SELECT version FROM schema_version`).Scan(&version); err != nil || version != 2 {
			t.Fatalf("schema_version = %d, %v; want 2", version, err)
		}
		var o *string
		if err := pool.QueryRow(ctx, `SELECT adapter_id FROM statements WHERE cve = 'CVE-1'`).Scan(&o); err != nil || o != nil {
			t.Fatalf("v1 row owner = %v, %v; want NULL", o, err)
		}
		var idx bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_indexes WHERE schemaname = $1 AND indexname = 'idx_statements_adapter')`, schema).Scan(&idx); err != nil || !idx {
			t.Fatalf("idx_statements_adapter exists = %v, %v", idx, err)
		}
		var opts []string
		if err := pool.QueryRow(ctx, `SELECT reloptions FROM pg_class WHERE oid = 'statements'::regclass`).Scan(&opts); err != nil {
			t.Fatalf("reloptions: %v", err)
		}
		if !slices.Contains(opts, "autovacuum_vacuum_scale_factor=0.01") || !slices.Contains(opts, "autovacuum_vacuum_threshold=100000") {
			t.Fatalf("reloptions = %v", opts)
		}
	})

	t.Run("migration v3 applies on top of v2 data", func(t *testing.T) {
		const schema = "reel_vex_v2_test"
		if _, err := d.pool.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE; CREATE SCHEMA `+schema); err != nil {
			t.Fatalf("create schema: %v", err)
		}
		defer d.pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
		cfg, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatalf("parse dsn: %v", err)
		}
		cfg.ConnConfig.RuntimeParams["search_path"] = schema
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatalf("pool: %v", err)
		}
		defer pool.Close()
		v2 := &DB{pool: pool}

		all := migrations
		migrations = all[:2]
		err = v2.migrate(ctx)
		migrations = all
		if err != nil {
			t.Fatalf("migrate to v2: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO statements (vendor, cve, product_id, base_id, version, id_type, status, justification, updated, adapter_id) VALUES
			('redhat', 'CVE-1', 'p1', 'p1', '5.1', 'purl', 'fixed', NULL, '2026-06-01T00:00:00Z', 'a'),
			('redhat', 'CVE-2', 'p1', 'p1', '', 'purl', 'not_affected', 'component_not_present', '2026-06-01T00:00:00Z', 'a'),
			('redhat', 'CVE-3', 'p1', 'p1', NULL, 'purl', 'affected', NULL, '2026-06-01T00:00:00Z', NULL)`); err != nil {
			t.Fatalf("insert v2 rows: %v", err)
		}
		// The covering index as v2 builds it, INCLUDEing version: v3 must drop it.
		if _, err := pool.Exec(ctx, `CREATE INDEX idx_statements_broad ON statements (base_id, cve, product_id, source_format)
			INCLUDE (vendor, version, id_type, status, justification, updated, scope)`); err != nil {
			t.Fatalf("v2 covering index: %v", err)
		}
		if err := v2.migrate(ctx); err != nil {
			t.Fatalf("migrate to v3: %v", err)
		}
		var version int
		if err := pool.QueryRow(ctx, `SELECT version FROM schema_version`).Scan(&version); err != nil || version != 3 {
			t.Fatalf("schema_version = %d, %v; want 3", version, err)
		}
		rows, err := pool.Query(ctx, `SELECT cve || '|' || array_to_string(versions, ',') || '|' || version_kind || '|' || stream || '|' || justification || '|' || coalesce(adapter_id, '-') FROM statements ORDER BY cve`)
		if err != nil {
			t.Fatalf("read v3 rows: %v", err)
		}
		got, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatalf("read v3 rows: %v", err)
		}
		want := []string{"CVE-1|5.1||||a", "CVE-2||||component_not_present|a", "CVE-3|||||-"}
		if !slices.Equal(got, want) {
			t.Fatalf("v3 rows = %q, want %q", got, want)
		}
		var pk string
		if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid = 'statements'::regclass AND contype = 'p'`).Scan(&pk); err != nil {
			t.Fatalf("primary key: %v", err)
		}
		if pk != "PRIMARY KEY (vendor, cve, product_id, source_format, scope, stream, status, justification)" {
			t.Fatalf("primary key = %s", pk)
		}
		var hasVersion, hasBroad bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema = $1 AND table_name = 'statements' AND column_name = 'version')`, schema).Scan(&hasVersion); err != nil || hasVersion {
			t.Fatalf("version column still present = %v, %v", hasVersion, err)
		}
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_indexes WHERE schemaname = $1 AND indexname = 'idx_statements_broad')`, schema).Scan(&hasBroad); err != nil || hasBroad {
			t.Fatalf("old covering index still present = %v, %v", hasBroad, err)
		}
		// The store writes and reads the new shape, and the index rebuilds.
		if err := v2.BulkInsert([]db.Statement{{Vendor: "redhat", CVE: "CVE-1", ProductID: "p1", IDType: "purl", Status: "affected",
			Updated: "2026-07-01T00:00:00Z", Versions: []string{"5.2"}}}); err != nil {
			t.Fatalf("BulkInsert on v3: %v", err)
		}
		if err := v2.EnsureCoveringIndex(); err != nil {
			t.Fatalf("EnsureCoveringIndex on v3: %v", err)
		}
		v2.queryTimeout = defaultQueryTimeout
		got2, err := v2.QueryStatements(db.QueryFilters{CVEs: []string{"CVE-1"}})
		if err != nil || len(got2) != 2 {
			t.Fatalf("QueryStatements on v3 = %+v, %v; want the fixed and the affected row", got2, err)
		}
	})
}

// explain returns the text plan of q run with args on the pool.
func explain(t *testing.T, d *DB, q string, args ...any) string {
	t.Helper()
	rows, err := d.pool.Query(t.Context(), `EXPLAIN `+q, args...)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	return collectPlan(t, rows)
}

// explainTx is explain inside tx, so it sees the transaction's temp tables.
func explainTx(t *testing.T, tx pgx.Tx, q string, args ...any) string {
	t.Helper()
	rows, err := tx.Query(t.Context(), `EXPLAIN `+q, args...)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	return collectPlan(t, rows)
}

func collectPlan(t *testing.T, rows pgx.Rows) string {
	t.Helper()
	lines, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	return strings.Join(lines, "\n")
}

// ownedScan matches a scan of the sweep's owned CTE source, `statements s`.
var ownedScan = regexp.MustCompile(`(Seq Scan|Index Scan using \S+|Index Only Scan using \S+|Bitmap Heap Scan) on statements s\b`)

// assertSweepPlan checks the shape sweepSQL was written for: the unseen rows
// found by an anti join (not a SubPlan, which cannot spill), the owned rows
// read once, and the delete done by ctid.
func assertSweepPlan(t *testing.T, plan string) {
	t.Helper()
	if !strings.Contains(plan, "Anti Join") {
		t.Errorf("sweep plan has no anti join:\n%s", plan)
	}
	if strings.Contains(plan, "SubPlan") {
		t.Errorf("sweep plan has a SubPlan:\n%s", plan)
	}
	if n := len(ownedScan.FindAllString(plan, -1)); n != 1 {
		t.Errorf("sweep plan scans statements s %d times, want 1:\n%s", n, plan)
	}
	if !strings.Contains(plan, "Tid Scan on statements d") {
		t.Errorf("sweep plan does not delete by Tid Scan:\n%s", plan)
	}
}

// TestSeenTable pins the seen-table naming: folded ids stay distinct, and the
// name stays inside Postgres' 63-byte identifier limit.
func TestSeenTable(t *testing.T) {
	a, b := seenTable("redhat-csaf"), seenTable("redhat.csaf")
	if a == b {
		t.Fatalf("distinct ids share a seen table: %s", a)
	}
	if !strings.HasPrefix(a, "sweep_seen_redhat_csaf_") {
		t.Fatalf("seenTable(redhat-csaf) = %s", a)
	}
	long := seenTable(strings.Repeat("Ä", 100))
	if len(long) > 63 || !regexp.MustCompile(`^sweep_seen_[a-z0-9_]{1,32}_[0-9a-f]{8}$`).MatchString(long) {
		t.Fatalf("seenTable(long) = %s (%d bytes)", long, len(long))
	}
}
