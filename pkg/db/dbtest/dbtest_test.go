package dbtest

import (
	"fmt"
	"math"
	"testing"

	"github.com/getreeldev/reel-vex/pkg/db"
)

// These mirror TestPG's removal subtests (pkg/db/postgres), so the fake and
// Postgres cannot drift on what a sweep or a withdrawal deletes.

func row(adapter, cve, product, scope string) db.Statement {
	return db.Statement{Vendor: "redhat", CVE: cve, ProductID: product, IDType: "purl",
		Status: "not_affected", Updated: "2026-06-01T00:00:00Z", SourceFormat: "csaf", Scope: scope, AdapterID: adapter}
}

func key(cve, product, scope string) db.StatementKey {
	return db.StatementKey{CVE: cve, ProductID: product, Scope: scope}
}

// rowsOf lists every row as "owner|cve|product|scope", owner "-" for none.
func rowsOf(s *Store) map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]bool{}
	for _, st := range s.stmts {
		o := st.AdapterID
		if o == "" {
			o = "-"
		}
		out[o+"|"+st.CVE+"|"+st.ProductID+"|"+st.Scope] = true
	}
	return out
}

func wantRows(t *testing.T, s *Store, want ...string) {
	t.Helper()
	got := rowsOf(s)
	if len(got) != len(want) {
		t.Fatalf("rows = %v, want %v", got, want)
	}
	for _, w := range want {
		if !got[w] {
			t.Fatalf("rows = %v, missing %q", got, w)
		}
	}
}

func open(t *testing.T, s *Store, adapter string, keys ...db.StatementKey) {
	t.Helper()
	if err := s.StartSweep(adapter); err != nil {
		t.Fatalf("StartSweep: %v", err)
	}
	if err := s.RecordSeen(adapter, keys); err != nil {
		t.Fatalf("RecordSeen: %v", err)
	}
}

func seed(t *testing.T, rows ...db.Statement) *Store {
	t.Helper()
	s := New()
	if err := s.BulkInsert(rows); err != nil {
		t.Fatalf("BulkInsert: %v", err)
	}
	return s
}

func TestSweepAll(t *testing.T) {
	s := seed(t,
		row("a", "CVE-1", "p1", ""),
		row("a", "CVE-1", "p1", "img"),
		row("a", "CVE-1", "p2", ""),
		row("a", "CVE-2", "p1", ""),
		row("a", "CVE-9", "p9", ""),
		row("b", "CVE-3", "p1", ""),
		row("", "CVE-4", "p1", ""),
	)
	open(t, s, "a", key("CVE-1", "p1", ""), key("CVE-1", "p2", ""), key("CVE-2", "p1", ""), key("CVE-2", "p1", ""))
	res, err := s.FinishSweep("a", db.SweepScope{All: true}, 0.5)
	if err != nil || res != (db.SweepResult{Seen: 4, Owned: 5, Deleted: 2}) {
		t.Fatalf("FinishSweep = %+v, %v", res, err)
	}
	wantRows(t, s, "a|CVE-1|p1|", "a|CVE-1|p2|", "a|CVE-2|p1|", "b|CVE-3|p1|", "-|CVE-4|p1|")
	if _, err := s.FinishSweep("a", db.SweepScope{All: true}, 0.5); err == nil {
		t.Fatal("the session outlived FinishSweep")
	}
}

func TestSweepGuard(t *testing.T) {
	var rows []db.Statement
	var keys []db.StatementKey
	for i := 0; i < 10; i++ {
		p := fmt.Sprintf("p%d", i)
		rows = append(rows, row("a", "CVE-1", p, ""))
		if i < 5 {
			keys = append(keys, key("CVE-1", p, ""))
		}
	}
	s := seed(t, rows...)
	open(t, s, "a", keys...)
	res, err := s.FinishSweep("a", db.SweepScope{All: true}, 0.3)
	if err != nil || !res.Refused || res.Seen != 5 || res.Owned != 10 || res.Deleted != 5 || res.Reason == "" {
		t.Fatalf("FinishSweep = %+v, %v; want a refusal of 5 of 10", res, err)
	}
	if n := len(rowsOf(s)); n != 10 {
		t.Fatalf("%d rows after a refused sweep, want 10", n)
	}
	if _, err := s.FinishSweep("a", db.SweepScope{All: true}, 0.3); err == nil {
		t.Fatal("the session outlived a refusal")
	}
	open(t, s, "a", keys...)
	if res, err := s.FinishSweep("a", db.SweepScope{All: true}, 0.5); err != nil || res.Refused || res.Deleted != 5 {
		t.Fatalf("at the limit: %+v, %v", res, err)
	}
}

func TestSweepRefusals(t *testing.T) {
	s := seed(t, row("a", "CVE-1", "p1", ""))
	open(t, s, "a")
	if res, err := s.FinishSweep("a", db.SweepScope{All: true}, 1); err != nil || res != (db.SweepResult{Refused: true, Reason: "nothing seen"}) {
		t.Fatalf("nothing seen: %+v, %v", res, err)
	}
	for _, mf := range []float64{0, -1, math.NaN()} {
		for _, sc := range []db.SweepScope{{All: true}, {CVEs: []string{"CVE-1"}}} {
			open(t, s, "a", key("CVE-2", "p1", ""), key("CVE-2", "p1", ""))
			res, err := s.FinishSweep("a", sc, mf)
			if err != nil || res != (db.SweepResult{Seen: 2, Refused: true, Reason: "sweep disabled"}) {
				t.Fatalf("disabled (%v, %+v): %+v, %v", mf, sc, res, err)
			}
		}
	}
	wantRows(t, s, "a|CVE-1|p1|")
}

func TestSweepSessionErrors(t *testing.T) {
	s := seed(t, row("a", "CVE-1", "p1", ""))
	if err := s.StartSweep(""); err == nil {
		t.Error(`StartSweep("") succeeded`)
	}
	if err := s.RecordSeen("", nil); err == nil {
		t.Error(`RecordSeen("") succeeded`)
	}
	if _, err := s.FinishSweep("", db.SweepScope{All: true}, 1); err == nil {
		t.Error(`FinishSweep("") succeeded`)
	}
	if err := s.AbortSweep(""); err == nil {
		t.Error(`AbortSweep("") succeeded`)
	}
	if _, err := s.Withdraw("", []string{"CVE-1"}, 1); err == nil {
		t.Error(`Withdraw("") succeeded`)
	}
	if err := s.RecordSeen("a", []db.StatementKey{key("CVE-1", "p1", "")}); err == nil {
		t.Error("RecordSeen with no session succeeded")
	}
	if _, err := s.FinishSweep("a", db.SweepScope{All: true}, 1); err == nil {
		t.Error("FinishSweep with no session succeeded")
	}
	if err := s.AbortSweep("a"); err != nil {
		t.Errorf("AbortSweep with no session: %v", err)
	}
	open(t, s, "a")
	if err := s.AbortSweep("a"); err != nil {
		t.Fatalf("AbortSweep: %v", err)
	}
	if _, err := s.FinishSweep("a", db.SweepScope{All: true}, 1); err == nil {
		t.Error("FinishSweep after abort succeeded")
	}
	open(t, s, "a")
	open(t, s, "b")
	if err := s.ResetSweeps(); err != nil {
		t.Fatalf("ResetSweeps: %v", err)
	}
	if err := s.RecordSeen("b", nil); err == nil {
		t.Error("RecordSeen after ResetSweeps succeeded")
	}
	wantRows(t, s, "a|CVE-1|p1|")
}

func TestSweepScoped(t *testing.T) {
	s := seed(t,
		row("a", "CVE-1", "p1", ""),
		row("a", "CVE-1", "p2", ""),
		row("a", "CVE-2", "p1", ""),
		row("a", "CVE-2", "p2", ""),
		row("a", "CVE-3", "p1", ""),
		row("b", "CVE-1", "p3", ""),
		row("", "CVE-2", "p3", ""),
	)
	open(t, s, "a", key("CVE-1", "p1", ""))
	res, err := s.FinishSweep("a", db.SweepScope{CVEs: []string{"CVE-1", "CVE-2"}}, 0.01)
	if err != nil || res != (db.SweepResult{Seen: 1, Owned: 4, Deleted: 3}) {
		t.Fatalf("FinishSweep = %+v, %v", res, err)
	}
	wantRows(t, s, "a|CVE-1|p1|", "a|CVE-3|p1|", "b|CVE-1|p3|", "-|CVE-2|p3|")

	open(t, s, "a")
	if res, err := s.FinishSweep("a", db.SweepScope{CVEs: []string{"CVE-3"}}, 0.01); err != nil || res != (db.SweepResult{Owned: 1, Deleted: 1}) {
		t.Fatalf("empty document: %+v, %v", res, err)
	}
	open(t, s, "a", key("CVE-9", "p1", ""))
	if res, err := s.FinishSweep("a", db.SweepScope{}, 0.5); err != nil || res != (db.SweepResult{Seen: 1}) {
		t.Fatalf("empty CVE list: %+v, %v", res, err)
	}
	wantRows(t, s, "a|CVE-1|p1|", "b|CVE-1|p3|", "-|CVE-2|p3|")
}

func TestWithdraw(t *testing.T) {
	var rows []db.Statement
	for i := 1; i <= 10; i++ {
		rows = append(rows, row("a", fmt.Sprintf("CVE-%d", i), "p1", ""))
	}
	rows = append(rows, row("a", "CVE-9", "p2", ""), row("b", "CVE-9", "p3", ""), row("", "CVE-10", "p3", ""))
	s := seed(t, rows...)
	for _, live := range [][]string{nil, {}} {
		if res, err := s.Withdraw("a", live, 1); err != nil || !res.Refused || res.Reason != "empty manifest" {
			t.Fatalf("empty manifest: %+v, %v", res, err)
		}
	}
	for _, mf := range []float64{0, math.NaN()} {
		if res, err := s.Withdraw("a", []string{"CVE-1"}, mf); err != nil || !res.Refused || res.Reason != "withdraw disabled" {
			t.Fatalf("disabled: %+v, %v", res, err)
		}
	}
	res, err := s.Withdraw("a", []string{"CVE-1"}, 0.5)
	if err != nil || !res.Refused || res.HeldCVEs != 10 || res.WithdrawnCVEs != 9 || res.Deleted != 0 {
		t.Fatalf("over the fraction: %+v, %v", res, err)
	}
	if n := len(rowsOf(s)); n != 13 {
		t.Fatalf("%d rows after a refused withdrawal, want 13", n)
	}
	live := []string{"CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5", "CVE-6", "CVE-7", "CVE-8", "CVE-8", "CVE-1", "CVE-99"}
	res, err = s.Withdraw("a", live, 0.2)
	if err != nil || res != (db.WithdrawResult{Live: 9, HeldCVEs: 10, WithdrawnCVEs: 2, Deleted: 3}) {
		t.Fatalf("Withdraw = %+v, %v", res, err)
	}
	got := rowsOf(s)
	if len(got) != 10 || got["a|CVE-9|p1|"] || got["a|CVE-9|p2|"] || got["a|CVE-10|p1|"] ||
		!got["b|CVE-9|p3|"] || !got["-|CVE-10|p3|"] {
		t.Fatalf("rows after withdrawal = %v", got)
	}
}

// The fake's owner follows the last writer even on an unchanged re-insert
// (Postgres keeps it); a changed one moves it in both. And QueryStatements
// never returns the owner, as Postgres never selects it.
func TestOwner(t *testing.T) {
	s := seed(t, row("a", "CVE-1", "p1", ""))
	changed := row("b", "CVE-1", "p1", "")
	changed.Status = "affected"
	if err := s.BulkInsert([]db.Statement{changed}); err != nil {
		t.Fatalf("BulkInsert: %v", err)
	}
	wantRows(t, s, "b|CVE-1|p1|")
	got, err := s.QueryStatements(db.QueryFilters{CVEs: []string{"CVE-1"}})
	if err != nil || len(got) != 1 || got[0].AdapterID != "" {
		t.Fatalf("QueryStatements = %+v, %v; want one row with no owner", got, err)
	}
}
