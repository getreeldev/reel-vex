package dbtest

import (
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/getreeldev/reel-vex/pkg/db"
)

// These mirror TestPG's removal subtests (pkg/db/postgres), so the fake and
// Postgres cannot drift on what a sweep or a withdrawal deletes.

func row(adapter, cve, product, scope string) db.Statement {
	return db.Statement{Vendor: "redhat", CVE: cve, ProductID: product, IDType: "purl",
		Status: "not_affected", Updated: "2026-06-01T00:00:00Z", SourceFormat: "csaf", Scope: scope, AdapterID: adapter}
}

// key is the seen key of a row(): every row() is not_affected with no
// justification.
func key(cve, product, scope string) db.StatementKey {
	return db.StatementKey{CVE: cve, ProductID: product, Scope: scope, Status: "not_affected"}
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

// An unchanged re-insert keeps the owner and a changed one moves it, as in
// Postgres. And QueryStatements never returns the owner, as Postgres never
// selects it.
func TestOwner(t *testing.T) {
	s := seed(t, row("a", "CVE-1", "p1", ""))
	if err := s.BulkInsert([]db.Statement{row("b", "CVE-1", "p1", "")}); err != nil {
		t.Fatalf("BulkInsert: %v", err)
	}
	wantRows(t, s, "a|CVE-1|p1|")
	changed := row("b", "CVE-1", "p1", "")
	changed.Versions = []string{"1.0"}
	if err := s.BulkInsert([]db.Statement{changed}); err != nil {
		t.Fatalf("BulkInsert: %v", err)
	}
	wantRows(t, s, "b|CVE-1|p1|")
	got, err := s.QueryStatements(db.QueryFilters{CVEs: []string{"CVE-1"}})
	if err != nil || len(got) != 1 || got[0].AdapterID != "" {
		t.Fatalf("QueryStatements = %+v, %v; want one row with no owner", got, err)
	}
}

// These mirror TestPG's verdict-key subtests.

func TestVerdictsCoexist(t *testing.T) {
	affected := row("a", "CVE-1", "p1", "")
	affected.Status = "affected"
	s := seed(t, row("a", "CVE-1", "p1", ""), affected)
	got, err := s.QueryStatements(db.QueryFilters{CVEs: []string{"CVE-1"}})
	if err != nil || len(got) != 2 {
		t.Fatalf("QueryStatements = %+v, %v; want both verdicts", got, err)
	}
}

func TestStreamsCoexist(t *testing.T) {
	rhel9 := row("a", "CVE-1", "p1", "")
	rhel9.Stream = "rhel-9"
	s := seed(t, row("a", "CVE-1", "p1", ""), rhel9)
	if n := len(s.stmts); n != 2 {
		t.Fatalf("%d rows, want one per stream", n)
	}
	got, err := s.QueryStatements(db.QueryFilters{CVEs: []string{"CVE-1"}})
	if err != nil || len(got) != 2 || got[0].Stream != "" || got[1].Stream != "" {
		t.Fatalf("QueryStatements = %+v, %v; want both rows, stream not returned", got, err)
	}
}

func TestVersionsGuard(t *testing.T) {
	first := row("a", "CVE-1", "p1", "")
	first.Versions = []string{"2.0", "1.0", "2.0", ""}
	s := seed(t, first)
	got, _ := s.QueryStatements(db.QueryFilters{CVEs: []string{"CVE-1"}})
	if len(got) != 1 || !slices.Equal(got[0].Versions, []string{"1.0", "2.0"}) {
		t.Fatalf("stored = %+v; want versions [1.0 2.0]", got)
	}
	// The same list in another order, with a newer timestamp: not a change.
	same := row("b", "CVE-1", "p1", "")
	same.Versions = []string{"2.0", "1.0"}
	same.Updated = "2026-12-31T00:00:00Z"
	if err := s.BulkInsert([]db.Statement{same}); err != nil {
		t.Fatalf("BulkInsert: %v", err)
	}
	got, _ = s.QueryStatements(db.QueryFilters{CVEs: []string{"CVE-1"}})
	if got[0].Updated != "2026-06-01T00:00:00Z" {
		t.Fatalf("unchanged list rewrote the row: %+v", got[0])
	}
	wantRows(t, s, "a|CVE-1|p1|")
	// A changed list is written, in place.
	grown := same
	grown.Versions = []string{"3.0", "1.0", "2.0"}
	if err := s.BulkInsert([]db.Statement{grown}); err != nil {
		t.Fatalf("BulkInsert: %v", err)
	}
	got, _ = s.QueryStatements(db.QueryFilters{CVEs: []string{"CVE-1"}})
	if len(got) != 1 || got[0].Updated != "2026-12-31T00:00:00Z" || !slices.Equal(got[0].Versions, []string{"1.0", "2.0", "3.0"}) {
		t.Fatalf("changed list not written: %+v", got)
	}
	wantRows(t, s, "b|CVE-1|p1|")
}

func TestSweepVerdictKey(t *testing.T) {
	old := row("a", "CVE-1", "p1", "")
	old.Status = "affected"
	s := seed(t, old, row("a", "CVE-1", "p1", ""))
	open(t, s, "a", key("CVE-1", "p1", ""))
	res, err := s.FinishSweep("a", db.SweepScope{All: true}, 1)
	if err != nil || res != (db.SweepResult{Seen: 1, Owned: 2, Deleted: 1}) {
		t.Fatalf("FinishSweep = %+v, %v", res, err)
	}
	got, _ := s.QueryStatements(db.QueryFilters{CVEs: []string{"CVE-1"}})
	if len(got) != 1 || got[0].Status != "not_affected" {
		t.Fatalf("rows = %+v; want only the not_affected successor", got)
	}
}

// TestExactVersions mirrors TestPG's exact-list subtests (pkg/db/postgres), so
// the fake and Postgres cannot drift on which rows a versioned query keeps.
func TestExactVersions(t *testing.T) {
	const cve = "CVE-2024-1234"
	base := func(name string) string { return "pkg:deb/ubuntu/" + name + "?distro=ubuntu-22.04" }
	exact := func(cve, name, arch, status string, versions ...string) db.Statement {
		return db.Statement{Vendor: "ubuntu", CVE: cve, ProductID: "pkg:deb/ubuntu/" + name + "?arch=" + arch + "&distro=ubuntu-22.04",
			BaseID: base(name), Versions: versions, VersionKind: "exact", IDType: "purl", Status: status,
			Updated: "2026-06-01T00:00:00Z", SourceFormat: "openvex"}
	}
	s := seed(t,
		exact(cve, "openssl", "amd64", "fixed", "1.10", "1.11"),
		exact(cve, "openssl", "arm64", "fixed", "1.12"),
		exact("CVE-2024-9999", "openssl", "amd64", "fixed", "1.09"),
		exact(cve, "glibc", "amd64", "affected", "2.35-1"),
		exact(cve, "glibc", "amd64", "fixed", "2.35-2"),
		exact(cve, "bash", "amd64", "not_affected"),
		db.Statement{Vendor: "debian", CVE: cve, ProductID: "pkg:deb/ubuntu/openssl?distro=ubuntu-22.04", BaseID: base("openssl"),
			Versions: []string{"0.9"}, IDType: "purl", Status: "fixed", Updated: "2026-06-01T00:00:00Z", SourceFormat: "oval"},
	)
	pv := func(b, v string) db.BaseVersion { return db.BaseVersion{Base: b, Version: v} }
	for _, c := range []struct {
		name string
		f    db.QueryFilters
		want []string
	}{
		{"versioned", db.QueryFilters{CVEs: []string{cve, "CVE-2024-9999"}, ProductBaseIDs: []string{base("openssl")},
			ExactVersions: []db.BaseVersion{pv(base("openssl"), "1.11")}},
			[]string{"ubuntu amd64 fixed [1.11]", "debian - fixed [0.9]"}},
		{"unlisted", db.QueryFilters{CVEs: []string{cve}, ProductBaseIDs: []string{base("openssl")},
			ExactVersions: []db.BaseVersion{pv(base("openssl"), "1.09")}},
			[]string{"debian - fixed [0.9]"}},
		{"no version", db.QueryFilters{CVEs: []string{cve}, ProductBaseIDs: []string{base("glibc")},
			ExactVersions: []db.BaseVersion{pv(base("glibc"), "")}},
			[]string{"ubuntu amd64 affected [2.35-1]", "ubuntu amd64 fixed [2.35-2]"}},
		{"glibc build", db.QueryFilters{CVEs: []string{cve}, ProductBaseIDs: []string{base("glibc")},
			ExactVersions: []db.BaseVersion{pv(base("glibc"), "2.35-1")}},
			[]string{"ubuntu amd64 affected [2.35-1]"}},
		{"versioned and unversioned", db.QueryFilters{CVEs: []string{cve}, ProductBaseIDs: []string{base("glibc")},
			ExactVersions: []db.BaseVersion{pv(base("glibc"), "2.35-1"), pv(base("glibc"), "")}},
			[]string{"ubuntu amd64 affected [2.35-1]", "ubuntu amd64 fixed [2.35-2]"}},
		{"empty list", db.QueryFilters{CVEs: []string{cve}, ProductBaseIDs: []string{base("bash")},
			ExactVersions: []db.BaseVersion{pv(base("bash"), "5.1")}},
			[]string{"ubuntu amd64 not_affected []"}},
		{"arch", db.QueryFilters{CVEs: []string{cve}, ProductBaseIDs: []string{base("openssl")},
			ExactVersions: []db.BaseVersion{pv(base("openssl"), "1.12")}},
			[]string{"ubuntu arm64 fixed [1.12]", "debian - fixed [0.9]"}},
		{"limit", db.QueryFilters{CVEs: []string{cve}, ProductBaseIDs: []string{base("glibc")},
			ExactVersions: []db.BaseVersion{pv(base("glibc"), "2.35-2")}, Limit: 1},
			[]string{"ubuntu amd64 fixed [2.35-2]"}},
	} {
		got, err := s.QueryStatements(c.f)
		if err != nil {
			t.Fatal(err)
		}
		var g []string
		for _, st := range got {
			arch := "-"
			if i := strings.Index(st.ProductID, "arch="); i >= 0 {
				arch = st.ProductID[i+5 : strings.IndexByte(st.ProductID, '&')]
			}
			g = append(g, fmt.Sprintf("%s %s %s %v", st.Vendor, arch, st.Status, st.Versions))
		}
		if !slices.Equal(g, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, g, c.want)
		}
	}
}
