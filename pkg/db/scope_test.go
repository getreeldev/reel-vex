package db

import "testing"

// TestScopeGating is the safety guard for product-scoped statements (Rancher
// VEX). It asserts three things at once:
//
//  1. With no scope context, only unscoped rows come back — a verdict scoped to
//     one image must never suppress the same package for an unrelated scan.
//  2. A scoped row surfaces only when its scope is explicitly named.
//  3. Two scoped rows that differ ONLY by scope coexist (the v4 PK includes
//     scope) and can carry opposite verdicts — the whole reason scope exists.
func TestScopeGating(t *testing.T) {
	d, err := Open(t.TempDir() + "/scope.db")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	const (
		cve  = "CVE-2024-9999"
		pkg  = "pkg:golang/golang.org/x/net"
		imgA = "pkg:oci/image-a?repository_url=r.io/ns/a"
		imgB = "pkg:oci/image-b?repository_url=r.io/ns/b"
	)
	if err := d.BulkInsert([]Statement{
		// Unscoped, package-level (e.g. a CSAF/OVAL row).
		{Vendor: "redhat", CVE: cve, ProductID: pkg, BaseID: pkg, IDType: "purl", Status: "affected", Updated: "2024-01-01T00:00:00Z", SourceFormat: "csaf"},
		// Two Rancher rows: same vendor+cve+product_id+source_format, differing
		// only by scope, with OPPOSITE verdicts. Pre-v4 they would collide.
		{Vendor: "rancher", CVE: cve, ProductID: pkg, BaseID: pkg, IDType: "purl", Status: "not_affected", Justification: "vulnerable_code_not_present", Updated: "2024-01-02T00:00:00Z", SourceFormat: "openvex", Scope: imgA},
		{Vendor: "rancher", CVE: cve, ProductID: pkg, BaseID: pkg, IDType: "purl", Status: "affected", Updated: "2024-01-02T00:00:00Z", SourceFormat: "openvex", Scope: imgB},
	}); err != nil {
		t.Fatalf("BulkInsert: %v", err)
	}

	// 1. No scope → only the unscoped row.
	rows, err := d.QueryStatements(QueryFilters{CVEs: []string{cve}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("no-scope query: got %d rows, want 1 (unscoped only)", len(rows))
	}
	if rows[0].Scope != "" || rows[0].Vendor != "redhat" {
		t.Errorf("no-scope query returned a scoped row: %+v", rows[0])
	}

	// 2. Scope imgA → unscoped + the imgA row, but NOT imgB.
	rows, err = d.QueryStatements(QueryFilters{CVEs: []string{cve}, Scopes: []string{imgA}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("scope=imgA query: got %d rows, want 2 (unscoped + imgA)", len(rows))
	}
	for _, r := range rows {
		if r.Scope == imgB {
			t.Errorf("scope=imgA query leaked an imgB-scoped row: %+v", r)
		}
	}

	// 3. Both scopes named → all three rows, and the two scoped rows kept their
	//    opposite verdicts (coexistence proves scope is in the PK).
	rows, err = d.QueryStatements(QueryFilters{CVEs: []string{cve}, Scopes: []string{imgA, imgB}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("both-scopes query: got %d rows, want 3", len(rows))
	}
	byScope := map[string]string{}
	for _, r := range rows {
		byScope[r.Scope] = r.Status
	}
	if byScope[imgA] != "not_affected" {
		t.Errorf("imgA verdict: got %q, want not_affected", byScope[imgA])
	}
	if byScope[imgB] != "affected" {
		t.Errorf("imgB verdict: got %q, want affected", byScope[imgB])
	}
	if byScope[""] != "affected" {
		t.Errorf("unscoped verdict: got %q, want affected", byScope[""])
	}
}
