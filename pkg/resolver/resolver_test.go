package resolver

import (
	"testing"

	"github.com/getreeldev/reel-vex/pkg/db"
)

// resolverTestDB opens a temp DB and seeds the product_aliases table with
// one representative Red Hat mapping.
func resolverTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(t.TempDir() + "/resolver-test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := d.BulkUpsertAliases([]db.Alias{
		{Vendor: "redhat", SourceNS: "repository_id", SourceID: "rhel-8-for-x86_64-appstream-rpms", TargetNS: "cpe", TargetID: "cpe:/a:redhat:enterprise_linux:8::appstream", Updated: "2024-01-01T00:00:00Z"},
		{Vendor: "redhat", SourceNS: "repository_id", SourceID: "rhel-8-for-x86_64-baseos-rpms", TargetNS: "cpe", TargetID: "cpe:/o:redhat:enterprise_linux:8::baseos", Updated: "2024-01-01T00:00:00Z"},
	}); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestExpand_PURLPassthrough(t *testing.T) {
	r := New(resolverTestDB(t))
	// A PURL with no qualifier and no alias match: only direct.
	cands := r.Expand("pkg:rpm/redhat/openssl@3.0")
	if len(cands) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(cands), cands)
	}
	if cands[0].ID != "pkg:rpm/redhat/openssl" {
		t.Errorf("base strip: got %q", cands[0].ID)
	}
	if cands[0].MatchReason != "direct" {
		t.Errorf("reason: got %q", cands[0].MatchReason)
	}
}

func TestExpand_PreservesDistroQualifier(t *testing.T) {
	r := New(resolverTestDB(t))
	// A deb PURL carries the distro qualifier as identity. splitBase must
	// keep it on the base; otherwise a query for noble openssl falls
	// through to jammy openssl statements and vice versa.
	cands := r.Expand("pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.1?arch=amd64&distro=ubuntu-24.04")
	if len(cands) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(cands), cands)
	}
	if cands[0].ID != "pkg:deb/ubuntu/openssl?distro=ubuntu-24.04" {
		t.Errorf("base: got %q, want pkg:deb/ubuntu/openssl?distro=ubuntu-24.04", cands[0].ID)
	}
}

func TestExpand_PURLWithRepositoryID(t *testing.T) {
	r := New(resolverTestDB(t))
	in := "pkg:rpm/redhat/openssl@3.0?arch=x86_64&repository_id=rhel-8-for-x86_64-appstream-rpms"
	cands := r.Expand(in)

	// Expect: direct (PURL base) + via_alias (CPE) + via_alias (CPE prefix).
	gotByReason := make(map[string][]string)
	for _, c := range cands {
		gotByReason[c.MatchReason] = append(gotByReason[c.MatchReason], c.ID)
	}

	if len(gotByReason["direct"]) != 1 || gotByReason["direct"][0] != "pkg:rpm/redhat/openssl" {
		t.Errorf("direct: got %v", gotByReason["direct"])
	}
	viaAlias := gotByReason["via_alias"]
	if len(viaAlias) < 1 {
		t.Fatalf("expected at least one via_alias candidate, got %v", viaAlias)
	}
	hasCPE := false
	hasPrefix := false
	for _, c := range viaAlias {
		if c == "cpe:/a:redhat:enterprise_linux:8::appstream" {
			hasCPE = true
		}
		if c == "cpe:/a:redhat:enterprise_linux:8" {
			hasPrefix = true
		}
	}
	if !hasCPE {
		t.Errorf("expected alias CPE, got %v", viaAlias)
	}
	if !hasPrefix {
		t.Errorf("expected prefix of alias CPE, got %v", viaAlias)
	}
}

func TestExpand_CPEInputGetsPrefix(t *testing.T) {
	r := New(resolverTestDB(t))
	cands := r.Expand("cpe:/o:redhat:enterprise_linux:8::baseos")

	reasons := make(map[string]string)
	for _, c := range cands {
		reasons[c.ID] = c.MatchReason
	}
	if reasons["cpe:/o:redhat:enterprise_linux:8::baseos"] != "direct" {
		t.Errorf("expected direct for exact CPE, got %q", reasons["cpe:/o:redhat:enterprise_linux:8::baseos"])
	}
	if reasons["cpe:/o:redhat:enterprise_linux:8"] != "via_cpe_prefix" {
		t.Errorf("expected via_cpe_prefix, got %q", reasons["cpe:/o:redhat:enterprise_linux:8"])
	}
}

func TestExpand_DedupeStrongerReasonWins(t *testing.T) {
	// If a CPE could be produced as both direct and via_cpe_prefix (e.g. user
	// queries with a CPE that is already at the 5-part form), direct wins.
	r := New(resolverTestDB(t))
	cands := r.Expand("cpe:/o:redhat:enterprise_linux:8")
	if len(cands) != 1 {
		t.Fatalf("expected 1 candidate (prefix == input), got %d: %+v", len(cands), cands)
	}
	if cands[0].MatchReason != "direct" {
		t.Errorf("reason: got %q, want direct", cands[0].MatchReason)
	}
}

func TestExtractRepositoryID(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"pkg:rpm/redhat/openssl@3.0?arch=x86_64&repository_id=rhel-8-for-x86_64-appstream-rpms", "rhel-8-for-x86_64-appstream-rpms"},
		{"pkg:rpm/redhat/openssl@3.0?repository_id=abc", "abc"},
		{"pkg:rpm/redhat/openssl@3.0", ""},
		{"cpe:/a:redhat:rhel:8", ""},
	}
	for _, tc := range cases {
		if got := extractRepositoryID(tc.in); got != tc.want {
			t.Errorf("extractRepositoryID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
