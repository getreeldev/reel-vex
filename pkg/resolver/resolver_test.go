package resolver

import (
	"testing"

	"github.com/getreeldev/reel-vex/pkg/db"
	"github.com/getreeldev/reel-vex/pkg/db/dbtest"
)

// resolverTestDB returns an in-memory store seeded with one representative
// Red Hat repository→CPE mapping.
func resolverTestDB(t *testing.T) db.Store {
	t.Helper()
	d := dbtest.New()
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
	// A deb PURL carries the distro qualifier as identity. The distro-bearing
	// candidate must be present so a query for noble openssl matches noble
	// stored data, not jammy. The distro-stripped candidate is also produced
	// (additive, harmless for Ubuntu data which is never stored bare) but
	// what this test cares about is the identity-preserving form.
	cands := r.Expand("pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.1?arch=amd64&distro=ubuntu-24.04")
	ids := make(map[string]string, len(cands))
	for _, c := range cands {
		ids[c.ID] = c.MatchReason
	}
	if ids["pkg:deb/ubuntu/openssl?distro=ubuntu-24.04"] != "direct" {
		t.Errorf("missing direct candidate with ?distro=ubuntu-24.04 in %v", ids)
	}
}

func TestExpand_RPMScannerDistroProducesBareAndDistroCandidates(t *testing.T) {
	// Trivy emits RPM PURLs with ?arch=...&distro=redhat-X.Y&epoch=N. Red Hat's
	// mainstream CSAF publishes bare PURLs (no distro). RH variants like
	// Hummingbird store with distro. The resolver must produce both candidates
	// so a scanner query can match either stored shape. Regression test for
	// v0.4.3 — without the stripped candidate, the bare RH form was unreachable.
	r := New(resolverTestDB(t))
	cands := r.Expand("pkg:rpm/redhat/openssl@3.0.7-25.el9_3?arch=x86_64&distro=redhat-9.3&epoch=1")

	ids := make(map[string]string, len(cands))
	for _, c := range cands {
		ids[c.ID] = c.MatchReason
	}
	if ids["pkg:rpm/redhat/openssl?distro=redhat-9.3"] != "direct" {
		t.Errorf("missing direct candidate with ?distro=redhat-9.3 in %v", ids)
	}
	if ids["pkg:rpm/redhat/openssl"] != "direct" {
		t.Errorf("missing distro-stripped direct candidate in %v", ids)
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

func TestExpand_AlpineDistroNormalization(t *testing.T) {
	// Alpine statements are stored branch-scoped as ?distro=alpine-<major.minor>.
	// A scanner's apk distro qualifier — Trivy's raw release "3.21.3" or syft's
	// "alpine-3.21.2" — must normalize to alpine-3.21 so it matches the stored
	// branch identity (and only that branch).
	r := New(resolverTestDB(t))
	for _, in := range []string{
		"pkg:apk/alpine/openssl@3.3.2-r0?arch=x86_64&distro=3.21.3",        // Trivy shape
		"pkg:apk/alpine/openssl@3.3.2-r0?arch=x86_64&distro=alpine-3.21.2", // syft shape
		"pkg:apk/alpine/openssl@3.3.2-r0?distro=3.21",                      // already minor
	} {
		ids := make(map[string]string)
		for _, c := range r.Expand(in) {
			ids[c.ID] = c.MatchReason
		}
		if ids["pkg:apk/alpine/openssl?distro=alpine-3.21"] != "direct" {
			t.Errorf("%s: missing normalized candidate ?distro=alpine-3.21 in %v", in, ids)
		}
		// The distro-stripped candidate is still produced (additive, harmless).
		if ids["pkg:apk/alpine/openssl"] != "direct" {
			t.Errorf("%s: missing distro-stripped candidate in %v", in, ids)
		}
	}
}

func TestNormalizeAlpineDistro(t *testing.T) {
	cases := map[string]string{
		"3.21.3":        "alpine-3.21",
		"alpine-3.21.2": "alpine-3.21",
		"3.21":          "alpine-3.21",
		"v3.21":         "alpine-3.21",
		"edge":          "", // no major.minor → no candidate
		"":              "",
	}
	for in, want := range cases {
		if got := normalizeAlpineDistro(in); got != want {
			t.Errorf("normalizeAlpineDistro(%q) = %q, want %q", in, got, want)
		}
	}
}
