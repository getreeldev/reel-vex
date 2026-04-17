package resolver

import "testing"

func TestCPEPrefix(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// SECDATA-1220 scenario: scanner query with variant, stored statement without.
		{"cpe:/o:redhat:enterprise_linux:8::baseos", "cpe:/o:redhat:enterprise_linux:8"},
		{"cpe:/a:redhat:enterprise_linux:8::appstream", "cpe:/a:redhat:enterprise_linux:8"},
		{"cpe:/a:redhat:rhel_eus:9.6::appstream", "cpe:/a:redhat:rhel_eus:9.6"},

		// Already at or below 5 parts.
		{"cpe:/o:redhat:enterprise_linux:8", "cpe:/o:redhat:enterprise_linux:8"},
		{"cpe:/a:redhat:rhel:8:2", "cpe:/a:redhat:rhel:8:2"},

		// Empty trailing update with trailing colons stripped.
		{"cpe:/o:redhat:enterprise_linux:8::", "cpe:/o:redhat:enterprise_linux:8"},

		// Non-CPE passthrough.
		{"pkg:rpm/redhat/openssl@3.0", "pkg:rpm/redhat/openssl@3.0"},
		{"pkg:rpm/redhat/openssl", "pkg:rpm/redhat/openssl"},

		// Degenerate but not crashing.
		{"cpe:/", "cpe:/"},
		{"cpe:/a", "cpe:/a"},
	}
	for _, tc := range cases {
		got := CPEPrefix(tc.in)
		if got != tc.want {
			t.Errorf("CPEPrefix(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
