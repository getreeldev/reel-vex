package csaf

import "testing"

func TestSplitPURL(t *testing.T) {
	cases := []struct {
		in          string
		wantBase    string
		wantVersion string
	}{
		// Versioned PURL with qualifiers
		{"pkg:rpm/redhat/log4j@1.2.17-18.el8?arch=noarch", "pkg:rpm/redhat/log4j", "1.2.17-18.el8"},
		// Versioned PURL without qualifiers
		{"pkg:rpm/redhat/log4j@2.17.0-1", "pkg:rpm/redhat/log4j", "2.17.0-1"},
		// Unversioned PURL
		{"pkg:rpm/redhat/log4j", "pkg:rpm/redhat/log4j", ""},
		// OCI PURL with digest as version and repository qualifiers
		{
			"pkg:oci/cluster-logging@sha256:abc123?repository_url=registry.redhat.io",
			"pkg:oci/cluster-logging",
			"sha256:abc123",
		},
		// PURL with subpath
		{"pkg:maven/org.apache/log4j@2.16.0#some/path", "pkg:maven/org.apache/log4j", "2.16.0"},
		// CPE should pass through unchanged
		{"cpe:/a:redhat:enterprise_linux:9", "cpe:/a:redhat:enterprise_linux:9", ""},
		// Empty
		{"", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			base, version := SplitPURL(tc.in)
			if base != tc.wantBase {
				t.Errorf("base: got %q, want %q", base, tc.wantBase)
			}
			if version != tc.wantVersion {
				t.Errorf("version: got %q, want %q", version, tc.wantVersion)
			}
		})
	}
}
