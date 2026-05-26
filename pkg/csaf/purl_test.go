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
		// distro qualifier is identity and must be preserved on the base.
		{
			"pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.1?arch=amd64&distro=ubuntu-24.04",
			"pkg:deb/ubuntu/openssl?distro=ubuntu-24.04",
			"3.0.13-0ubuntu3.1",
		},
		// distro-only qualifier, no version.
		{
			"pkg:deb/ubuntu/openssl?distro=ubuntu-22.04",
			"pkg:deb/ubuntu/openssl?distro=ubuntu-22.04",
			"",
		},
		// Qualifier present but no distro — base is bare.
		{
			"pkg:rpm/redhat/log4j@1.2?arch=noarch&repository_id=rhel-8",
			"pkg:rpm/redhat/log4j",
			"1.2",
		},
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

func TestNormalizeScope(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// OCI image: repository_url is identity and is preserved; no version to strip.
		{
			"pkg:oci/aks-operator?repository_url=index.docker.io/rancher/aks-operator",
			"pkg:oci/aks-operator?repository_url=index.docker.io/rancher/aks-operator",
		},
		// OCI with a digest: the @sha256 suffix is dropped, repository_url kept.
		{
			"pkg:oci/longhorn-engine@sha256:abc123?repository_url=registry.suse.com/rancher/longhorn-engine",
			"pkg:oci/longhorn-engine?repository_url=registry.suse.com/rancher/longhorn-engine",
		},
		// Extra qualifiers (arch, tag) are dropped; only repository_url survives.
		{
			"pkg:oci/x@sha256:deadbeef?arch=amd64&repository_url=r.io/ns/x&tag=v1",
			"pkg:oci/x?repository_url=r.io/ns/x",
		},
		// Go module: strip @version, no qualifiers to keep.
		{
			"pkg:golang/github.com/harvester/harvester@v0.0.0-20240919204204-3da2ae0cabd1",
			"pkg:golang/github.com/harvester/harvester",
		},
		// Go module, already bare.
		{"pkg:golang/k8s.io/apimachinery", "pkg:golang/k8s.io/apimachinery"},
		// Subpath fragment is dropped along with the version.
		{"pkg:golang/x@v1.2.3#cmd/foo", "pkg:golang/x"},
		// Non-PURL (CPE) passes through, trimmed.
		{"  cpe:/a:rancher:rancher  ", "cpe:/a:rancher:rancher"},
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := NormalizeScope(tc.in); got != tc.want {
				t.Errorf("NormalizeScope(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
