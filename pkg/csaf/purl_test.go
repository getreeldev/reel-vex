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

func TestPURLArch(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want string
	}{
		{"redhat rpm", "pkg:rpm/redhat/openssl@3.0.7-1.el9?arch=x86_64", "x86_64"},
		{"ubuntu deb with distro", "pkg:deb/ubuntu/tar@1.34-1?arch=arm64&distro=ubuntu-22.04", "arm64"},
		{"arch not first qualifier", "pkg:deb/ubuntu/tar@1.34-1?distro=ubuntu-22.04&arch=s390x", "s390x"},
		{"noarch", "pkg:rpm/redhat/log4j@1.2.17?arch=noarch", "noarch"},
		{"no qualifiers", "pkg:rpm/redhat/openssl@3.0.7", ""},
		{"qualifiers but no arch", "pkg:deb/ubuntu/tar@1.34-1?distro=ubuntu-22.04", ""},
		{"empty arch value", "pkg:rpm/redhat/openssl@3.0.7?arch=", ""},
		{"url-encoded value", "pkg:generic/x@1?arch=x86%5F64", "x86_64"},
		{"subpath fragment after qualifiers", "pkg:golang/x/y@1?arch=amd64#sub/dir", "amd64"},
		{"cpe input", "cpe:/a:redhat:openssl:3.0", ""},
		{"empty input", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PURLArch(tt.id); got != tt.want {
				t.Errorf("PURLArch(%q) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}

// TestArchIndependent names the vendor behind each value so the set can't be
// trimmed without someone noticing which feed it breaks.
func TestArchIndependent(t *testing.T) {
	independent := map[string]string{
		"":       "no arch qualifier at all — every CSAF/OVAL feed but Red Hat's",
		"noarch": "Red Hat, architecture-independent RPM",
		"src":    "Red Hat, source RPM",
		"source": "Ubuntu, source package",
		"all":    "Debian/Ubuntu, architecture-independent deb",
	}
	for v, why := range independent {
		if !ArchIndependent(v) {
			t.Errorf("ArchIndependent(%q) = false, want true (%s)", v, why)
		}
	}
	for _, v := range []string{"x86_64", "amd64", "arm64", "armhf", "i386", "ppc64el", "riscv64", "s390x", "aarch64"} {
		if ArchIndependent(v) {
			t.Errorf("ArchIndependent(%q) = true, want false", v)
		}
	}
}

func TestStripAndInsertPURLVersion(t *testing.T) {
	cases := []struct{ in, versionless, version string }{
		{"pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?arch=amd64&distro=ubuntu-22.04", "pkg:deb/ubuntu/openssl?arch=amd64&distro=ubuntu-22.04", "3.0.2-0ubuntu1.10"},
		{"pkg:deb/ubuntu/zlib1g@1:1.2.11.dfsg-2ubuntu9.2?arch=amd64&distro=ubuntu-22.04", "pkg:deb/ubuntu/zlib1g?arch=amd64&distro=ubuntu-22.04", "1:1.2.11.dfsg-2ubuntu9.2"},
		{"pkg:golang/golang.org/x/net@v0.35.0", "pkg:golang/golang.org/x/net", "v0.35.0"},
		{"pkg:maven/org.apache/log4j@2.16.0?type=jar#some/path", "pkg:maven/org.apache/log4j?type=jar#some/path", "2.16.0"},
		{"pkg:npm/%40angular/core@16.0.0", "pkg:npm/%40angular/core", "16.0.0"},
		{"pkg:apk/alpine/zlib", "pkg:apk/alpine/zlib", ""},
		{"pkg:deb/ubuntu/curl?arch=amd64", "pkg:deb/ubuntu/curl?arch=amd64", ""},
		{"cpe:/a:redhat:enterprise_linux:9", "cpe:/a:redhat:enterprise_linux:9", ""},
	}
	for _, c := range cases {
		vl, v := StripPURLVersion(c.in)
		if vl != c.versionless || v != c.version {
			t.Errorf("StripPURLVersion(%q) = %q, %q; want %q, %q", c.in, vl, v, c.versionless, c.version)
		}
		if c.version != "" {
			if got := InsertPURLVersion(vl, v); got != c.in {
				t.Errorf("InsertPURLVersion(%q, %q) = %q, want %q", vl, v, got, c.in)
			}
		}
	}
	if got := InsertPURLVersion("pkg:apk/alpine/zlib", ""); got != "pkg:apk/alpine/zlib" {
		t.Errorf("an empty version must leave the identifier unchanged, got %q", got)
	}
}

func TestMatchVersion(t *testing.T) {
	cases := []struct{ in, want string }{
		{"pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?arch=amd64&distro=ubuntu-22.04", "3.0.2-0ubuntu1.10"},
		// PathUnescape, never QueryUnescape: %2B is '+', and '+' stays '+'.
		{"pkg:deb/ubuntu/dolibarr@3.5.8%2Bdfsg1-1ubuntu1%2Besm1?arch=amd64", "3.5.8+dfsg1-1ubuntu1+esm1"},
		{"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=amd64", "3.5.8+dfsg1-1ubuntu1+esm1"},
		// A non-zero epoch qualifier folds in; zero and an inline epoch do not.
		{"pkg:deb/ubuntu/zlib1g@1.2.11.dfsg-2ubuntu9.2?arch=amd64&distro=ubuntu-22.04&epoch=1", "1:1.2.11.dfsg-2ubuntu9.2"},
		{"pkg:deb/ubuntu/zlib1g@1.2.11.dfsg-2ubuntu9.2?epoch=0&arch=amd64", "1.2.11.dfsg-2ubuntu9.2"},
		{"pkg:deb/ubuntu/bind9@1:9.11.3%2Bdfsg-1ubuntu1.17?epoch=1", "1:9.11.3+dfsg-1ubuntu1.17"},
		{"pkg:deb/ubuntu/bind9@1%3A9.11.3?epoch=1", "1:9.11.3"},
		{"pkg:deb/ubuntu/zlib1g?epoch=1", ""},
		{"cpe:/a:redhat:enterprise_linux:9", ""},
		// A malformed escape is compared as written.
		{"pkg:golang/x@v1%zz", "v1%zz"},
	}
	for _, c := range cases {
		if got := MatchVersion(c.in); got != c.want {
			t.Errorf("MatchVersion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
