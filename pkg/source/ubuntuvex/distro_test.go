package ubuntuvex

import "testing"

func TestNormalize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "non-PURL passes through",
			in:   "cpe:/a:redhat:log4j",
			want: "cpe:/a:redhat:log4j",
		},
		{
			name: "PURL without qualifiers passes through",
			in:   "pkg:deb/ubuntu/openssl",
			want: "pkg:deb/ubuntu/openssl",
		},
		{
			name: "unknown distro qualifier passes through",
			in:   "pkg:deb/ubuntu/openssl?distro=ubuntu/notarealrelease",
			want: "pkg:deb/ubuntu/openssl?distro=ubuntu/notarealrelease",
		},
		{
			name: "scanner-convention distro passes through (already normalized)",
			in:   "pkg:deb/ubuntu/openssl?distro=ubuntu-22.04",
			want: "pkg:deb/ubuntu/openssl?distro=ubuntu-22.04",
		},
		{
			name: "mainline ubuntu/jammy → ubuntu-22.04",
			in:   "pkg:deb/ubuntu/openssl?distro=ubuntu/jammy",
			want: "pkg:deb/ubuntu/openssl?distro=ubuntu-22.04",
		},
		{
			name: "mainline ubuntu/noble → ubuntu-24.04",
			in:   "pkg:deb/ubuntu/openssl?distro=ubuntu/noble",
			want: "pkg:deb/ubuntu/openssl?distro=ubuntu-24.04",
		},
		{
			name: "esm-apps/jammy → ubuntu-22.04",
			in:   "pkg:deb/ubuntu/openssl?distro=esm-apps/jammy",
			want: "pkg:deb/ubuntu/openssl?distro=ubuntu-22.04",
		},
		{
			name: "esm-infra/focal → ubuntu-20.04",
			in:   "pkg:deb/ubuntu/openssl?distro=esm-infra/focal",
			want: "pkg:deb/ubuntu/openssl?distro=ubuntu-20.04",
		},
		{
			name: "esm-infra-legacy/trusty → ubuntu-14.04",
			in:   "pkg:deb/ubuntu/linux?distro=esm-infra-legacy/trusty",
			want: "pkg:deb/ubuntu/linux?distro=ubuntu-14.04",
		},
		{
			name: "preserves other qualifiers (arch before distro)",
			in:   "pkg:deb/ubuntu/linux@4.15.0-1199?arch=source&distro=esm-infra-legacy/trusty",
			want: "pkg:deb/ubuntu/linux@4.15.0-1199?arch=source&distro=ubuntu-14.04",
		},
		{
			name: "preserves other qualifiers (distro before arch)",
			in:   "pkg:deb/ubuntu/linux@4.15.0-1199?distro=ubuntu/jammy&arch=amd64",
			want: "pkg:deb/ubuntu/linux@4.15.0-1199?distro=ubuntu-22.04&arch=amd64",
		},
		{
			name: "preserves fragment",
			in:   "pkg:deb/ubuntu/openssl?distro=ubuntu/jammy#extra",
			want: "pkg:deb/ubuntu/openssl?distro=ubuntu-22.04#extra",
		},
		{
			name: "no distro qualifier present passes through",
			in:   "pkg:deb/ubuntu/openssl?arch=amd64",
			want: "pkg:deb/ubuntu/openssl?arch=amd64",
		},
		{
			name: "version + many qualifiers",
			in:   "pkg:deb/ubuntu/linux-azure@4.15.0-1199.214~14.04.1?arch=source&distro=esm-infra-legacy/trusty",
			want: "pkg:deb/ubuntu/linux-azure@4.15.0-1199.214~14.04.1?arch=source&distro=ubuntu-14.04",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Normalize(tc.in)
			if got != tc.want {
				t.Errorf("Normalize(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalize_AllMappingsResolveToValidUbuntuVersion(t *testing.T) {
	// Every entry in the table must produce a `ubuntu-NN.MM` form. Defensive
	// against typos that would silently leak through.
	for k, v := range canonicalToScanner {
		if !startsWith(v, "ubuntu-") {
			t.Errorf("mapping %q -> %q does not start with 'ubuntu-'", k, v)
		}
	}
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
