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
			name: "unknown codename passes through",
			in:   "pkg:deb/ubuntu/openssl?distro=notarealcodename",
			want: "pkg:deb/ubuntu/openssl?distro=notarealcodename",
		},
		{
			name: "scanner-convention distro passes through (already normalized; ubuntu-22.04 isn't a codename)",
			in:   "pkg:deb/ubuntu/openssl?distro=ubuntu-22.04",
			want: "pkg:deb/ubuntu/openssl?distro=ubuntu-22.04",
		},
		// Bare codenames — the most common shape on mainline rows.
		{
			name: "bare codename: jammy → ubuntu-22.04",
			in:   "pkg:deb/ubuntu/openssl?distro=jammy",
			want: "pkg:deb/ubuntu/openssl?distro=ubuntu-22.04",
		},
		{
			name: "bare codename: noble → ubuntu-24.04",
			in:   "pkg:deb/ubuntu/openssl?distro=noble",
			want: "pkg:deb/ubuntu/openssl?distro=ubuntu-24.04",
		},
		{
			name: "bare codename: trusty → ubuntu-14.04",
			in:   "pkg:deb/ubuntu/openssl?distro=trusty",
			want: "pkg:deb/ubuntu/openssl?distro=ubuntu-14.04",
		},
		{
			name: "bare codename: questing → ubuntu-25.10 (interim)",
			in:   "pkg:deb/ubuntu/openssl?distro=questing",
			want: "pkg:deb/ubuntu/openssl?distro=ubuntu-25.10",
		},
		// ESM tracks.
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
		// FIPS / Realtime / Bluefield tracks — observed in CVE-2026-31431.
		{
			name: "fips/jammy → ubuntu-22.04",
			in:   "pkg:deb/ubuntu/linux?distro=fips/jammy",
			want: "pkg:deb/ubuntu/linux?distro=ubuntu-22.04",
		},
		{
			name: "fips-updates/noble → ubuntu-24.04",
			in:   "pkg:deb/ubuntu/linux?distro=fips-updates/noble",
			want: "pkg:deb/ubuntu/linux?distro=ubuntu-24.04",
		},
		{
			name: "fips-preview/jammy → ubuntu-22.04",
			in:   "pkg:deb/ubuntu/linux?distro=fips-preview/jammy",
			want: "pkg:deb/ubuntu/linux?distro=ubuntu-22.04",
		},
		{
			name: "realtime/noble → ubuntu-24.04",
			in:   "pkg:deb/ubuntu/linux?distro=realtime/noble",
			want: "pkg:deb/ubuntu/linux?distro=ubuntu-24.04",
		},
		{
			name: "bluefield/jammy → ubuntu-22.04",
			in:   "pkg:deb/ubuntu/linux?distro=bluefield/jammy",
			want: "pkg:deb/ubuntu/linux?distro=ubuntu-22.04",
		},
		// Hypothetical future track — last-segment-as-codename rule generalises.
		{
			name: "future-track/noble → ubuntu-24.04 (last segment as codename)",
			in:   "pkg:deb/ubuntu/linux?distro=brand-new-track/noble",
			want: "pkg:deb/ubuntu/linux?distro=ubuntu-24.04",
		},
		// Other-qualifier preservation.
		{
			name: "preserves other qualifiers (arch before distro)",
			in:   "pkg:deb/ubuntu/linux@4.15.0-1199?arch=source&distro=esm-infra-legacy/trusty",
			want: "pkg:deb/ubuntu/linux@4.15.0-1199?arch=source&distro=ubuntu-14.04",
		},
		{
			name: "preserves other qualifiers (distro before arch)",
			in:   "pkg:deb/ubuntu/linux@4.15.0-1199?distro=jammy&arch=amd64",
			want: "pkg:deb/ubuntu/linux@4.15.0-1199?distro=ubuntu-22.04&arch=amd64",
		},
		{
			name: "preserves fragment",
			in:   "pkg:deb/ubuntu/openssl?distro=jammy#extra",
			want: "pkg:deb/ubuntu/openssl?distro=ubuntu-22.04#extra",
		},
		{
			name: "no distro qualifier present passes through",
			in:   "pkg:deb/ubuntu/openssl?arch=amd64",
			want: "pkg:deb/ubuntu/openssl?arch=amd64",
		},
		{
			name: "version + many qualifiers (CVE-2026-31431 shape)",
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
	for k, v := range codenameToVersion {
		if !startsWith(v, "ubuntu-") {
			t.Errorf("mapping %q -> %q does not start with 'ubuntu-'", k, v)
		}
	}
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
