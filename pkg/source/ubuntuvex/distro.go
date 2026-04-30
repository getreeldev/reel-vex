package ubuntuvex

import "strings"

// canonicalToScanner maps the `?distro=` qualifier values that Canonical
// emits in their OpenVEX feed to the `ubuntu-<version>` form that scanners
// (Trivy, Grype) emit. Three Canonical conventions exist:
//
//   - ubuntu/<codename>           — mainline supported releases
//   - esm-apps/<codename>         — Ubuntu Pro ESM Apps tier (post-EOL apps)
//   - esm-infra/<codename>        — Ubuntu Pro ESM Infra tier (post-EOL OS)
//   - esm-infra-legacy/<codename> — older EOL releases on the legacy ESM tier
//
// Three-to-one is expected: a single Ubuntu release can carry rows under all
// three ESM tracks plus the mainline. The dedup step in adapter.Sync collapses
// these so we don't emit duplicate rows per CVE × release.
//
// Update this table when Canonical adds a new release codename (rare).
var canonicalToScanner = map[string]string{
	// Mainline releases.
	"ubuntu/precise":  "ubuntu-12.04",
	"ubuntu/trusty":   "ubuntu-14.04",
	"ubuntu/xenial":   "ubuntu-16.04",
	"ubuntu/bionic":   "ubuntu-18.04",
	"ubuntu/focal":    "ubuntu-20.04",
	"ubuntu/jammy":    "ubuntu-22.04",
	"ubuntu/kinetic":  "ubuntu-22.10",
	"ubuntu/lunar":    "ubuntu-23.04",
	"ubuntu/mantic":   "ubuntu-23.10",
	"ubuntu/noble":    "ubuntu-24.04",
	"ubuntu/oracular": "ubuntu-24.10",
	"ubuntu/plucky":   "ubuntu-25.04",
	// ESM Apps.
	"esm-apps/trusty": "ubuntu-14.04",
	"esm-apps/xenial": "ubuntu-16.04",
	"esm-apps/bionic": "ubuntu-18.04",
	"esm-apps/focal":  "ubuntu-20.04",
	"esm-apps/jammy":  "ubuntu-22.04",
	"esm-apps/noble":  "ubuntu-24.04",
	// ESM Infra.
	"esm-infra/xenial": "ubuntu-16.04",
	"esm-infra/bionic": "ubuntu-18.04",
	"esm-infra/focal":  "ubuntu-20.04",
	"esm-infra/jammy":  "ubuntu-22.04",
	"esm-infra/noble":  "ubuntu-24.04",
	// ESM Infra Legacy.
	"esm-infra-legacy/precise": "ubuntu-12.04",
	"esm-infra-legacy/trusty":  "ubuntu-14.04",
	"esm-infra-legacy/xenial":  "ubuntu-16.04",
}

// Normalize rewrites the `?distro=` qualifier in rawPurl to the
// scanner-convention `ubuntu-<version>` form when the original value matches
// a known Canonical track. Non-PURL identifiers, PURLs without a distro
// qualifier, and unknown distro values pass through unchanged.
//
// Other qualifiers (arch, epoch, etc.) and any fragment are preserved
// verbatim — only the distro qualifier value is rewritten.
func Normalize(rawPurl string) string {
	if !strings.HasPrefix(rawPurl, "pkg:") {
		return rawPurl
	}
	qIdx := strings.IndexByte(rawPurl, '?')
	if qIdx < 0 {
		return rawPurl
	}
	base := rawPurl[:qIdx]
	rest := rawPurl[qIdx+1:]
	var frag string
	if hashIdx := strings.IndexByte(rest, '#'); hashIdx >= 0 {
		frag = rest[hashIdx:]
		rest = rest[:hashIdx]
	}
	parts := strings.Split(rest, "&")
	for i, p := range parts {
		eq := strings.IndexByte(p, '=')
		if eq < 0 {
			continue
		}
		if p[:eq] != "distro" {
			continue
		}
		mapped, ok := canonicalToScanner[p[eq+1:]]
		if !ok {
			return rawPurl
		}
		parts[i] = "distro=" + mapped
		return base + "?" + strings.Join(parts, "&") + frag
	}
	return rawPurl
}
