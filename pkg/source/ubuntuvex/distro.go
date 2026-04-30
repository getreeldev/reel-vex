package ubuntuvex

import "strings"

// codenameToVersion maps Ubuntu release codenames to the
// scanner-convention `ubuntu-<version>` form.
//
// Canonical's `?distro=` qualifier comes in many shapes — `<codename>` for
// mainline, `<track>/<codename>` for support tiers (esm-apps, esm-infra,
// esm-infra-legacy, fips, fips-preview, fips-updates, realtime, bluefield,
// and almost certainly more in the future). The track is metadata about
// which support tier the row is from; the codename is the underlying
// release. Scanners only emit `ubuntu-<version>`, so reducing every
// `<track>/<codename>` to its codename is the correct collapse for query
// matching. Many-to-one is by design — rows from different tracks for the
// same release dedupe at emit time.
//
// Update this table when Canonical ships a new release codename (rare).
var codenameToVersion = map[string]string{
	"precise":  "ubuntu-12.04",
	"trusty":   "ubuntu-14.04",
	"xenial":   "ubuntu-16.04",
	"bionic":   "ubuntu-18.04",
	"focal":    "ubuntu-20.04",
	"jammy":    "ubuntu-22.04",
	"kinetic":  "ubuntu-22.10",
	"lunar":    "ubuntu-23.04",
	"mantic":   "ubuntu-23.10",
	"noble":    "ubuntu-24.04",
	"oracular": "ubuntu-24.10",
	"plucky":   "ubuntu-25.04",
	"questing": "ubuntu-25.10",
	"resolute": "ubuntu-26.04",
}

// Normalize rewrites the `?distro=` qualifier in rawPurl to the
// scanner-convention `ubuntu-<version>` form. Inputs of every shape we've
// seen from Canonical work the same way: take the last `/`-separated
// segment as the codename, look it up. Non-PURL identifiers, PURLs without
// a distro qualifier, and unknown codenames pass through unchanged.
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
		// Take the last `/`-separated segment as the codename. Works for
		// bare `xenial`, `esm-infra/xenial`, `fips-updates/jammy`, and any
		// future `<track>/<codename>` variant Canonical introduces.
		val := p[eq+1:]
		codename := val
		if slash := strings.LastIndexByte(val, '/'); slash >= 0 {
			codename = val[slash+1:]
		}
		mapped, ok := codenameToVersion[codename]
		if !ok {
			return rawPurl
		}
		parts[i] = "distro=" + mapped
		return base + "?" + strings.Join(parts, "&") + frag
	}
	return rawPurl
}
