package csaf

import (
	"net/url"
	"strings"
)

// SplitPURL parses a Package URL into its base form (type/namespace/name) and
// version. For non-PURL identifiers, returns the input unchanged as base with
// an empty version.
//
// The `distro` qualifier is preserved on the base form because it is identity,
// not a filter — `pkg:deb/ubuntu/openssl?distro=ubuntu-24.04` and
// `?distro=ubuntu-22.04` describe different packages with different fixed
// versions. `arch`, `epoch`, `repository_id` and other qualifiers are
// scanner-side filters and are stripped.
//
// Examples:
//
//	pkg:rpm/redhat/log4j@1.2.17-18.el8?arch=noarch
//	    → base: pkg:rpm/redhat/log4j, version: 1.2.17-18.el8
//	pkg:deb/ubuntu/openssl@3.0.13@4?distro=ubuntu-24.04
//	    → base: pkg:deb/ubuntu/openssl?distro=ubuntu-24.04, version: 3.0.13@4
//	cpe:/a:redhat:log4j:1.2
//	    → base: cpe:/a:redhat:log4j:1.2, version: "" (CPEs aren't decomposed)
func SplitPURL(id string) (base, version string) {
	if !strings.HasPrefix(id, "pkg:") {
		return id, ""
	}

	var distro string
	if i := strings.IndexByte(id, '?'); i >= 0 {
		if vals, err := url.ParseQuery(id[i+1:]); err == nil {
			distro = vals.Get("distro")
		}
		id = id[:i]
	}

	if i := strings.IndexByte(id, '#'); i >= 0 {
		id = id[:i]
	}

	if i := strings.LastIndexByte(id, '@'); i >= 0 {
		base, version = id[:i], id[i+1:]
	} else {
		base = id
	}
	if distro != "" {
		base += "?distro=" + distro
	}
	return base, version
}

// NormalizeScope canonicalizes an OpenVEX product identifier for use as a
// statement *scope* key. Unlike SplitPURL — which strips nearly every
// qualifier — it preserves the identity-bearing `repository_url` (for pkg:oci
// the registry/repository *is* the image identity) while dropping the version
// or digest (the @-suffix), the subpath fragment, and all other qualifiers.
// Non-PURL identifiers (e.g. CPEs) are returned trimmed and otherwise
// unchanged.
//
// Both the Rancher VEX adapter (at ingest) and the API scope gate (at query
// time) call this so a scanned image's root component and a stored scope
// canonicalize to the same string. A normalization mismatch only ever costs a
// missed suppression, never a false one, so byte-exact qualifier fidelity is
// not required.
func NormalizeScope(id string) string {
	id = strings.TrimSpace(id)
	if id == "" || !strings.HasPrefix(id, "pkg:") {
		return id
	}

	var repoURL string
	if i := strings.IndexByte(id, '?'); i >= 0 {
		if vals, err := url.ParseQuery(id[i+1:]); err == nil {
			repoURL = vals.Get("repository_url")
		}
		id = id[:i]
	}
	if i := strings.IndexByte(id, '#'); i >= 0 {
		id = id[:i]
	}
	if i := strings.LastIndexByte(id, '@'); i >= 0 {
		id = id[:i]
	}
	if repoURL != "" {
		id += "?repository_url=" + repoURL
	}
	return id
}
