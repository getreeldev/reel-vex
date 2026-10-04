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
// The subpath (`#...`) is not part of the base either: it names a part of the
// package, and the statements are about the package. The version is found the
// way StripPURLVersion finds it — the text after the first '@' of the last path
// segment — so a namespace's '@' (npm scopes) is never read as one.
//
// Examples:
//
//	pkg:rpm/redhat/log4j@1.2.17-18.el8?arch=noarch
//	    → base: pkg:rpm/redhat/log4j, version: 1.2.17-18.el8
//	pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.1?arch=amd64&distro=ubuntu-24.04
//	    → base: pkg:deb/ubuntu/openssl?distro=ubuntu-24.04, version: 3.0.13-0ubuntu3.1
//	pkg:npm/@angular/core
//	    → base: pkg:npm/@angular/core, version: ""
//	cpe:/a:redhat:log4j:1.2
//	    → base: cpe:/a:redhat:log4j:1.2, version: "" (CPEs aren't decomposed)
func SplitPURL(id string) (base, version string) {
	if !strings.HasPrefix(id, "pkg:") {
		return id, ""
	}

	if i := strings.IndexByte(id, '#'); i >= 0 {
		id = id[:i]
	}

	var distro string
	if i := strings.IndexByte(id, '?'); i >= 0 {
		if vals, err := url.ParseQuery(id[i+1:]); err == nil {
			distro = vals.Get("distro")
		}
		id = id[:i]
	}

	start := strings.LastIndexByte(id, '/') + 1
	if i := strings.IndexByte(id[start:], '@'); i >= 0 {
		base, version = id[:start+i], id[start+i+1:]
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

// PURLArch returns the `arch` qualifier of a PURL, or "" when the identifier
// is not a PURL, carries no qualifiers, or has no arch.
//
// SplitPURL strips arch from the base form on purpose — matching is
// arch-blind by default because the feeds disagree wildly about whether to
// qualify at all (Canonical's OpenVEX qualifies ~100% of rows, Red Hat CSAF
// ~69%, every other wired source 0%), so exact matching would turn most of
// the corpus into false negatives. This helper exists for the caller that
// opts into arch-precise matching and therefore needs the value back.
func PURLArch(id string) string {
	if !strings.HasPrefix(id, "pkg:") {
		return ""
	}
	q := strings.IndexByte(id, '?')
	if q < 0 {
		return ""
	}
	qualifiers := id[q+1:]
	if i := strings.IndexByte(qualifiers, '#'); i >= 0 {
		qualifiers = qualifiers[:i]
	}
	vals, err := url.ParseQuery(qualifiers)
	if err != nil {
		return ""
	}
	return vals.Get("arch")
}

// ArchIndependent reports whether an arch qualifier value means the statement
// holds regardless of the consumer's architecture.
//
// Getting this set right is not cosmetic. Red Hat writes `src` for source
// packages and `noarch` for architecture-independent ones; Ubuntu writes
// `source`; Debian and Ubuntu write `all`. Treating any of these as a
// concrete architecture would make arch-precise matching silently discard
// real vendor verdicts — the one failure mode a suppression service must
// never have.
func ArchIndependent(arch string) bool {
	switch arch {
	case "", "noarch", "src", "source", "all":
		return true
	}
	return false
}

// StripPURLVersion splits a PURL into the identifier without its @version and
// the version itself. Unlike SplitPURL, every qualifier and the subpath are
// kept, as written:
//
//	pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?arch=amd64&distro=ubuntu-22.04
//	    → pkg:deb/ubuntu/openssl?arch=amd64&distro=ubuntu-22.04, 3.0.2-0ubuntu1.10
//
// The version is the text after the first '@' of the last path segment (a
// namespace may carry an '@', a name may not), returned as written. Non-PURL
// identifiers and PURLs without a version are returned unchanged with an
// empty version.
func StripPURLVersion(id string) (versionless, version string) {
	if !strings.HasPrefix(id, "pkg:") {
		return id, ""
	}
	end := len(id)
	if i := strings.IndexAny(id, "?#"); i >= 0 {
		end = i
	}
	start := strings.LastIndexByte(id[:end], '/') + 1
	at := strings.IndexByte(id[start:end], '@')
	if at < 0 {
		return id, ""
	}
	at += start
	return id[:at] + id[end:], id[at+1 : end]
}

// InsertPURLVersion is the inverse of StripPURLVersion: it puts @version into
// a versionless PURL before its qualifiers and subpath. An empty version, or
// an identifier that is not a PURL, is returned unchanged.
func InsertPURLVersion(versionless, version string) string {
	if version == "" || !strings.HasPrefix(versionless, "pkg:") {
		return versionless
	}
	end := len(versionless)
	if i := strings.IndexAny(versionless, "?#"); i >= 0 {
		end = i
	}
	return versionless[:end] + "@" + version + versionless[end:]
}

// RenderPURLVersion puts a vendor-stated version into a versionless PURL the
// way a PURL writer does (packageurl-go, and so Trivy). For pkg:deb and pkg:rpm
// a version with an inline epoch — Canonical writes
// bind9@1:9.11.3+dfsg-1ubuntu1.17 — is written without it, percent-encoded as
// packageurl-go encodes it, and a non-zero epoch is appended as the `epoch`
// qualifier after the qualifiers already there:
//
//	pkg:deb/ubuntu/bind9?arch=amd64&distro=ubuntu-18.04, 1:9.11.3+dfsg-1ubuntu1.17
//	    → pkg:deb/ubuntu/bind9@9.11.3%2Bdfsg-1ubuntu1.17?arch=amd64&distro=ubuntu-18.04&epoch=1
//
// That is the identifier Trivy writes for the package, and Trivy applies a VEX
// statement only when the product's version equals the package's, so the
// inline form suppresses nothing. Every other version, and an identifier that
// already carries an epoch qualifier, is put back as written (InsertPURLVersion).
func RenderPURLVersion(versionless, version string) string {
	if !strings.HasPrefix(versionless, "pkg:deb/") && !strings.HasPrefix(versionless, "pkg:rpm/") {
		return InsertPURLVersion(versionless, version)
	}
	v := UnescapeVersion(version)
	epoch, rest, ok := strings.Cut(v, ":")
	if !ok || epoch == "" || strings.Trim(epoch, "0123456789") != "" || purlHasQualifier(versionless, "epoch") {
		return InsertPURLVersion(versionless, version)
	}
	out := InsertPURLVersion(versionless, strings.ReplaceAll(url.QueryEscape(rest), "+", "%20"))
	if strings.Trim(epoch, "0") == "" {
		return out
	}
	end := len(out)
	if i := strings.IndexByte(out, '#'); i >= 0 {
		end = i
	}
	sep := "?"
	if strings.Contains(out[:end], "?") {
		sep = "&"
	}
	return out[:end] + sep + "epoch=" + epoch + out[end:]
}

// purlHasQualifier reports whether a PURL carries the qualifier key.
func purlHasQualifier(id, key string) bool {
	q := strings.IndexByte(id, '?')
	if q < 0 {
		return false
	}
	qualifiers := id[q+1:]
	if i := strings.IndexByte(qualifiers, '#'); i >= 0 {
		qualifiers = qualifiers[:i]
	}
	for _, kv := range strings.Split(qualifiers, "&") {
		if k, _, _ := strings.Cut(kv, "="); k == key {
			return true
		}
	}
	return false
}

// MatchVersion returns the version a caller's PURL names, in the form an
// exact-list row stores it: percent-decoded (UnescapeVersion), and with a
// non-zero `epoch` qualifier folded in as "<epoch>:<version>" when the version
// carries no epoch of its own — Canonical writes epochs inline
// (bind9@1:9.11.3+dfsg-1ubuntu1.17), scanners write them as a qualifier.
// Empty for a non-PURL or a PURL without a version.
func MatchVersion(id string) string {
	_, v := StripPURLVersion(id)
	if v == "" {
		return ""
	}
	v = UnescapeVersion(v)
	if strings.Contains(v, ":") {
		return v
	}
	q := strings.IndexByte(id, '?')
	if q < 0 {
		return v
	}
	qualifiers := id[q+1:]
	if i := strings.IndexByte(qualifiers, '#'); i >= 0 {
		qualifiers = qualifiers[:i]
	}
	for _, kv := range strings.Split(qualifiers, "&") {
		k, val, ok := strings.Cut(kv, "=")
		if !ok || k != "epoch" {
			continue
		}
		if val = UnescapeVersion(val); strings.Trim(val, "0") != "" {
			return val + ":" + v
		}
	}
	return v
}

// UnescapeVersion percent-decodes a PURL version with url.PathUnescape, so
// "%2B" and a literal '+' compare equal. Never url.QueryUnescape, which reads
// the '+' of "+dfsg" as a space. A version that does not decode is returned
// as written.
func UnescapeVersion(v string) string {
	if !strings.Contains(v, "%") {
		return v
	}
	if u, err := url.PathUnescape(v); err == nil {
		return u
	}
	return v
}
