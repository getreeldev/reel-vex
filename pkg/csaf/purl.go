package csaf

import "strings"

// SplitPURL parses a Package URL into its base form (type/namespace/name) and
// version. For non-PURL identifiers, returns the input unchanged as base with
// an empty version.
//
// Examples:
//
//	pkg:rpm/redhat/log4j@1.2.17-18.el8?arch=noarch
//	    → base: pkg:rpm/redhat/log4j, version: 1.2.17-18.el8
//	pkg:rpm/redhat/log4j
//	    → base: pkg:rpm/redhat/log4j, version: ""
//	cpe:/a:redhat:log4j:1.2
//	    → base: cpe:/a:redhat:log4j:1.2, version: "" (CPEs aren't decomposed)
func SplitPURL(id string) (base, version string) {
	if !strings.HasPrefix(id, "pkg:") {
		return id, ""
	}

	// Strip qualifiers (anything after ?)
	if i := strings.IndexByte(id, '?'); i >= 0 {
		id = id[:i]
	}

	// Strip subpath (anything after #)
	if i := strings.IndexByte(id, '#'); i >= 0 {
		id = id[:i]
	}

	// Split version
	if i := strings.LastIndexByte(id, '@'); i >= 0 {
		return id[:i], id[i+1:]
	}

	return id, ""
}
