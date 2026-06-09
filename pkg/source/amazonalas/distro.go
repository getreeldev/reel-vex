package amazonalas

import (
	"fmt"
	"net/url"
	"strings"
)

// distroSpec carries the per-distro constants the adapter needs once the distro
// has been identified from its mirror.list URL.
type distroSpec struct {
	// major is the version token used in the PURL distro qualifier: "2" for
	// Amazon Linux 2, "2023" for Amazon Linux 2023.
	major string
	// displayName is the human-readable vendor-row name used when config Name
	// is empty.
	displayName string
}

// baseID builds the version-less, distro-qualified RPM PURL base for a package
// name — the matchable identity stored as base_id. Mirrors the deb feeds'
// shape (pkg:deb/<vendor>/<name>?distro=<vendor>-<ver>): distro is identity
// (amzn2 vs amzn2023 are different packages). The resolver normalizes a
// scanner's full point-release distro (e.g. amazon-2023.7.x) down to
// amazon-<major> so the query matches this major-scoped base precisely.
func (d distroSpec) baseID(name string) string {
	return "pkg:rpm/amazon/" + name + "?distro=amazon-" + d.major
}

// distroFromMirrorURL infers the Amazon Linux distro from a core-repo
// mirror.list URL. The two supported shapes:
//
//	https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list              -> amzn2
//	https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list -> al2023
//
// Detection keys on the path segments rather than the full string so a mirror
// host change doesn't break it. An unrecognised path is a hard error: a silent
// wrong-distro guess would mislabel every statement's ?distro= qualifier.
func distroFromMirrorURL(rawURL string) (distroSpec, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return distroSpec{}, fmt.Errorf("parse mirror url %q: %w", rawURL, err)
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	for _, seg := range segs {
		switch seg {
		case "al2023":
			return distroSpec{major: "2023", displayName: "Amazon Linux 2023"}, nil
		case "2":
			return distroSpec{major: "2", displayName: "Amazon Linux 2"}, nil
		}
	}
	return distroSpec{}, fmt.Errorf("cannot infer Amazon Linux distro from url %q: "+
		"expected a path segment of \"2\" (amzn2) or \"al2023\"", rawURL)
}
