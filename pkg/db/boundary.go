package db

import (
	"strings"

	apkversion "github.com/knqyf263/go-apk-version"
	debversion "github.com/knqyf263/go-deb-version"
	rpmversion "github.com/knqyf263/go-rpm-version"
)

// VersionKindBoundary marks a `fixed` row whose Versions are the fixed-in
// versions the vendor stated (the OVAL feeds, Alpine secdb, Amazon ALAS): a
// versioned query gets the row only at or above them, compared in the
// ecosystem's version ordering (BoundaryReaches).
const VersionKindBoundary = "boundary"

// BoundaryFilter is QueryFilters.BoundaryVersions resolved per base: the bases
// the caller named only with versions, each with the set of versions named.
type BoundaryFilter map[string]map[string]bool

// NewBoundaryFilter resolves pairs into a BoundaryFilter. A base named at
// least once without a version is left out: it keeps every boundary row, as a
// query without a version always has.
func NewBoundaryFilter(pairs []BaseVersion) BoundaryFilter {
	return BoundaryFilter(NewExactFilter(pairs))
}

// Keeps is the one boundary rule every store applies to a row it read: a
// boundary row with a fixed-in version, under a base the filter names, is kept
// only when some version named for that base reaches it (BoundaryReaches).
// Every other row is kept.
func (f BoundaryFilter) Keeps(s Statement) bool {
	want, ok := f[s.BaseID]
	if !ok || s.VersionKind != VersionKindBoundary || len(s.Versions) == 0 {
		return true
	}
	for v := range want {
		if BoundaryReaches(s, v) {
			return true
		}
	}
	return false
}

// BoundaryReaches reports whether version v (csaf.MatchVersion form: an epoch,
// when there is one, inline as "N:") is at or above every fixed-in version of
// boundary row s, in the version ordering of the row's ecosystem — dpkg for
// pkg:deb, rpm for pkg:rpm, apk for pkg:apk. A missing epoch is 0 on both
// sides. A version either side that the ordering cannot parse, and an
// ecosystem with no ordering here, reach nothing: the row is then withheld,
// which can only cost a `fixed` answer, never invent one. A row that is not a
// boundary row, or has no version, is reached by any version.
//
// The stores keep one fixed-in version per row today (the feeds state one per
// row), so "every" is the stated version; a list of several, which would be
// the boundaries of parallel streams, is reached only at or above all of them
// — never the lowest, which would call an unpatched build of a higher stream
// fixed.
func BoundaryReaches(s Statement, v string) bool {
	if s.VersionKind != VersionKindBoundary || len(s.Versions) == 0 {
		return true
	}
	if v == "" {
		return false
	}
	cmp := boundaryOrdering(s.BaseID)
	if cmp == nil {
		return false
	}
	for _, b := range s.Versions {
		if c, ok := cmp(v, b); !ok || c < 0 {
			return false
		}
	}
	return true
}

// boundaryOrdering returns the comparison of a base identifier's ecosystem:
// it reports a's order against b (-1, 0, 1) and false when either does not
// parse. nil for an ecosystem with no ordering here.
func boundaryOrdering(base string) func(a, b string) (int, bool) {
	switch {
	case strings.HasPrefix(base, "pkg:deb/"):
		return compareDeb
	case strings.HasPrefix(base, "pkg:rpm/"):
		return compareRPM
	case strings.HasPrefix(base, "pkg:apk/"):
		return compareAPK
	}
	return nil
}

func compareDeb(a, b string) (int, bool) {
	va, err := debversion.NewVersion(a)
	if err != nil {
		return 0, false
	}
	vb, err := debversion.NewVersion(b)
	if err != nil {
		return 0, false
	}
	return va.Compare(vb), true
}

// compareRPM orders two rpm [epoch:]version[-release] strings. The library
// never fails a parse (an unreadable epoch becomes 0), so the shape is checked
// here: a version must be present and an epoch, when written, a number.
func compareRPM(a, b string) (int, bool) {
	if !validRPM(a) || !validRPM(b) {
		return 0, false
	}
	return rpmversion.NewVersion(a).Compare(rpmversion.NewVersion(b)), true
}

func validRPM(v string) bool {
	epoch, rest, ok := strings.Cut(v, ":")
	if !ok {
		rest = epoch
	} else if epoch == "" || strings.Trim(epoch, "0123456789") != "" {
		return false
	}
	return rest != "" && !strings.HasPrefix(rest, "-")
}

func compareAPK(a, b string) (int, bool) {
	va, err := apkversion.NewVersion(a)
	if err != nil {
		return 0, false
	}
	vb, err := apkversion.NewVersion(b)
	if err != nil {
		return 0, false
	}
	return va.Compare(vb), true
}
