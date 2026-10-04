package source

import "github.com/getreeldev/reel-vex/pkg/db"

// FixedInKind is the VersionKind of a statement from a feed that states a fix
// as a fixed-in version (the OVAL feeds, Alpine secdb, Amazon ALAS):
// db.VersionKindBoundary for a `fixed` statement carrying that version, so a
// versioned query gets it only at or above the version; empty for everything
// else — a verdict stated with no version (Debian's open 0:0 is `affected`,
// Alpine's "0" is `not_affected`) holds for any version, as before.
func FixedInKind(status, version string) string {
	if status == "fixed" && version != "" {
		return db.VersionKindBoundary
	}
	return ""
}
