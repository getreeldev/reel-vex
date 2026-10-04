package db

import "testing"

func TestBoundaryReaches(t *testing.T) {
	row := func(base string, versions ...string) Statement {
		return Statement{BaseID: base, Versions: versions, VersionKind: VersionKindBoundary, Status: "fixed"}
	}
	const (
		deb = "pkg:deb/debian/zlib?distro=debian-12"
		rpm = "pkg:rpm/oracle/sudo?distro=oracle-8"
		apk = "pkg:apk/alpine/socat?distro=alpine-3.22"
	)
	for _, c := range []struct {
		name string
		s    Statement
		v    string
		want bool
	}{
		{"deb below", row(deb, "1:1.2.11.dfsg-4.1"), "1:1.2.11.dfsg-2", false},
		{"deb at", row(deb, "1:1.2.11.dfsg-4.1"), "1:1.2.11.dfsg-4.1", true},
		{"deb above", row(deb, "1:1.2.11.dfsg-4.1"), "1:1.2.13.dfsg-1", true},
		{"deb tilde sorts before", row(deb, "1:9.18.16-1~deb12u1"), "1:9.18.16-1~deb12u0", false},
		{"deb 0: and no epoch are one", row(deb, "0:1.3.5-6"), "1.3.5-6", true},
		{"deb missing epoch is 0", row(deb, "1:1.2.11.dfsg-4.1"), "1.2.13.dfsg-1", false},
		{"deb unparseable", row(deb, "0:1.3.5-6"), "x1.3", false},
		{"rpm at, epoch absent and 0", row(rpm, "0:1.9.5p2-1.el8_9"), "1.9.5p2-1.el8_9", true},
		{"rpm below", row(rpm, "0:1.9.5p2-1.el8_9"), "1.9.5p2-1.el8_8", false},
		{"rpm epoch wins", row(rpm, "7:5.2-1.el9_0.1"), "5.9-1.el9", false},
		{"rpm epoch inline", row(rpm, "7:5.2-1.el9_0.1"), "7:5.2-1.el9_0.1", true},
		{"rpm unparseable epoch", row(rpm, "0:1.0-1"), "x:2.0-1", false},
		{"apk below", row(apk, "1.8.1.2-r0"), "1.8.0.3-r0", false},
		{"apk above", row(apk, "1.8.1.2-r0"), "1.8.1.2-r1", true},
		{"apk unparseable", row(apk, "1.8.1.2-r0"), "latest", false},
		{"no ordering for the ecosystem", row("pkg:gem/rack", "2.2.0"), "3.0.0", false},
		{"no version asked", row(deb, "1:1.0-1"), "", false},
		// Several boundaries (parallel streams) are reached only at or above
		// every one of them, never the lowest alone.
		{"several: between", row(rpm, "0:4.18.0-1.el8", "0:5.15.0-1.el8"), "5.4.17-1.el8", false},
		{"several: above all", row(rpm, "0:4.18.0-1.el8", "0:5.15.0-1.el8"), "5.15.0-2.el8", true},
		{"not a boundary row", Statement{BaseID: deb, Versions: []string{"1.0-1"}, Status: "fixed"}, "0.1-1", true},
		{"a boundary row with no version", Statement{BaseID: deb, VersionKind: VersionKindBoundary, Status: "fixed"}, "0.1-1", true},
	} {
		if got := BoundaryReaches(c.s, c.v); got != c.want {
			t.Errorf("%s: BoundaryReaches(%v, %q) = %v, want %v", c.name, c.s.Versions, c.v, got, c.want)
		}
	}
}
