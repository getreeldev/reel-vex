//go:build integration

package acceptance

import (
	"strings"
	"testing"
)

// tsDay1File is the fixture server's day-1 Last-Modified. secdb rows carry no
// date of their own and are dated by it. OVAL rows are too, although OVAL
// definitions do carry dates (Ubuntu, AlmaLinux and Oracle `issued`/`updated`,
// Debian DSA `<date>`): dating OVAL rows by the file is the product's current
// design, recorded as an open decision in PLAN-VEX-SWEEP.md §6 Backlog, "Found
// by Phase 3a", and these expectations follow it until that is decided.
const tsDay1File = "2026-10-03T00:00:00Z"

// notes renders the status_notes the API documents: the feed format, then the
// match rule when the query named products.
func notes(format, reason string) string {
	if reason == "" {
		return "source_format=" + format
	}
	return "source_format=" + format + "; match_reason=" + reason
}

// scoped appends the scope a product-scoped (Rancher) row discloses.
func scoped(n, scope string) string { return n + "; scope=" + scope }

// TestAcceptance runs the day-1 cases against the first ingest, then — once
// any day-2 case is no longer pending — ingests the day-2 fixtures and runs
// the day-2 cases.
func TestAcceptance(t *testing.T) {
	var day1 []Case
	for _, cs := range [][]Case{
		redhatCases(), suseCases(), ubuntuCases(), ubuntuOVALCases(), debianCases(),
		rancherCases(), alpineCases(), amazonCases(), almalinuxCases(), oracleCases(),
		filterCases(), analyzeCases(),
	} {
		day1 = append(day1, cs...)
	}
	t.Run("day1", func(t *testing.T) { runCases(t, day1) })

	day2 := day2Cases()
	runDay2 := false
	for _, c := range day2 {
		if c.Pending == "" {
			runDay2 = true
		}
	}
	if runDay2 {
		if err := ingest("day2", day2Allowed); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("day2", func(t *testing.T) { runCases(t, day2) })
}

// day2Allowed accepts the two warnings the day-2 ingest must log: the Alpine
// community feed loses more than 20% of its rows, so its sweep is refused, and
// SUSE's index.txt loses more than 20% of its CVEs, so its withdrawal is.
func day2Allowed(line string) bool {
	return strings.Contains(line, "refused=") &&
		(strings.Contains(line, " WARN sweep ") && strings.Contains(line, "adapter=alpine-secdb-v3.22-community") ||
			strings.Contains(line, " WARN withdraw ") && strings.Contains(line, "adapter=suse"))
}
