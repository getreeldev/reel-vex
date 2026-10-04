//go:build integration

package acceptance

import "testing"

// tsDay1File is the fixture server's day-1 Last-Modified. secdb rows carry no
// date of their own and are dated by it. OVAL rows are too, although OVAL
// definitions do carry dates (Ubuntu, AlmaLinux and Oracle `issued`/`updated`,
// Debian DSA `<date>`): dating OVAL rows by the file is the product's current
// design (whether to date them by the definition instead is an open question),
// and these expectations follow it.
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

// TestAcceptance runs the day-1 cases against the first ingest, then ingests
// the day-2 fixtures and runs the day-2 cases.
func TestAcceptance(t *testing.T) {
	if env.serverURL == "" {
		t.Skip("REEL_VEX_TEST_PG_DSN not set")
	}
	var day1 []Case
	for _, cs := range [][]Case{
		redhatCases(), suseCases(), ubuntuCases(), ubuntuOVALCases(), debianCases(),
		rancherCases(), alpineCases(), amazonCases(), almalinuxCases(), oracleCases(),
		filterCases(), analyzeCases(), boundaryCases(),
	} {
		day1 = append(day1, cs...)
	}
	t.Run("day1", func(t *testing.T) { runCases(t, day1) })

	if err := ingest("day2", day2Want); err != nil {
		t.Fatal(err)
	}
	t.Run("day2", func(t *testing.T) { runCases(t, day2Cases()) })
}
