package api

import (
	"sort"
	"strings"

	"github.com/getreeldev/reel-vex/pkg/csaf"
	"github.com/getreeldev/reel-vex/pkg/db"
)

// Architecture matching is off by default and opt-in via `strict_arch`.
//
// The default has to be arch-blind: the wired feeds disagree about whether to
// qualify at all (Canonical's OpenVEX qualifies ~100% of rows, Red Hat CSAF
// ~69%, every other source 0%), so matching architectures exactly would turn
// most of the corpus into false negatives. But a caller that knows it is
// scanning one architecture should be able to say so, rather than being handed
// another architecture's verdicts echoed back under its own identifier —
// which is what happens by default and is invisible in the response, because
// the base identifier the encoder echoes has no arch on it.

// requestArches returns the concrete architectures the caller named across its
// product identifiers, deduped and sorted.
//
// The set is request-level, not per-product: the union across every supplied
// identifier. A mixed-architecture request therefore widens rather than
// narrows, which is the safe direction — and in practice one image is one
// architecture. Architecture-independent values (noarch, src, source, all)
// are not concrete and never narrow anything, so they are skipped here; they
// come back in archAllowList, which is about what to *keep*.
func requestArches(products []string) []string {
	seen := make(map[string]bool)
	for _, p := range products {
		a := csaf.PURLArch(p)
		if csaf.ArchIndependent(a) {
			continue
		}
		seen[a] = true
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// archAllowList turns a concrete architecture set into the values a
// db.QueryFilters.ArchAllow predicate should keep: the caller's own
// architectures plus the architecture-independent ones, which are verdicts
// that hold everywhere and must never be narrowed away. Returns nil for an
// empty input so the filter stays absent rather than matching nothing.
func archAllowList(arches []string) []string {
	if len(arches) == 0 {
		return nil
	}
	out := make([]string, 0, len(arches)+4)
	out = append(out, arches...)
	// Mirrors csaf.ArchIndependent's non-empty values. Rows with no arch
	// qualifier at all are handled by the backends' predicate, not by this list.
	out = append(out, "noarch", "src", "source", "all")
	return out
}

// filterByArch drops statements whose product_id names an architecture the
// caller did not ask for. Returns the input untouched when arches is empty.
//
// This is the exact half of a two-layer filter. The db backends apply a
// substring predicate so LIMIT applies to rows the caller will actually keep —
// necessary, but it cannot see qualifier boundaries, so "%arch=amd64%" also
// matches a hypothetical arch=amd64_v2. This pass re-parses the qualifier and
// makes the decision properly. Do not remove it as redundant.
func filterByArch(stmts []db.Statement, arches []string) []db.Statement {
	if len(arches) == 0 {
		return stmts
	}
	allowed := make(map[string]bool, len(arches))
	for _, a := range arches {
		allowed[a] = true
	}
	// Compacts in place; both callers reassign and don't reuse the original.
	out := stmts[:0]
	for _, s := range stmts {
		a := csaf.PURLArch(s.ProductID)
		if csaf.ArchIndependent(a) || allowed[a] {
			out = append(out, s)
		}
	}
	return out
}

// archHeader renders the applied architecture set for X-Reel-Arch. Empty when
// nothing was narrowed, so the header is only present when it means something.
func archHeader(arches []string) string {
	return strings.Join(arches, ",")
}
