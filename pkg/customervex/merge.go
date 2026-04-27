package customervex

import (
	"sort"

	"github.com/getreeldev/reel-vex/pkg/db"
)

// MatchReason identifies a customer-sourced row in the merged set.
const MatchReason = "from_customer_vex"

// Merge combines vendor and customer statement sets with customer-override
// semantics:
//
//   - Self-collisions among customer statements (same (cve, base_id) appearing
//     in two customer rows) dedupe: latest db.Statement.Updated wins; ties
//     break by list order.
//   - Vendor rows whose (cve, base_id) collides with any customer row are
//     dropped from the merged set.
//
// Returns:
//
//   - merged: surviving vendor rows + all customer rows (after self-dedup).
//   - customerCVEs: set of CVE IDs the customer asserted on. Used by the SBOM
//     annotator to honour customer override at the per-CVE rollup level
//     (vendor rows on customer-asserted CVEs are excluded from the rollup
//     even when their base_id didn't directly collide).
func Merge(vendor, customer []db.Statement) (merged []db.Statement, customerCVEs map[string]bool) {
	customerCVEs = make(map[string]bool, len(customer))
	dedupedCustomer := dedupeCustomer(customer)

	collide := make(map[collisionKey]bool, len(dedupedCustomer))
	for _, c := range dedupedCustomer {
		collide[collisionKey{cve: c.CVE, base: c.BaseID}] = true
		customerCVEs[c.CVE] = true
	}

	merged = make([]db.Statement, 0, len(vendor)+len(dedupedCustomer))
	for _, v := range vendor {
		if collide[collisionKey{cve: v.CVE, base: v.BaseID}] {
			continue
		}
		merged = append(merged, v)
	}
	merged = append(merged, dedupedCustomer...)
	return merged, customerCVEs
}

// collisionKey identifies the (cve, base_id) tuple that decides override.
// Different base_ids for the same CVE do not collide; they are independent
// product claims.
type collisionKey struct {
	cve  string
	base string
}

// dedupeCustomer collapses self-collisions among customer statements. Two
// customer rows with the same (cve, base_id) are treated as restating the
// same claim; the newer Updated timestamp wins. Tie on timestamp: list order
// wins (later index → kept). Equal-timestamp customer rows on different
// base_ids do not collide; they are independent.
func dedupeCustomer(customer []db.Statement) []db.Statement {
	if len(customer) <= 1 {
		// Defensive copy so callers can't mutate the slice we returned.
		out := make([]db.Statement, len(customer))
		copy(out, customer)
		return out
	}
	type indexed struct {
		stmt db.Statement
		ord  int // original list index, used as tie-breaker
	}
	keep := make(map[collisionKey]indexed, len(customer))
	for i, s := range customer {
		key := collisionKey{cve: s.CVE, base: s.BaseID}
		current, exists := keep[key]
		if !exists || s.Updated > current.stmt.Updated || (s.Updated == current.stmt.Updated && i > current.ord) {
			keep[key] = indexed{stmt: s, ord: i}
		}
	}
	out := make([]db.Statement, 0, len(keep))
	for _, v := range keep {
		out = append(out, v.stmt)
	}
	// Stable order so test fixtures and the OpenVEX encoder (which has its
	// own sort) see a deterministic input. Sort by (cve, base, ord).
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CVE != out[j].CVE {
			return out[i].CVE < out[j].CVE
		}
		return out[i].BaseID < out[j].BaseID
	})
	return out
}
