package uservex

import (
	"sort"

	"github.com/getreeldev/reel-vex/pkg/db"
)

// MatchReason identifies a user-sourced row in the merged set.
const MatchReason = "from_user_vex"

// Merge combines vendor and user statement sets with user-override
// semantics:
//
//   - Self-collisions among user statements (same (cve, base_id) appearing
//     in two user rows) dedupe: latest db.Statement.Updated wins; ties
//     break by list order.
//   - Vendor rows whose (cve, base_id) collides with any user row are
//     dropped from the merged set.
//
// Returns:
//
//   - merged: surviving vendor rows + all user rows (after self-dedup).
//   - userCVEs: set of CVE IDs the user asserted on. Used by the SBOM
//     annotator to honour user override at the per-CVE rollup level
//     (vendor rows on user-asserted CVEs are excluded from the rollup
//     even when their base_id didn't directly collide).
func Merge(vendor, user []db.Statement) (merged []db.Statement, userCVEs map[string]bool) {
	userCVEs = make(map[string]bool, len(user))
	dedupedUser := dedupeUser(user)

	collide := make(map[collisionKey]bool, len(dedupedUser))
	for _, c := range dedupedUser {
		collide[collisionKey{cve: c.CVE, base: c.BaseID}] = true
		userCVEs[c.CVE] = true
	}

	merged = make([]db.Statement, 0, len(vendor)+len(dedupedUser))
	for _, v := range vendor {
		if collide[collisionKey{cve: v.CVE, base: v.BaseID}] {
			continue
		}
		merged = append(merged, v)
	}
	merged = append(merged, dedupedUser...)
	return merged, userCVEs
}

// collisionKey identifies the (cve, base_id) tuple that decides override.
// Different base_ids for the same CVE do not collide; they are independent
// product claims.
type collisionKey struct {
	cve  string
	base string
}

// dedupeUser collapses self-collisions among user statements. Two
// user rows with the same (cve, base_id) are treated as restating the
// same claim; the newer Updated timestamp wins. Tie on timestamp: list order
// wins (later index → kept). Equal-timestamp user rows on different
// base_ids do not collide; they are independent.
func dedupeUser(user []db.Statement) []db.Statement {
	if len(user) <= 1 {
		// Defensive copy so callers can't mutate the slice we returned.
		out := make([]db.Statement, len(user))
		copy(out, user)
		return out
	}
	type indexed struct {
		stmt db.Statement
		ord  int // original list index, used as tie-breaker
	}
	keep := make(map[collisionKey]indexed, len(user))
	for i, s := range user {
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
