package resolver

import (
	"log/slog"
	"net/url"
	"strings"

	"github.com/getreeldev/reel-vex/pkg/db"
)

// Candidate is one identifier reel-vex will look up in the statements table,
// together with the rule that produced it. Callers preserve the reason so
// it can be reported to the consumer as match_reason.
type Candidate struct {
	ID          string
	MatchReason string // "direct", "via_cpe_prefix", "via_alias"
}

// Resolver turns a user-supplied product identifier (PURL or CPE) into the
// set of candidate base identifiers that should be looked up against the
// statements table. Composes:
//
//   - direct: the normalized base of the input (PURL stripped of version
//     and qualifiers; CPE as-is)
//   - via_cpe_prefix: for CPE inputs, the first 5 CPE 2.2 URI parts with
//     trailing variants dropped (Red Hat SECDATA-1220 contract)
//   - via_alias: for PURLs carrying a `repository_id=...` qualifier, the
//     CPEs stored in product_aliases for that repository
//
// The Resolver is stateful because alias lookup hits the database. For pure
// CPE-prefix expansion (no alias table access) use the CPEPrefix helper
// directly.
type Resolver struct {
	db *db.DB
}

func New(database *db.DB) *Resolver {
	return &Resolver{db: database}
}

// Expand returns the candidate set for id. Order of returned candidates
// mirrors rule priority: direct first, then via_alias, then via_cpe_prefix.
// Duplicates are deduped with the first (stronger) reason winning.
func (r *Resolver) Expand(id string) []Candidate {
	seen := make(map[string]string)
	ordered := []string{}

	add := func(candidate, reason string) {
		if candidate == "" {
			return
		}
		if _, exists := seen[candidate]; exists {
			return
		}
		seen[candidate] = reason
		ordered = append(ordered, candidate)
	}

	// direct: the base form of the input.
	base, _ := splitBase(id)
	add(base, "direct")

	// via_alias: repository_id qualifier on a PURL → CPEs in the alias table.
	if qual := extractRepositoryID(id); qual != "" {
		targets, err := r.db.LookupAliases("repository_id", qual, "cpe")
		if err != nil {
			slog.Warn("alias lookup failed", "source_id", qual, "error", err)
		}
		for _, t := range targets {
			add(t, "via_alias")
			// CPE targets can themselves benefit from prefix matching.
			if prefix := CPEPrefix(t); prefix != t {
				add(prefix, "via_alias")
			}
		}
	}

	// via_cpe_prefix: for CPE inputs, the 5-part prefix.
	if strings.HasPrefix(id, "cpe:/") {
		if prefix := CPEPrefix(id); prefix != id {
			add(prefix, "via_cpe_prefix")
		}
	}

	out := make([]Candidate, 0, len(ordered))
	for _, c := range ordered {
		out = append(out, Candidate{ID: c, MatchReason: seen[c]})
	}
	return out
}

// splitBase mirrors csaf.SplitPURL but is duplicated here to keep pkg/resolver
// free of a dependency on pkg/csaf. PURLs get stripped of version and most
// qualifiers; everything else (including CPEs) is returned unchanged.
//
// The `distro` qualifier is preserved because it is identity, not a filter:
// noble `openssl` and jammy `openssl` are genuinely different packages with
// different fixed versions, so their base IDs must differ. `arch`, `epoch`,
// `repository_id` and other qualifiers remain scanner-side filters and are
// stripped.
func splitBase(id string) (string, string) {
	if !strings.HasPrefix(id, "pkg:") {
		return id, ""
	}
	var distro string
	if q := strings.IndexByte(id, '?'); q >= 0 {
		if vals, err := url.ParseQuery(id[q+1:]); err == nil {
			distro = vals.Get("distro")
		}
		id = id[:q]
	}
	if i := strings.IndexByte(id, '#'); i >= 0 {
		id = id[:i]
	}
	var base, version string
	if i := strings.LastIndexByte(id, '@'); i >= 0 {
		base, version = id[:i], id[i+1:]
	} else {
		base = id
	}
	if distro != "" {
		base += "?distro=" + distro
	}
	return base, version
}

// extractRepositoryID pulls the repository_id qualifier out of a PURL. Returns
// "" if the input isn't a PURL or has no repository_id.
//
// Example: pkg:rpm/redhat/openssl@3.0?arch=x86_64&repository_id=rhel-8-for-x86_64-appstream-rpms
// →        rhel-8-for-x86_64-appstream-rpms
func extractRepositoryID(id string) string {
	if !strings.HasPrefix(id, "pkg:") {
		return ""
	}
	q := strings.IndexByte(id, '?')
	if q < 0 {
		return ""
	}
	qualifiers := id[q+1:]
	// PURL qualifiers follow URL query-string conventions (& separated, = for value).
	values, err := url.ParseQuery(qualifiers)
	if err != nil {
		return ""
	}
	return values.Get("repository_id")
}
