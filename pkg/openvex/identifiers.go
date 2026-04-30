package openvex

import "strings"

// CollectIdentifiers walks a Product list and returns the deduplicated list
// of identifier strings, in stable order. Empty / whitespace-only values are
// dropped. Returns nil if no usable identifier is found — callers decide
// whether that's an error in their context (it is for inbound user-VEX, not
// for vendor adapter ingest, which logs and skips the statement).
func CollectIdentifiers(products []Component) []string {
	seen := make(map[string]bool)
	var ids []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		ids = append(ids, s)
	}
	for _, p := range products {
		add(p.ID)
		if p.Identifiers != nil {
			add(p.Identifiers.PURL)
			add(p.Identifiers.CPE22)
			add(p.Identifiers.CPE23)
		}
	}
	return ids
}
