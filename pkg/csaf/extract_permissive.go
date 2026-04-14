package csaf

import (
	"encoding/json"
	"fmt"
)

// extractPermissive parses a CSAF document with a tolerant map[string]any
// walker. It's the fallback when the strict gocsaf/csaf parser rejects a
// document because of schema validation — most commonly CPE 2.3 syntax
// violations in real vendor feeds (e.g. SUSE's `+git...` version suffixes,
// `c/c++` in software_edition, trailing `+`, etc.).
//
// We deliberately don't validate product_id strings here. Whatever the vendor
// publishes is what we store; the matching layer treats them as opaque keys.
// This means we may store identifiers that don't strictly conform to CPE 2.3
// — but they only ever match when a consumer queries with that exact string,
// so the worst case is dead-weight rows. The benefit is that we don't drop
// the entire document just because one field is non-conformant: legitimate
// PURLs and other CPEs in the same doc still get extracted.
func extractPermissive(data []byte) ([]Statement, error) {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("permissive parse: %w", err)
	}

	products := buildProductMapPermissive(doc)
	flagMap := buildFlagMapPermissive(doc)

	var statements []Statement

	vulns, _ := doc["vulnerabilities"].([]any)
	for _, v := range vulns {
		vuln, _ := v.(map[string]any)
		if vuln == nil {
			continue
		}
		cve, _ := vuln["cve"].(string)
		if cve == "" {
			continue
		}

		ps, _ := vuln["product_status"].(map[string]any)
		if ps == nil {
			continue
		}

		extract := func(statusKey, status string) {
			ids, _ := ps[statusKey].([]any)
			for _, id := range ids {
				productID, _ := id.(string)
				if productID == "" {
					continue
				}
				idents := products[productID]
				if len(idents) == 0 {
					continue
				}
				justification := ""
				if status == "not_affected" {
					justification = flagMap[productID]
				}
				for _, ident := range idents {
					base, version := SplitPURL(ident.id)
					statements = append(statements, Statement{
						CVE:           cve,
						ProductID:     ident.id,
						BaseID:        base,
						Version:       version,
						IDType:        ident.idType,
						Status:        status,
						Justification: justification,
					})
				}
			}
		}

		extract("known_not_affected", "not_affected")
		extract("fixed", "fixed")
		extract("known_affected", "affected")
		extract("under_investigation", "under_investigation")
	}

	return statements, nil
}

// buildProductMapPermissive walks product_tree.branches, full_product_names,
// and relationships using map[string]any, mirroring the strict version's
// structure but without library-level validation.
func buildProductMapPermissive(doc map[string]any) map[string][]productIdentifier {
	m := make(map[string][]productIdentifier)

	pt, _ := doc["product_tree"].(map[string]any)
	if pt == nil {
		return m
	}

	if branches, ok := pt["branches"].([]any); ok {
		walkBranchesPermissive(branches, m)
	}

	if fpns, ok := pt["full_product_names"].([]any); ok {
		for _, fpn := range fpns {
			if fp, ok := fpn.(map[string]any); ok {
				addProductPermissive(fp, m)
			}
		}
	}

	if rels, ok := pt["relationships"].([]any); ok {
		for _, r := range rels {
			rel, _ := r.(map[string]any)
			if rel == nil {
				continue
			}
			fpn, _ := rel["full_product_name"].(map[string]any)
			if fpn == nil {
				continue
			}
			addProductPermissive(fpn, m)

			// Inherit identifiers from the referenced component if the
			// relationship product itself has none.
			relID, _ := fpn["product_id"].(string)
			refID, _ := rel["product_reference"].(string)
			if relID != "" && refID != "" && len(m[relID]) == 0 {
				if idents := m[refID]; len(idents) > 0 {
					m[relID] = append(m[relID], idents...)
				}
			}
		}
	}

	return m
}

func walkBranchesPermissive(branches []any, m map[string][]productIdentifier) {
	for _, b := range branches {
		branch, _ := b.(map[string]any)
		if branch == nil {
			continue
		}
		if product, ok := branch["product"].(map[string]any); ok {
			addProductPermissive(product, m)
		}
		if subBranches, ok := branch["branches"].([]any); ok {
			walkBranchesPermissive(subBranches, m)
		}
	}
}

func addProductPermissive(fpn map[string]any, m map[string][]productIdentifier) {
	productID, ok := fpn["product_id"].(string)
	if !ok || productID == "" {
		return
	}
	helper, ok := fpn["product_identification_helper"].(map[string]any)
	if !ok {
		return
	}
	if purl, ok := helper["purl"].(string); ok && purl != "" {
		m[productID] = append(m[productID], productIdentifier{
			id:     purl,
			idType: "purl",
		})
	}
	if cpe, ok := helper["cpe"].(string); ok && cpe != "" {
		m[productID] = append(m[productID], productIdentifier{
			id:     cpe,
			idType: "cpe",
		})
	}
}

func buildFlagMapPermissive(doc map[string]any) map[string]string {
	m := make(map[string]string)
	vulns, _ := doc["vulnerabilities"].([]any)
	for _, v := range vulns {
		vuln, _ := v.(map[string]any)
		if vuln == nil {
			continue
		}
		flags, _ := vuln["flags"].([]any)
		for _, f := range flags {
			flag, _ := f.(map[string]any)
			if flag == nil {
				continue
			}
			label, _ := flag["label"].(string)
			if label == "" {
				continue
			}
			ids, _ := flag["product_ids"].([]any)
			for _, id := range ids {
				if pid, ok := id.(string); ok {
					m[pid] = label
				}
			}
		}
	}
	return m
}
