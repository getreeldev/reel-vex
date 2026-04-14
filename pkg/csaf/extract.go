package csaf

import (
	"encoding/json"
	"os"

	"github.com/gocsaf/csaf/v3/csaf"
)

// Statement is a single VEX assertion: a product is (or isn't) affected by a CVE.
type Statement struct {
	CVE           string
	ProductID     string // Full PURL or CPE as published by the vendor
	BaseID        string // Normalized identifier for matching (PURL without version/qualifiers, CPE as-is)
	Version       string // Extracted version (PURL only; empty for CPE or unversioned PURLs)
	IDType        string // "purl" or "cpe"
	Status        string // not_affected, fixed, affected, under_investigation
	Justification string // e.g. vulnerable_code_not_present (only for not_affected)
}

// ExtractFromFile parses a CSAF document and extracts all VEX statements.
func ExtractFromFile(path string) ([]Statement, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Extract(data)
}

// Extract parses CSAF JSON bytes and extracts all VEX statements.
//
// First tries the strict gocsaf/csaf parser. If that fails (most often because
// of CPE 2.3 syntax violations in real vendor feeds — see SUSE's `+git...`
// version suffixes and `c/c++` software_edition patterns), falls back to a
// permissive map-based extractor that treats product_id strings as opaque
// keys. We'd rather store something the vendor actually published than drop
// the whole document.
func Extract(data []byte) ([]Statement, error) {
	var adv csaf.Advisory
	if err := json.Unmarshal(data, &adv); err != nil {
		return extractPermissive(data)
	}

	// Build product_id → []productIdentifier map from product_tree
	products := buildProductMap(&adv)

	// Build flag lookup: product_id → justification label
	flagMap := buildFlagMap(&adv)

	var statements []Statement

	for _, vuln := range adv.Vulnerabilities {
		if vuln == nil || vuln.CVE == nil {
			continue
		}
		cve := string(*vuln.CVE)

		if vuln.ProductStatus == nil {
			continue
		}

		ps := vuln.ProductStatus

		extract := func(productIDs *csaf.Products, status string) {
			if productIDs == nil {
				return
			}
			for _, pid := range *productIDs {
				if pid == nil {
					continue
				}
				id := string(*pid)
				identifiers := products[id]
				if len(identifiers) == 0 {
					continue
				}

				justification := ""
				if status == "not_affected" {
					justification = flagMap[id]
				}

				for _, ident := range identifiers {
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

		extract(ps.KnownNotAffected, "not_affected")
		extract(ps.Fixed, "fixed")
		extract(ps.KnownAffected, "affected")
		extract(ps.UnderInvestigation, "under_investigation")
	}

	return statements, nil
}

type productIdentifier struct {
	id     string
	idType string
}

// buildProductMap walks product_tree.branches and product_tree.relationships
// to build a map from product_id to product identifiers (PURLs and CPEs).
func buildProductMap(adv *csaf.Advisory) map[string][]productIdentifier {
	m := make(map[string][]productIdentifier)

	if adv.ProductTree == nil {
		return m
	}

	// Walk branches recursively
	walkBranches(adv.ProductTree.Branches, m)

	// Walk top-level full_product_names
	if adv.ProductTree.FullProductNames != nil {
		for _, fpn := range *adv.ProductTree.FullProductNames {
			addProduct(fpn, m)
		}
	}

	// Walk relationships — these define composite products
	// (e.g., "openssh as component of RHEL 8")
	if adv.ProductTree.RelationShips != nil {
		for _, rel := range *adv.ProductTree.RelationShips {
			if rel == nil || rel.FullProductName == nil {
				continue
			}
			addProduct(rel.FullProductName, m)

			// The relationship's product inherits identifiers from its component
			// (product_reference) if the relationship product itself has no identifiers.
			if rel.FullProductName.ProductID != nil && rel.ProductReference != nil {
				relID := string(*rel.FullProductName.ProductID)
				if len(m[relID]) == 0 {
					refID := string(*rel.ProductReference)
					if idents := m[refID]; len(idents) > 0 {
						m[relID] = append(m[relID], idents...)
					}
				}
			}
		}
	}

	return m
}

func walkBranches(branches csaf.Branches, m map[string][]productIdentifier) {
	for _, b := range branches {
		if b == nil {
			continue
		}
		if b.Product != nil {
			addProduct(b.Product, m)
		}
		if b.Branches != nil {
			walkBranches(b.Branches, m)
		}
	}
}

func addProduct(fpn *csaf.FullProductName, m map[string][]productIdentifier) {
	if fpn == nil || fpn.ProductID == nil {
		return
	}
	id := string(*fpn.ProductID)
	helper := fpn.ProductIdentificationHelper
	if helper == nil {
		return
	}
	if helper.PURL != nil {
		m[id] = append(m[id], productIdentifier{
			id:     string(*helper.PURL),
			idType: "purl",
		})
	}
	if helper.CPE != nil {
		m[id] = append(m[id], productIdentifier{
			id:     string(*helper.CPE),
			idType: "cpe",
		})
	}
}

// buildFlagMap builds a map from product_id to justification label.
func buildFlagMap(adv *csaf.Advisory) map[string]string {
	m := make(map[string]string)
	for _, vuln := range adv.Vulnerabilities {
		if vuln == nil {
			continue
		}
		for _, flag := range vuln.Flags {
			if flag == nil || flag.Label == nil || flag.ProductIds == nil {
				continue
			}
			label := string(*flag.Label)
			for _, pid := range *flag.ProductIds {
				if pid != nil {
					m[string(*pid)] = label
				}
			}
		}
	}
	return m
}
