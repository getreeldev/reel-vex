package csaf

import (
	"encoding/json"
	"testing"
)

// docBuilder is a small helper that lets tests compose CSAF-shaped JSON
// without the verbosity of literal map[string]any{} nesting.
func docBuilder(productID, purl, cpe, cve, status string) []byte {
	doc := map[string]any{
		"document": map[string]any{
			"category":     "csaf_vex",
			"csaf_version": "2.0",
			"distribution": map[string]any{
				"tlp": map[string]any{"label": "WHITE"},
			},
			"publisher": map[string]any{
				"category":  "vendor",
				"name":      "Test",
				"namespace": "https://example.test",
			},
			"title":    "Test",
			"tracking": map[string]any{},
		},
		"product_tree": map[string]any{
			"branches": []any{
				map[string]any{
					"category": "vendor",
					"name":     "test",
					"branches": []any{
						map[string]any{
							"category": "product_version",
							"name":     "test-product",
							"product": map[string]any{
								"name":       "test-product",
								"product_id": productID,
								"product_identification_helper": map[string]any{
									"purl": purl,
									"cpe":  cpe,
								},
							},
						},
					},
				},
			},
		},
		"vulnerabilities": []any{
			map[string]any{
				"cve": cve,
				"product_status": map[string]any{
					"known_" + status: []any{productID},
				},
			},
		},
	}
	b, _ := json.Marshal(doc)
	return b
}

// Real-world failing patterns observed in SUSE's CSAF VEX feed (April 2026).
// Each one breaks the strict gocsaf/csaf CPE 2.3 regex. We must recover them.
var problematicCPEs = []struct {
	name string
	cpe  string
}{
	{"plus suffix in version", "cpe:2.3:a:suse:aaa_base:13.2+git20140911.61c1681:*:*:*:*:*:*:*"},
	{"trailing plus in version", "cpe:2.3:a:qemu:qemu:1.0.0+:*:*:*:*:*:*:*"},
	{"slash in software_edition", "cpe:2.3:a:icu-project:international_components_for_unicode:4.0:*:*:*:*:c/c++:*:*"},
	{"plus security suffix", "cpe:2.3:a:grafana:grafana:11.6.1+security01:*:*:*:*:*:*:*"},
}

func TestExtract_FallsBackForBadCPE(t *testing.T) {
	for _, tc := range problematicCPEs {
		t.Run(tc.name, func(t *testing.T) {
			// Use the bad CPE alongside a valid PURL so we can verify both
			// are recovered (the document shouldn't be dropped just because
			// of one bad field).
			data := docBuilder("test-pid", "pkg:rpm/test/foo@1.0", tc.cpe, "CVE-2024-9999", "affected")

			stmts, err := Extract(data)
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}
			if len(stmts) != 2 {
				t.Fatalf("expected 2 statements (purl+cpe), got %d", len(stmts))
			}

			byType := map[string]Statement{}
			for _, s := range stmts {
				byType[s.IDType] = s
			}

			purl, ok := byType["purl"]
			if !ok {
				t.Fatalf("missing PURL statement")
			}
			if purl.ProductID != "pkg:rpm/test/foo@1.0" {
				t.Fatalf("PURL ProductID: got %q", purl.ProductID)
			}
			if purl.BaseID != "pkg:rpm/test/foo" || purl.Version != "1.0" {
				t.Fatalf("PURL split wrong: base=%q version=%q", purl.BaseID, purl.Version)
			}

			cpe, ok := byType["cpe"]
			if !ok {
				t.Fatalf("missing CPE statement")
			}
			if cpe.ProductID != tc.cpe {
				t.Fatalf("CPE ProductID: got %q, want %q", cpe.ProductID, tc.cpe)
			}
			// CPEs pass through SplitPURL unchanged.
			if cpe.BaseID != tc.cpe || cpe.Version != "" {
				t.Fatalf("CPE split wrong: base=%q version=%q", cpe.BaseID, cpe.Version)
			}

			if cpe.CVE != "CVE-2024-9999" || cpe.Status != "affected" {
				t.Fatalf("CVE/status wrong: cve=%q status=%q", cpe.CVE, cpe.Status)
			}
		})
	}
}

func TestExtract_StrictPathStillUsedWhenValid(t *testing.T) {
	// A clean CSAF document with a spec-conformant CPE — should go through
	// the strict path. We can't observe which path was taken directly, but
	// we can at least confirm a valid doc still produces the right output.
	data := docBuilder(
		"test-pid",
		"pkg:rpm/test/openssl@3.0",
		"cpe:2.3:a:test:openssl:3.0:*:*:*:*:*:*:*",
		"CVE-2024-1234",
		"not_affected",
	)

	stmts, err := Extract(data)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(stmts))
	}
}

func TestExtractPermissive_RelationshipInheritance(t *testing.T) {
	// Composite product (X as component of Y) where the relationship product
	// has no identifiers but the component reference does.
	doc := map[string]any{
		"product_tree": map[string]any{
			"branches": []any{
				map[string]any{
					"category": "vendor",
					"branches": []any{
						map[string]any{
							"category": "product_version",
							"product": map[string]any{
								"product_id": "comp-1",
								"product_identification_helper": map[string]any{
									"purl": "pkg:rpm/test/log4j@2.16.0",
								},
							},
						},
					},
				},
			},
			"relationships": []any{
				map[string]any{
					"category":          "default_component_of",
					"product_reference": "comp-1",
					"full_product_name": map[string]any{
						"product_id": "rel-1",
						// No identification helper — should inherit from comp-1.
					},
				},
			},
		},
		"vulnerabilities": []any{
			map[string]any{
				"cve": "CVE-2021-44228",
				"product_status": map[string]any{
					"fixed": []any{"rel-1"},
				},
			},
		},
	}
	data, _ := json.Marshal(doc)

	stmts, err := extractPermissive(data)
	if err != nil {
		t.Fatalf("extractPermissive: %v", err)
	}
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(stmts))
	}
	if stmts[0].ProductID != "pkg:rpm/test/log4j@2.16.0" {
		t.Fatalf("inherited ProductID wrong: got %q", stmts[0].ProductID)
	}
	if stmts[0].Status != "fixed" {
		t.Fatalf("status wrong: got %q", stmts[0].Status)
	}
}

func TestExtractPermissive_FlagsBecomeJustifications(t *testing.T) {
	doc := map[string]any{
		"product_tree": map[string]any{
			"branches": []any{
				map[string]any{
					"product": map[string]any{
						"product_id": "p1",
						"product_identification_helper": map[string]any{
							"purl": "pkg:rpm/test/log4j",
						},
					},
				},
			},
		},
		"vulnerabilities": []any{
			map[string]any{
				"cve": "CVE-2021-44228",
				"product_status": map[string]any{
					"known_not_affected": []any{"p1"},
				},
				"flags": []any{
					map[string]any{
						"label":       "vulnerable_code_not_present",
						"product_ids": []any{"p1"},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(doc)

	stmts, err := extractPermissive(data)
	if err != nil {
		t.Fatalf("extractPermissive: %v", err)
	}
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(stmts))
	}
	if stmts[0].Justification != "vulnerable_code_not_present" {
		t.Fatalf("justification wrong: got %q", stmts[0].Justification)
	}
}
