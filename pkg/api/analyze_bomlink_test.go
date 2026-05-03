package api

import (
	"testing"
)

// TestRewriteAffectsAsBOMLinks_RewritesPURLToBOMLink covers the v0.4.4 fix:
// vulnerability.affects[].ref values pointing at a component's PURL must be
// rewritten to BOM-Link form so Trivy --vex can bind the VEX statement back
// to a scan finding.
func TestRewriteAffectsAsBOMLinks_RewritesPURLToBOMLink(t *testing.T) {
	sbom := map[string]any{
		"serialNumber": "urn:uuid:abcd-1234",
		"version":      float64(1),
		"components": []any{
			map[string]any{
				"bom-ref": "comp-openssl-1",
				"purl":    "pkg:rpm/redhat/openssl@3.0.7-25.el9_3?arch=x86_64&distro=redhat-9.3",
			},
		},
		"vulnerabilities": []any{
			map[string]any{
				"id": "CVE-2024-1234",
				"affects": []any{
					map[string]any{
						"ref": "pkg:rpm/redhat/openssl@3.0.7-25.el9_3?arch=x86_64&distro=redhat-9.3",
					},
				},
			},
		},
	}
	rewriteAffectsAsBOMLinks(sbom)

	vuln := sbom["vulnerabilities"].([]any)[0].(map[string]any)
	affects := vuln["affects"].([]any)
	got := affects[0].(map[string]any)["ref"].(string)
	want := "urn:cdx:abcd-1234/1#comp-openssl-1"
	if got != want {
		t.Errorf("ref: got %q, want %q", got, want)
	}
}

// TestRewriteAffectsAsBOMLinks_StringAffectsEntry covers the alternate
// CycloneDX shape where affects[] is a plain string rather than {ref, versions}.
func TestRewriteAffectsAsBOMLinks_StringAffectsEntry(t *testing.T) {
	sbom := map[string]any{
		"serialNumber": "urn:uuid:abcd-1234",
		"version":      float64(1),
		"components": []any{
			map[string]any{
				"bom-ref": "comp-openssl-1",
				"purl":    "pkg:rpm/redhat/openssl",
			},
		},
		"vulnerabilities": []any{
			map[string]any{
				"affects": []any{"pkg:rpm/redhat/openssl"},
			},
		},
	}
	rewriteAffectsAsBOMLinks(sbom)

	got := sbom["vulnerabilities"].([]any)[0].(map[string]any)["affects"].([]any)[0]
	want := "urn:cdx:abcd-1234/1#comp-openssl-1"
	if got != want {
		t.Errorf("ref: got %q, want %q", got, want)
	}
}

// TestRewriteAffectsAsBOMLinks_NoSerialNumberIsNoOp: hand-rolled SBOMs with
// no serialNumber should pass through unchanged. Test fixtures elsewhere
// (TestAnalyze_SBOMOnly_Annotates etc.) rely on this.
func TestRewriteAffectsAsBOMLinks_NoSerialNumberIsNoOp(t *testing.T) {
	sbom := map[string]any{
		"vulnerabilities": []any{
			map[string]any{
				"affects": []any{map[string]any{"ref": "pkg:rpm/redhat/openssl@v"}},
			},
		},
	}
	rewriteAffectsAsBOMLinks(sbom)
	ref := sbom["vulnerabilities"].([]any)[0].(map[string]any)["affects"].([]any)[0].(map[string]any)["ref"]
	if ref != "pkg:rpm/redhat/openssl@v" {
		t.Errorf("expected ref unchanged, got %v", ref)
	}
}

// TestRewriteAffectsAsBOMLinks_UnmatchedRefPassesThrough: an affects.ref
// pointing at a component that isn't in the SBOM is left as-is.
func TestRewriteAffectsAsBOMLinks_UnmatchedRefPassesThrough(t *testing.T) {
	sbom := map[string]any{
		"serialNumber": "urn:uuid:abcd",
		"version":      float64(1),
		"components":   []any{},
		"vulnerabilities": []any{
			map[string]any{
				"affects": []any{map[string]any{"ref": "pkg:rpm/redhat/openssl@v"}},
			},
		},
	}
	rewriteAffectsAsBOMLinks(sbom)
	ref := sbom["vulnerabilities"].([]any)[0].(map[string]any)["affects"].([]any)[0].(map[string]any)["ref"]
	if ref != "pkg:rpm/redhat/openssl@v" {
		t.Errorf("expected unmatched ref unchanged, got %v", ref)
	}
}

// TestRewriteAffectsAsBOMLinks_ComponentWithoutBOMRefIsSkipped: components
// missing bom-ref are skipped (the affects entry stays as the input PURL).
// This is the path hand-rolled test fixtures take.
func TestRewriteAffectsAsBOMLinks_ComponentWithoutBOMRefIsSkipped(t *testing.T) {
	sbom := map[string]any{
		"serialNumber": "urn:uuid:abcd",
		"version":      float64(1),
		"components": []any{
			map[string]any{
				"purl": "pkg:rpm/redhat/openssl",
				// no bom-ref
			},
		},
		"vulnerabilities": []any{
			map[string]any{
				"affects": []any{map[string]any{"ref": "pkg:rpm/redhat/openssl"}},
			},
		},
	}
	rewriteAffectsAsBOMLinks(sbom)
	ref := sbom["vulnerabilities"].([]any)[0].(map[string]any)["affects"].([]any)[0].(map[string]any)["ref"]
	if ref != "pkg:rpm/redhat/openssl" {
		t.Errorf("expected ref unchanged when bom-ref missing, got %v", ref)
	}
}
