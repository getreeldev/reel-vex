package csaf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestExtract_RedHat(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "redhat-cve-2024-6387.json")
	statements, err := ExtractFromFile(path)
	if err != nil {
		t.Fatalf("ExtractFromFile: %v", err)
	}

	if len(statements) == 0 {
		t.Fatal("expected statements, got none")
	}

	// All statements should reference CVE-2024-6387
	for _, s := range statements {
		if s.CVE != "CVE-2024-6387" {
			t.Errorf("unexpected CVE: %s", s.CVE)
		}
	}

	// Count by type
	var purls, cpes int
	for _, s := range statements {
		switch s.IDType {
		case "purl":
			purls++
		case "cpe":
			cpes++
		default:
			t.Errorf("unexpected id_type: %s", s.IDType)
		}
	}
	t.Logf("Red Hat: %d statements (%d purl, %d cpe)", len(statements), purls, cpes)

	if purls == 0 {
		t.Error("expected PURL-based statements from Red Hat")
	}

	// Count by status
	statusCounts := map[string]int{}
	for _, s := range statements {
		statusCounts[s.Status]++
	}
	t.Logf("Statuses: %v", statusCounts)

	if statusCounts["not_affected"] == 0 {
		t.Error("expected not_affected statements")
	}
	if statusCounts["fixed"] == 0 {
		t.Error("expected fixed statements")
	}

	// Check justifications exist for not_affected
	var withJustification int
	for _, s := range statements {
		if s.Status == "not_affected" && s.Justification != "" {
			withJustification++
		}
	}
	t.Logf("not_affected with justification: %d", withJustification)
	if withJustification == 0 {
		t.Error("expected justifications for not_affected statements")
	}

	// Spot check: find openssh PURL
	var foundOpenSSH bool
	for _, s := range statements {
		if s.IDType == "purl" && s.Status == "fixed" {
			if contains(s.ProductID, "openssh") {
				foundOpenSSH = true
				t.Logf("Found openssh fix: %s", s.ProductID)
				break
			}
		}
	}
	if !foundOpenSSH {
		t.Error("expected to find openssh in fixed PURLs")
	}
}

func TestExtract_SUSE(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "suse-cve-2024-6387.json")
	statements, err := ExtractFromFile(path)
	if err != nil {
		t.Fatalf("ExtractFromFile: %v", err)
	}

	if len(statements) == 0 {
		t.Fatal("expected statements, got none")
	}

	// All statements should reference CVE-2024-6387
	for _, s := range statements {
		if s.CVE != "CVE-2024-6387" {
			t.Errorf("unexpected CVE: %s", s.CVE)
		}
	}

	// Count by type
	var purls, cpes int
	for _, s := range statements {
		switch s.IDType {
		case "purl":
			purls++
		case "cpe":
			cpes++
		default:
			t.Errorf("unexpected id_type: %s", s.IDType)
		}
	}
	t.Logf("SUSE: %d statements (%d purl, %d cpe)", len(statements), purls, cpes)

	// SUSE has both PURLs and CPEs
	if cpes == 0 {
		t.Error("expected CPE-based statements from SUSE")
	}

	// Count by status
	statusCounts := map[string]int{}
	for _, s := range statements {
		statusCounts[s.Status]++
	}
	t.Logf("Statuses: %v", statusCounts)

	if statusCounts["not_affected"] == 0 && statusCounts["affected"] == 0 {
		t.Error("expected not_affected or affected statements")
	}
}

// TestExtract_SUSERecommendedIsFixed: SUSE marks fixed packages as
// product_status.recommended (older documents: first_fixed) and never uses
// fixed. cve-2025-1914 lists only recommended, so without the mapping it
// yields nothing. Checked through both the strict and the permissive path.
func TestExtract_SUSERecommendedIsFixed(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "suse-cve-2025-1914.json"))
	if err != nil {
		t.Fatal(err)
	}
	strict, err := Extract(data)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	permissive, err := extractPermissive(data)
	if err != nil {
		t.Fatalf("extractPermissive: %v", err)
	}
	for name, stmts := range map[string][]Statement{"strict": strict, "permissive": permissive} {
		if len(stmts) != 13 {
			t.Errorf("%s: got %d statements, want 13", name, len(stmts))
		}
		var versioned int
		for _, s := range stmts {
			if s.Status != "fixed" {
				t.Errorf("%s: %s status %q, want fixed", name, s.ProductID, s.Status)
			}
			if s.Version != "" {
				versioned++
			}
		}
		if versioned == 0 {
			t.Errorf("%s: no statement carries a fixed version", name)
		}
	}
}

func TestExtract_FirstFixedIsFixed(t *testing.T) {
	doc := map[string]any{
		"product_tree": map[string]any{
			"branches": []any{
				map[string]any{
					"product": map[string]any{
						"product_id": "p1",
						"product_identification_helper": map[string]any{
							"purl": "pkg:rpm/suse/curl@8.0.1-1.1?arch=x86_64",
						},
					},
				},
			},
		},
		"vulnerabilities": []any{
			map[string]any{
				"cve": "CVE-2024-0001",
				"product_status": map[string]any{
					"first_fixed": []any{"p1"},
				},
			},
		},
	}
	data, _ := json.Marshal(doc)
	strict, err := Extract(data)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	permissive, err := extractPermissive(data)
	if err != nil {
		t.Fatalf("extractPermissive: %v", err)
	}
	for name, stmts := range map[string][]Statement{"strict": strict, "permissive": permissive} {
		if len(stmts) != 1 {
			t.Fatalf("%s: got %d statements, want 1", name, len(stmts))
		}
		if s := stmts[0]; s.Status != "fixed" || s.Version != "8.0.1-1.1" {
			t.Errorf("%s: got status %q version %q, want fixed 8.0.1-1.1", name, s.Status, s.Version)
		}
	}
}

// TestExtract_PlatformCPEInheritance is a regression guard for the fix that
// makes composite products in `product_tree.relationships` inherit identifiers
// from BOTH sides — the package (product_reference, usually a PURL) and the
// platform (relates_to_product_reference, usually a CPE). Red Hat's unfixed-
// advisory documents put CPEs only on the platform side; dropping them means
// zero CPE-keyed statements for RHEL advisories.
func TestExtract_PlatformCPEInheritance(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "secdata-1220-cve-2024-0217.json")
	stmts, err := ExtractFromFile(path)
	if err != nil {
		t.Fatalf("ExtractFromFile: %v", err)
	}

	var cpeCount int
	var sawBaseRHEL8 bool
	for _, s := range stmts {
		if s.IDType == "cpe" {
			cpeCount++
			if s.ProductID == "cpe:/o:redhat:enterprise_linux:8" {
				sawBaseRHEL8 = true
			}
		}
	}
	if cpeCount == 0 {
		t.Fatal("expected CPE statements from relationship inheritance; got none")
	}
	if !sawBaseRHEL8 {
		t.Error("expected at least one statement keyed on cpe:/o:redhat:enterprise_linux:8")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
