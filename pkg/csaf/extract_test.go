package csaf

import (
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
