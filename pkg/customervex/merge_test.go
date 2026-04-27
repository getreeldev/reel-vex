package customervex

import (
	"testing"

	"github.com/getreeldev/reel-vex/pkg/db"
)

func TestMerge_OverrideDropsCollidingVendor(t *testing.T) {
	vendor := []db.Statement{
		{Vendor: "redhat", CVE: "CVE-1", BaseID: "pkg:rpm/log4j", Status: "not_affected", SourceFormat: "csaf"},
		{Vendor: "redhat", CVE: "CVE-1", BaseID: "pkg:rpm/openssl", Status: "fixed", SourceFormat: "csaf"},
	}
	customer := []db.Statement{
		{Vendor: "acme", CVE: "CVE-1", BaseID: "pkg:rpm/log4j", Status: "affected"},
	}

	merged, customerCVEs := Merge(vendor, customer)
	if len(merged) != 2 {
		t.Fatalf("expected 2 merged rows (1 vendor survives + 1 customer), got %d", len(merged))
	}
	// Find the surviving vendor row: should be the openssl one, not log4j.
	var foundVendorPath, foundCustomerLog4j bool
	for _, s := range merged {
		if s.Vendor == "redhat" && s.BaseID == "pkg:rpm/openssl" {
			foundVendorPath = true
		}
		if s.Vendor == "acme" && s.BaseID == "pkg:rpm/log4j" && s.Status == "affected" {
			foundCustomerLog4j = true
		}
		if s.Vendor == "redhat" && s.BaseID == "pkg:rpm/log4j" {
			t.Errorf("vendor row at colliding base_id should have been dropped, got %+v", s)
		}
	}
	if !foundVendorPath {
		t.Error("non-colliding vendor row was incorrectly dropped")
	}
	if !foundCustomerLog4j {
		t.Error("customer row missing from merged set")
	}
	if !customerCVEs["CVE-1"] {
		t.Error("customerCVEs should contain CVE-1")
	}
	if len(customerCVEs) != 1 {
		t.Errorf("customerCVEs should have exactly 1 entry, got %d", len(customerCVEs))
	}
}

func TestMerge_NoCollisionDifferentBaseIDs(t *testing.T) {
	// Customer asserts on PURL; vendor's matching row is keyed on CPE.
	// No collision (different base_ids); both survive in the merged set.
	// The SBOM-annotation override path uses customerCVEs, which still
	// captures the customer's CVE assertion so the rollup honours override.
	vendor := []db.Statement{
		{Vendor: "redhat", CVE: "CVE-1", BaseID: "cpe:/a:redhat:enterprise_linux:8::appstream", Status: "not_affected", SourceFormat: "csaf"},
	}
	customer := []db.Statement{
		{Vendor: "acme", CVE: "CVE-1", BaseID: "pkg:rpm/log4j", Status: "affected"},
	}
	merged, customerCVEs := Merge(vendor, customer)
	if len(merged) != 2 {
		t.Fatalf("expected 2 merged rows (different base_ids → no collision), got %d", len(merged))
	}
	if !customerCVEs["CVE-1"] {
		t.Error("customerCVEs must capture the customer's CVE assertion regardless of base_id collision")
	}
}

func TestMerge_SelfCollisionNewerTimestampWins(t *testing.T) {
	customer := []db.Statement{
		{Vendor: "acme", CVE: "CVE-1", BaseID: "pkg:rpm/log4j", Status: "fixed", Updated: "2026-01-01T00:00:00Z"},
		{Vendor: "acme", CVE: "CVE-1", BaseID: "pkg:rpm/log4j", Status: "affected", Updated: "2026-04-01T00:00:00Z"},
	}
	merged, _ := Merge(nil, customer)
	if len(merged) != 1 {
		t.Fatalf("expected 1 row after self-collision dedup, got %d", len(merged))
	}
	if merged[0].Status != "affected" {
		t.Errorf("newer timestamp should win, got status=%q", merged[0].Status)
	}
}

func TestMerge_SelfCollisionSameTimestampListOrderWins(t *testing.T) {
	customer := []db.Statement{
		{Vendor: "acme", CVE: "CVE-1", BaseID: "pkg:rpm/log4j", Status: "fixed", Updated: "2026-04-01T00:00:00Z"},
		{Vendor: "acme", CVE: "CVE-1", BaseID: "pkg:rpm/log4j", Status: "affected", Updated: "2026-04-01T00:00:00Z"},
	}
	merged, _ := Merge(nil, customer)
	if len(merged) != 1 {
		t.Fatalf("expected 1 row after self-collision dedup, got %d", len(merged))
	}
	if merged[0].Status != "affected" {
		t.Errorf("later list index should win on timestamp tie, got status=%q", merged[0].Status)
	}
}

func TestMerge_EmptyCustomerPassesVendorThrough(t *testing.T) {
	vendor := []db.Statement{
		{Vendor: "redhat", CVE: "CVE-1", BaseID: "pkg:rpm/log4j", Status: "not_affected", SourceFormat: "csaf"},
	}
	merged, customerCVEs := Merge(vendor, nil)
	if len(merged) != 1 {
		t.Fatalf("expected vendor unchanged with empty customer, got %d rows", len(merged))
	}
	if len(customerCVEs) != 0 {
		t.Errorf("customerCVEs should be empty, got %v", customerCVEs)
	}
}

func TestMerge_EmptyVendor(t *testing.T) {
	customer := []db.Statement{
		{Vendor: "acme", CVE: "CVE-1", BaseID: "pkg:rpm/log4j", Status: "affected"},
	}
	merged, customerCVEs := Merge(nil, customer)
	if len(merged) != 1 {
		t.Fatalf("expected 1 customer row, got %d", len(merged))
	}
	if !customerCVEs["CVE-1"] {
		t.Error("customerCVEs should contain CVE-1")
	}
}

func TestMerge_CustomerCVEsAccumulatesAcrossStatements(t *testing.T) {
	customer := []db.Statement{
		{Vendor: "acme", CVE: "CVE-1", BaseID: "pkg:rpm/log4j", Status: "affected"},
		{Vendor: "acme", CVE: "CVE-2", BaseID: "pkg:rpm/openssl", Status: "fixed"},
		{Vendor: "acme", CVE: "CVE-1", BaseID: "pkg:rpm/log4j-core", Status: "not_affected", Justification: "vulnerable_code_not_present"},
	}
	_, customerCVEs := Merge(nil, customer)
	if len(customerCVEs) != 2 {
		t.Errorf("expected 2 distinct CVEs in customerCVEs, got %d", len(customerCVEs))
	}
	if !customerCVEs["CVE-1"] || !customerCVEs["CVE-2"] {
		t.Errorf("customerCVEs missing entries: %v", customerCVEs)
	}
}
