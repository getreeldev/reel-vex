package uservex

import (
	"testing"

	"github.com/getreeldev/reel-vex/pkg/db"
)

func TestMerge_OverrideDropsCollidingVendor(t *testing.T) {
	vendor := []db.Statement{
		{Vendor: "redhat", CVE: "CVE-1", BaseID: "pkg:rpm/log4j", Status: "not_affected", SourceFormat: "csaf"},
		{Vendor: "redhat", CVE: "CVE-1", BaseID: "pkg:rpm/openssl", Status: "fixed", SourceFormat: "csaf"},
	}
	user := []db.Statement{
		{Vendor: "acme", CVE: "CVE-1", BaseID: "pkg:rpm/log4j", Status: "affected"},
	}

	merged, userCVEs := Merge(vendor, user)
	if len(merged) != 2 {
		t.Fatalf("expected 2 merged rows (1 vendor survives + 1 user), got %d", len(merged))
	}
	// Find the surviving vendor row: should be the openssl one, not log4j.
	var foundVendorPath, foundUserLog4j bool
	for _, s := range merged {
		if s.Vendor == "redhat" && s.BaseID == "pkg:rpm/openssl" {
			foundVendorPath = true
		}
		if s.Vendor == "acme" && s.BaseID == "pkg:rpm/log4j" && s.Status == "affected" {
			foundUserLog4j = true
		}
		if s.Vendor == "redhat" && s.BaseID == "pkg:rpm/log4j" {
			t.Errorf("vendor row at colliding base_id should have been dropped, got %+v", s)
		}
	}
	if !foundVendorPath {
		t.Error("non-colliding vendor row was incorrectly dropped")
	}
	if !foundUserLog4j {
		t.Error("user row missing from merged set")
	}
	if !userCVEs["CVE-1"] {
		t.Error("userCVEs should contain CVE-1")
	}
	if len(userCVEs) != 1 {
		t.Errorf("userCVEs should have exactly 1 entry, got %d", len(userCVEs))
	}
}

func TestMerge_NoCollisionDifferentBaseIDs(t *testing.T) {
	// User asserts on PURL; vendor's matching row is keyed on CPE.
	// No collision (different base_ids); both survive in the merged set.
	// The SBOM-annotation override path uses userCVEs, which still
	// captures the user's CVE assertion so the rollup honours override.
	vendor := []db.Statement{
		{Vendor: "redhat", CVE: "CVE-1", BaseID: "cpe:/a:redhat:enterprise_linux:8::appstream", Status: "not_affected", SourceFormat: "csaf"},
	}
	user := []db.Statement{
		{Vendor: "acme", CVE: "CVE-1", BaseID: "pkg:rpm/log4j", Status: "affected"},
	}
	merged, userCVEs := Merge(vendor, user)
	if len(merged) != 2 {
		t.Fatalf("expected 2 merged rows (different base_ids → no collision), got %d", len(merged))
	}
	if !userCVEs["CVE-1"] {
		t.Error("userCVEs must capture the user's CVE assertion regardless of base_id collision")
	}
}

func TestMerge_SelfCollisionNewerTimestampWins(t *testing.T) {
	user := []db.Statement{
		{Vendor: "acme", CVE: "CVE-1", BaseID: "pkg:rpm/log4j", Status: "fixed", Updated: "2026-01-01T00:00:00Z"},
		{Vendor: "acme", CVE: "CVE-1", BaseID: "pkg:rpm/log4j", Status: "affected", Updated: "2026-04-01T00:00:00Z"},
	}
	merged, _ := Merge(nil, user)
	if len(merged) != 1 {
		t.Fatalf("expected 1 row after self-collision dedup, got %d", len(merged))
	}
	if merged[0].Status != "affected" {
		t.Errorf("newer timestamp should win, got status=%q", merged[0].Status)
	}
}

func TestMerge_SelfCollisionSameTimestampListOrderWins(t *testing.T) {
	user := []db.Statement{
		{Vendor: "acme", CVE: "CVE-1", BaseID: "pkg:rpm/log4j", Status: "fixed", Updated: "2026-04-01T00:00:00Z"},
		{Vendor: "acme", CVE: "CVE-1", BaseID: "pkg:rpm/log4j", Status: "affected", Updated: "2026-04-01T00:00:00Z"},
	}
	merged, _ := Merge(nil, user)
	if len(merged) != 1 {
		t.Fatalf("expected 1 row after self-collision dedup, got %d", len(merged))
	}
	if merged[0].Status != "affected" {
		t.Errorf("later list index should win on timestamp tie, got status=%q", merged[0].Status)
	}
}

func TestMerge_EmptyUserPassesVendorThrough(t *testing.T) {
	vendor := []db.Statement{
		{Vendor: "redhat", CVE: "CVE-1", BaseID: "pkg:rpm/log4j", Status: "not_affected", SourceFormat: "csaf"},
	}
	merged, userCVEs := Merge(vendor, nil)
	if len(merged) != 1 {
		t.Fatalf("expected vendor unchanged with empty user, got %d rows", len(merged))
	}
	if len(userCVEs) != 0 {
		t.Errorf("userCVEs should be empty, got %v", userCVEs)
	}
}

func TestMerge_EmptyVendor(t *testing.T) {
	user := []db.Statement{
		{Vendor: "acme", CVE: "CVE-1", BaseID: "pkg:rpm/log4j", Status: "affected"},
	}
	merged, userCVEs := Merge(nil, user)
	if len(merged) != 1 {
		t.Fatalf("expected 1 user row, got %d", len(merged))
	}
	if !userCVEs["CVE-1"] {
		t.Error("userCVEs should contain CVE-1")
	}
}

func TestMerge_UserCVEsAccumulatesAcrossStatements(t *testing.T) {
	user := []db.Statement{
		{Vendor: "acme", CVE: "CVE-1", BaseID: "pkg:rpm/log4j", Status: "affected"},
		{Vendor: "acme", CVE: "CVE-2", BaseID: "pkg:rpm/openssl", Status: "fixed"},
		{Vendor: "acme", CVE: "CVE-1", BaseID: "pkg:rpm/log4j-core", Status: "not_affected", Justification: "vulnerable_code_not_present"},
	}
	_, userCVEs := Merge(nil, user)
	if len(userCVEs) != 2 {
		t.Errorf("expected 2 distinct CVEs in userCVEs, got %d", len(userCVEs))
	}
	if !userCVEs["CVE-1"] || !userCVEs["CVE-2"] {
		t.Errorf("userCVEs missing entries: %v", userCVEs)
	}
}
