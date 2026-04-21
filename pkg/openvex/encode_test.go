package openvex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getreeldev/reel-vex/pkg/db"
)

func init() {
	// Deterministic document timestamp for tests.
	now = func() time.Time { return time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC) }
}

func TestEncode_PURLkeyedCSAF(t *testing.T) {
	stmts := []db.Statement{{
		Vendor:        "redhat",
		CVE:           "CVE-2024-0001",
		ProductID:     "pkg:rpm/redhat/openssl",
		BaseID:        "pkg:rpm/redhat/openssl",
		Status:        "not_affected",
		Justification: "vulnerable_code_not_present",
		Updated:       "2024-03-01T10:00:00Z",
		SourceFormat:  "csaf",
	}}
	baseToInputs := map[string][]string{
		"pkg:rpm/redhat/openssl": {"pkg:rpm/redhat/openssl"},
	}
	doc := Encode(stmts, baseToInputs, nil)

	if err := Validate(doc); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if doc.Context != Context {
		t.Errorf("@context = %q; want %q", doc.Context, Context)
	}
	if !strings.HasPrefix(doc.ID, DocIDPrefix) {
		t.Errorf("@id = %q; want prefix %q", doc.ID, DocIDPrefix)
	}
	if doc.Version != 1 {
		t.Errorf("version = %d; want 1", doc.Version)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("got %d statements, want 1", len(doc.Statements))
	}
	s := doc.Statements[0]
	if s.Vulnerability.Name != "CVE-2024-0001" {
		t.Errorf("vulnerability.name = %q", s.Vulnerability.Name)
	}
	if s.Status != "not_affected" || s.Justification != "vulnerable_code_not_present" {
		t.Errorf("status/justification = %q / %q", s.Status, s.Justification)
	}
	if s.Supplier != "redhat" {
		t.Errorf("supplier = %q", s.Supplier)
	}
	if !strings.Contains(s.StatusNotes, "source_format=csaf") {
		t.Errorf("status_notes missing source_format: %q", s.StatusNotes)
	}
	if len(s.Products) != 1 || s.Products[0].Identifiers == nil || s.Products[0].Identifiers.PURL != "pkg:rpm/redhat/openssl" {
		t.Errorf("products[0] unexpected: %+v", s.Products)
	}
}

// TestEncode_CPEkeyedOVAL_InputEcho confirms the core design decision: a
// CPE-keyed OVAL statement is emitted with the user's PURL input in
// products[], making it consumable by Trivy's PURL matcher.
func TestEncode_CPEkeyedOVAL_InputEcho(t *testing.T) {
	stmts := []db.Statement{{
		Vendor:        "redhat",
		CVE:           "CVE-2025-2487",
		ProductID:     "cpe:/o:redhat:enterprise_linux:9::baseos",
		BaseID:        "cpe:/o:redhat:enterprise_linux:9::baseos",
		Status:        "not_affected",
		Justification: "vulnerable_code_not_present",
		Updated:       "2026-01-15T08:00:00Z",
		SourceFormat:  "oval",
	}}
	// User queried with a PURL carrying repository_id; resolver expanded
	// to the CPE that keys the OVAL statement.
	baseToInputs := map[string][]string{
		"cpe:/o:redhat:enterprise_linux:9::baseos": {"pkg:rpm/redhat/kernel"},
	}
	baseToReason := map[string]string{
		"cpe:/o:redhat:enterprise_linux:9::baseos": "via_alias",
	}
	doc := Encode(stmts, baseToInputs, baseToReason)

	if err := Validate(doc); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	s := doc.Statements[0]
	if len(s.Products) != 1 {
		t.Fatalf("got %d products, want 1", len(s.Products))
	}
	p := s.Products[0]
	if p.Identifiers == nil || p.Identifiers.PURL != "pkg:rpm/redhat/kernel" {
		t.Errorf("expected PURL echo in identifiers.purl, got %+v", p.Identifiers)
	}
	if p.ID != "pkg:rpm/redhat/kernel" {
		t.Errorf("expected @id mirror of PURL, got %q", p.ID)
	}
	if !strings.Contains(s.StatusNotes, "match_reason=via_alias") {
		t.Errorf("status_notes missing match_reason: %q", s.StatusNotes)
	}
}

// TestEncode_SortDoesNotMutateCaller guards against a regression where the
// encoder would sort the slice referenced by baseToInputs in place.
func TestEncode_SortDoesNotMutateCaller(t *testing.T) {
	caller := []string{"pkg:rpm/redhat/zzz", "pkg:rpm/redhat/aaa"}
	baseToInputs := map[string][]string{
		"pkg:rpm/redhat/a": caller,
	}
	stmts := []db.Statement{{
		Vendor: "redhat", CVE: "CVE-X", ProductID: "pkg:rpm/redhat/a", BaseID: "pkg:rpm/redhat/a",
		Status: "fixed", Updated: "2024-01-01T00:00:00Z", SourceFormat: "csaf",
	}}
	_ = Encode(stmts, baseToInputs, nil)
	if caller[0] != "pkg:rpm/redhat/zzz" || caller[1] != "pkg:rpm/redhat/aaa" {
		t.Errorf("encoder mutated caller slice: %v", caller)
	}
}

func TestEncode_AffectedGetsActionStatement(t *testing.T) {
	stmts := []db.Statement{{
		Vendor:       "redhat",
		CVE:          "CVE-2024-0002",
		ProductID:    "pkg:rpm/redhat/curl",
		BaseID:       "pkg:rpm/redhat/curl",
		Status:       "affected",
		Updated:      "2024-03-02T10:00:00Z",
		SourceFormat: "csaf",
	}}
	baseToInputs := map[string][]string{
		"pkg:rpm/redhat/curl": {"pkg:rpm/redhat/curl"},
	}
	doc := Encode(stmts, baseToInputs, nil)
	if err := Validate(doc); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if doc.Statements[0].ActionStatement == "" {
		t.Error("affected statement must carry action_statement per spec")
	}
}

func TestEncode_NotAffectedWithoutJustification_GetsImpactStatement(t *testing.T) {
	stmts := []db.Statement{{
		Vendor:       "redhat",
		CVE:          "CVE-2024-0003",
		ProductID:    "cpe:/o:redhat:enterprise_linux:8",
		BaseID:       "cpe:/o:redhat:enterprise_linux:8",
		Status:       "not_affected",
		Updated:      "2024-03-02T10:00:00Z",
		SourceFormat: "oval",
	}}
	baseToInputs := map[string][]string{
		"cpe:/o:redhat:enterprise_linux:8": {"cpe:/o:redhat:enterprise_linux:8"},
	}
	doc := Encode(stmts, baseToInputs, nil)
	if err := Validate(doc); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	s := doc.Statements[0]
	if s.Justification == "" && s.ImpactStatement == "" {
		t.Error("not_affected must carry either justification or impact_statement per spec")
	}
}

func TestEncode_Deterministic(t *testing.T) {
	stmts := []db.Statement{
		{Vendor: "redhat", CVE: "CVE-2024-0001", ProductID: "pkg:rpm/redhat/a", BaseID: "pkg:rpm/redhat/a", Status: "not_affected", Justification: "component_not_present", Updated: "2024-01-01T00:00:00Z", SourceFormat: "csaf"},
		{Vendor: "suse", CVE: "CVE-2024-0001", ProductID: "pkg:rpm/suse/b", BaseID: "pkg:rpm/suse/b", Status: "fixed", Updated: "2024-01-01T00:00:00Z", SourceFormat: "csaf"},
	}
	baseToInputs := map[string][]string{
		"pkg:rpm/redhat/a": {"pkg:rpm/redhat/a"},
		"pkg:rpm/suse/b":   {"pkg:rpm/suse/b"},
	}
	d1 := Encode(stmts, baseToInputs, nil)
	d2 := Encode(reverse(stmts), baseToInputs, nil)
	if d1.ID != d2.ID {
		t.Errorf("@id differs across input orders: %q vs %q", d1.ID, d2.ID)
	}
	b1, _ := json.Marshal(d1)
	b2, _ := json.Marshal(d2)
	if string(b1) != string(b2) {
		t.Error("JSON output differs across input orders — encoder is not deterministic")
	}
}

func TestEncode_RoundTrip(t *testing.T) {
	stmts := []db.Statement{{
		Vendor:        "redhat",
		CVE:           "CVE-2024-0001",
		ProductID:     "pkg:rpm/redhat/openssl",
		BaseID:        "pkg:rpm/redhat/openssl",
		Status:        "not_affected",
		Justification: "vulnerable_code_not_present",
		Updated:       "2024-03-01T10:00:00Z",
		SourceFormat:  "csaf",
	}}
	baseToInputs := map[string][]string{
		"pkg:rpm/redhat/openssl": {"pkg:rpm/redhat/openssl"},
	}
	doc := Encode(stmts, baseToInputs, nil)
	first, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var parsed Document
	if err := json.Unmarshal(first, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	second, err := json.Marshal(parsed)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("round-trip not byte-stable:\nfirst:  %s\nsecond: %s", first, second)
	}
}

// TestEncode_SchemaRequiredFields reads the embedded OpenVEX 0.2.0 JSON
// Schema and checks that every `required` key at the document and
// statement levels is present in an encoded sample. Not a full JSON
// Schema validator — covers the regressions we care about (missing
// required field) without adding a runtime or test-time dependency.
func TestEncode_SchemaRequiredFields(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "openvex_json_schema_0.2.0.json"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}

	docRequired := stringSlice(t, schema, "required")
	stmts := []db.Statement{{
		Vendor:        "redhat",
		CVE:           "CVE-2024-0001",
		ProductID:     "pkg:rpm/redhat/openssl",
		BaseID:        "pkg:rpm/redhat/openssl",
		Status:        "not_affected",
		Justification: "vulnerable_code_not_present",
		Updated:       "2024-03-01T10:00:00Z",
		SourceFormat:  "csaf",
	}}
	doc := Encode(stmts, map[string][]string{"pkg:rpm/redhat/openssl": {"pkg:rpm/redhat/openssl"}}, nil)
	raw2, _ := json.Marshal(doc)
	var encoded map[string]any
	if err := json.Unmarshal(raw2, &encoded); err != nil {
		t.Fatalf("re-parse encoded: %v", err)
	}
	for _, k := range docRequired {
		if _, ok := encoded[k]; !ok {
			t.Errorf("document missing required field %q", k)
		}
	}

	// Dive into statements.items.required.
	props, _ := schema["properties"].(map[string]any)
	stmtsSchema, _ := props["statements"].(map[string]any)
	items, _ := stmtsSchema["items"].(map[string]any)
	stmtRequired := stringSlice(t, items, "required")
	rawStmts, _ := encoded["statements"].([]any)
	if len(rawStmts) == 0 {
		t.Fatal("encoded statements empty")
	}
	first, _ := rawStmts[0].(map[string]any)
	for _, k := range stmtRequired {
		if _, ok := first[k]; !ok {
			t.Errorf("statement missing required field %q", k)
		}
	}
}

func stringSlice(t *testing.T, m map[string]any, key string) []string {
	t.Helper()
	raw, ok := m[key].([]any)
	if !ok {
		t.Fatalf("schema key %q not a list", key)
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func reverse(in []db.Statement) []db.Statement {
	out := make([]db.Statement, len(in))
	for i, v := range in {
		out[len(in)-1-i] = v
	}
	return out
}
