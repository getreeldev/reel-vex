package uservex

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const validDoc = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements": [
    {
      "vulnerability": {"name": "CVE-2021-44228"},
      "products": [{"@id": "pkg:rpm/redhat/log4j"}],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "supplier": "acme",
      "timestamp": "2026-04-20T10:00:00Z"
    }
  ]
}`

func mustRaw(t *testing.T, s string) json.RawMessage {
	t.Helper()
	var raw json.RawMessage
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		t.Fatalf("setup: %v", err)
	}
	return raw
}

func TestParse_HappyPath(t *testing.T) {
	stmts, _, err := Parse([]json.RawMessage{mustRaw(t, validDoc)}, time.Now(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(stmts))
	}
	got := stmts[0]
	if got.Vendor != "acme" {
		t.Errorf("vendor: got %q, want %q (supplier flows through)", got.Vendor, "acme")
	}
	if got.CVE != "CVE-2021-44228" {
		t.Errorf("cve: got %q", got.CVE)
	}
	if got.ProductID != "pkg:rpm/redhat/log4j" {
		t.Errorf("product_id: got %q", got.ProductID)
	}
	if got.BaseID != "pkg:rpm/redhat/log4j" {
		t.Errorf("base_id: got %q", got.BaseID)
	}
	if got.IDType != "purl" {
		t.Errorf("id_type: got %q, want purl", got.IDType)
	}
	if got.SourceFormat != "" {
		t.Errorf("source_format: got %q, want empty (user rows have no upstream feed)", got.SourceFormat)
	}
	if got.Updated != "2026-04-20T10:00:00Z" {
		t.Errorf("updated: got %q (per-statement timestamp should win)", got.Updated)
	}
}

func TestParse_TimestampFallbackChain(t *testing.T) {
	// Per-statement absent → doc timestamp wins.
	docNoStmtTS := `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "timestamp": "2026-04-21T00:00:00Z",
  "statements": [
    {"vulnerability":{"name":"CVE-X"},"products":[{"@id":"pkg:rpm/x"}],"status":"fixed"}
  ]
}`
	requestTime := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	stmts, _, err := Parse([]json.RawMessage{mustRaw(t, docNoStmtTS)}, requestTime, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stmts[0].Updated != "2026-04-21T00:00:00Z" {
		t.Errorf("expected doc timestamp to win: got %q", stmts[0].Updated)
	}

	// Both absent → request time stamps.
	docNoTS := `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements": [
    {"vulnerability":{"name":"CVE-X"},"products":[{"@id":"pkg:rpm/x"}],"status":"fixed"}
  ]
}`
	stmts, _, err = Parse([]json.RawMessage{mustRaw(t, docNoTS)}, requestTime, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stmts[0].Updated != "2030-01-01T00:00:00Z" {
		t.Errorf("expected request time stamp: got %q", stmts[0].Updated)
	}
}

func TestParse_RejectsBadContext(t *testing.T) {
	bad := `{"@context":"https://wrong.example/","statements":[]}`
	_, _, err := Parse([]json.RawMessage{mustRaw(t, bad)}, time.Now(), Options{})
	if !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("expected ErrInvalidContext, got %v", err)
	}
}

func TestParse_SkipsInvalidStatus(t *testing.T) {
	bad := `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements":[{"vulnerability":{"name":"CVE-X"},"products":[{"@id":"pkg:rpm/x"}],"status":"made_up"}]
}`
	stmts, info, err := Parse([]json.RawMessage{mustRaw(t, bad)}, time.Now(), Options{})
	if err != nil || len(stmts) != 0 || info.Skipped != 1 {
		t.Fatalf("tolerant skip expected: got stmts=%d skipped=%d err=%v", len(stmts), info.Skipped, err)
	}
}

// An OpenVEX-shaped doc carrying a CycloneDX justification (Pau's real-world
// case) is now NORMALISED in place via the crosswalk, not rejected:
// requires_environment -> vulnerable_code_cannot_be_controlled_by_adversary
// (lossy), with provenance in the row's Notes.
func TestParse_RemapsCycloneDXJustification(t *testing.T) {
	doc := `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements":[{"vulnerability":{"name":"CVE-2022-42898"},"products":[{"@id":"pkg:deb/debian/libk5crypto3"}],"status":"not_affected","justification":"requires_environment"}]
}`
	stmts, info, err := Parse([]json.RawMessage{mustRaw(t, doc)}, time.Now(), Options{})
	if err != nil {
		t.Fatalf("expected conversion, got error: %v", err)
	}
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(stmts))
	}
	if stmts[0].Justification != "vulnerable_code_cannot_be_controlled_by_adversary" {
		t.Errorf("justification not remapped: got %q", stmts[0].Justification)
	}
	if info.Converted != 1 || info.Lossy != 1 {
		t.Errorf("info: converted=%d lossy=%d (want 1/1)", info.Converted, info.Lossy)
	}
	for _, want := range []string{"converted_from=cyclonedx-vex", "original_justification=requires_environment", "fidelity=lossy"} {
		if !strings.Contains(stmts[0].Notes, want) {
			t.Errorf("Notes missing %q: got %q", want, stmts[0].Notes)
		}
	}
}

// A CycloneDX analysis.state in an OpenVEX envelope is likewise remapped:
// in_triage -> under_investigation (exact, no justification needed).
func TestParse_RemapsCycloneDXState(t *testing.T) {
	doc := `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements":[{"vulnerability":{"name":"CVE-X"},"products":[{"@id":"pkg:rpm/x"}],"status":"in_triage"}]
}`
	stmts, info, err := Parse([]json.RawMessage{mustRaw(t, doc)}, time.Now(), Options{})
	if err != nil {
		t.Fatalf("expected conversion, got error: %v", err)
	}
	if len(stmts) != 1 || stmts[0].Status != "under_investigation" {
		t.Fatalf("status not remapped: %+v", stmts)
	}
	if info.Converted != 1 {
		t.Errorf("info.Converted=%d, want 1", info.Converted)
	}
}

// RejectLossy drops the lossy mapping instead of normalising it.
func TestParse_RejectLossyDropsLossy(t *testing.T) {
	doc := `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements":[{"vulnerability":{"name":"CVE-X"},"products":[{"@id":"pkg:rpm/x"}],"status":"not_affected","justification":"requires_environment"}]
}`
	stmts, info, err := Parse([]json.RawMessage{mustRaw(t, doc)}, time.Now(), Options{RejectLossy: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(stmts) != 0 || info.Skipped != 1 {
		t.Errorf("reject-lossy: stmts=%d skipped=%d (want 0/1)", len(stmts), info.Skipped)
	}
}

// A genuine CycloneDX BOM in the user_vex slot is converted whole.
func TestParse_ConvertsCycloneDXBOM(t *testing.T) {
	bom := `{
  "bomFormat":"CycloneDX","specVersion":"1.6",
  "vulnerabilities":[{"id":"CVE-2023-0001","analysis":{"state":"not_affected","justification":"code_not_reachable"},"affects":[{"ref":"pkg:golang/x@v1.0.0"}]}]
}`
	stmts, info, err := Parse([]json.RawMessage{mustRaw(t, bom)}, time.Now(), Options{})
	if err != nil {
		t.Fatalf("BOM conversion failed: %v", err)
	}
	if len(stmts) != 1 || stmts[0].Justification != "vulnerable_code_not_in_execute_path" {
		t.Fatalf("BOM not converted as expected: %+v", stmts)
	}
	if info.Converted != 1 {
		t.Errorf("info.Converted=%d, want 1", info.Converted)
	}
	if !strings.Contains(stmts[0].Notes, "converted_from=cyclonedx-vex") {
		t.Errorf("BOM row missing conversion provenance: %q", stmts[0].Notes)
	}
}

// Plain OpenVEX is left untouched — no conversion, no Notes.
func TestParse_PlainOpenVEXUntouched(t *testing.T) {
	stmts, info, err := Parse([]json.RawMessage{mustRaw(t, validDoc)}, time.Now(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Converted != 0 || stmts[0].Notes != "" {
		t.Errorf("plain OpenVEX should be untouched: converted=%d notes=%q", info.Converted, stmts[0].Notes)
	}
}

func TestParse_NotAffectedRequiresJustification(t *testing.T) {
	bad := `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements":[{"vulnerability":{"name":"CVE-X"},"products":[{"@id":"pkg:rpm/x"}],"status":"not_affected"}]
}`
	stmts, info, err := Parse([]json.RawMessage{mustRaw(t, bad)}, time.Now(), Options{})
	if err != nil || len(stmts) != 0 || info.Skipped != 1 {
		t.Fatalf("tolerant skip expected: got stmts=%d skipped=%d err=%v", len(stmts), info.Skipped, err)
	}
}

func TestParse_JustificationOnlyValidWithNotAffected(t *testing.T) {
	bad := `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements":[{"vulnerability":{"name":"CVE-X"},"products":[{"@id":"pkg:rpm/x"}],"status":"affected","justification":"vulnerable_code_not_present"}]
}`
	stmts, info, err := Parse([]json.RawMessage{mustRaw(t, bad)}, time.Now(), Options{})
	if err != nil || len(stmts) != 0 || info.Skipped != 1 {
		t.Fatalf("tolerant skip expected: got stmts=%d skipped=%d err=%v", len(stmts), info.Skipped, err)
	}
}

func TestParse_MissingVulnerabilityName(t *testing.T) {
	bad := `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements":[{"vulnerability":{},"products":[{"@id":"pkg:rpm/x"}],"status":"fixed"}]
}`
	stmts, info, err := Parse([]json.RawMessage{mustRaw(t, bad)}, time.Now(), Options{})
	if err != nil || len(stmts) != 0 || info.Skipped != 1 {
		t.Fatalf("tolerant skip expected: got stmts=%d skipped=%d err=%v", len(stmts), info.Skipped, err)
	}
}

func TestParse_MissingProducts(t *testing.T) {
	bad := `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements":[{"vulnerability":{"name":"CVE-X"},"products":[],"status":"fixed"}]
}`
	stmts, info, err := Parse([]json.RawMessage{mustRaw(t, bad)}, time.Now(), Options{})
	if err != nil || len(stmts) != 0 || info.Skipped != 1 {
		t.Fatalf("tolerant skip expected: got stmts=%d skipped=%d err=%v", len(stmts), info.Skipped, err)
	}
}

func TestParse_ProductWithoutIdentifier(t *testing.T) {
	bad := `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements":[{"vulnerability":{"name":"CVE-X"},"products":[{}],"status":"fixed"}]
}`
	stmts, info, err := Parse([]json.RawMessage{mustRaw(t, bad)}, time.Now(), Options{})
	if err != nil || len(stmts) != 0 || info.Skipped != 1 {
		t.Fatalf("tolerant skip expected: got stmts=%d skipped=%d err=%v", len(stmts), info.Skipped, err)
	}
}

func TestParse_TooManyDocs(t *testing.T) {
	docs := make([]json.RawMessage, MaxDocsPerRequest+1)
	for i := range docs {
		docs[i] = mustRaw(t, validDoc)
	}
	_, _, err := Parse(docs, time.Now(), Options{})
	if !errors.Is(err, ErrTooManyDocs) || !IsClientError(err) {
		t.Fatalf("expected ErrTooManyDocs (client error), got %v", err)
	}
}

func TestParse_TooManyStatements(t *testing.T) {
	// Build one doc with MaxStatementsTotal+1 statements.
	var b strings.Builder
	b.WriteString(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[`)
	for i := 0; i <= MaxStatementsTotal; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"vulnerability":{"name":"CVE-X"},"products":[{"@id":"pkg:rpm/x"}],"status":"fixed"}`)
	}
	b.WriteString(`]}`)
	_, _, err := Parse([]json.RawMessage{mustRaw(t, b.String())}, time.Now(), Options{})
	if !errors.Is(err, ErrTooManyStatements) || !IsClientError(err) {
		t.Fatalf("expected ErrTooManyStatements (client error), got %v", err)
	}
}

func TestParse_TooManyProductsPerStatement(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"vulnerability":{"name":"CVE-X"},"status":"fixed","products":[`)
	for i := 0; i <= MaxProductsPerStatement; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"@id":"pkg:rpm/x`)
		b.WriteString(strings.Repeat("a", i+1))
		b.WriteString(`"}`)
	}
	b.WriteString(`]}]}`)
	_, _, err := Parse([]json.RawMessage{mustRaw(t, b.String())}, time.Now(), Options{})
	if !errors.Is(err, ErrTooManyProducts) || !IsClientError(err) {
		t.Fatalf("expected ErrTooManyProducts (client error), got %v", err)
	}
}

func TestParse_OneStatementMultipleIdentifiers(t *testing.T) {
	doc := `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements":[{
    "vulnerability":{"name":"CVE-X"},
    "products":[{
      "@id":"pkg:rpm/redhat/log4j",
      "identifiers":{"purl":"pkg:rpm/redhat/log4j","cpe23":"cpe:2.3:a:redhat:log4j:*"}
    }],
    "status":"fixed"
  }]
}`
	stmts, _, err := Parse([]json.RawMessage{mustRaw(t, doc)}, time.Now(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// @id and identifiers.purl are the same → 1 row. cpe23 is different → +1 row.
	if len(stmts) != 2 {
		t.Fatalf("expected 2 deduplicated rows (purl + cpe23), got %d", len(stmts))
	}
	hasPURL, hasCPE := false, false
	for _, s := range stmts {
		switch s.IDType {
		case "purl":
			hasPURL = true
		case "cpe":
			hasCPE = true
		}
	}
	if !hasPURL || !hasCPE {
		t.Errorf("expected one purl and one cpe row, got %+v", stmts)
	}
}

func TestParse_PURLBaseIDPreservesDistroQualifier(t *testing.T) {
	doc := `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements":[{
    "vulnerability":{"name":"CVE-X"},
    "products":[{"@id":"pkg:deb/ubuntu/openssl@3.0.13?distro=ubuntu-24.04"}],
    "status":"fixed"
  }]
}`
	stmts, _, err := Parse([]json.RawMessage{mustRaw(t, doc)}, time.Now(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stmts[0].BaseID != "pkg:deb/ubuntu/openssl?distro=ubuntu-24.04" {
		t.Errorf("base_id should preserve distro qualifier (deb identity), got %q", stmts[0].BaseID)
	}
	if stmts[0].Version != "3.0.13" {
		t.Errorf("version should be split out, got %q", stmts[0].Version)
	}
}

func TestParse_EmptySupplier(t *testing.T) {
	doc := `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements":[{
    "vulnerability":{"name":"CVE-X"},
    "products":[{"@id":"pkg:rpm/x"}],
    "status":"fixed"
  }]
}`
	stmts, _, err := Parse([]json.RawMessage{mustRaw(t, doc)}, time.Now(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stmts[0].Vendor != "" {
		t.Errorf("missing supplier should yield empty vendor, got %q", stmts[0].Vendor)
	}
}
