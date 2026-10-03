//go:build integration

package acceptance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	epStatements = "/v1/statements"
	epAnalyze    = "/v1/analyze"
)

// Case is one query and the exact answer the vendor documents imply.
//
// For /v1/statements the answer is every statement's vulnerability name,
// supplier, status, justification, impact_statement, timestamp, status_notes
// and products[] identifiers, compared as a set: a missing statement and an
// extra one both fail; every OpenVEX document is also validated against the
// OpenVEX 0.2.0 schema. For /v1/analyze it is every vulnerability of the
// returned SBOM: its analysis state and justification (none when the vendor
// data said nothing) and its affects refs — or, on the user-VEX-only path,
// which answers OpenVEX, the statements as above.
type Case struct {
	Name     string
	Endpoint string
	Body     body
	Status   int
	// Rows is the X-Reel-Statements header: database rows the query matched
	// (one per vendor identifier and verdict), before statement grouping. Not
	// checked on a 4xx.
	Rows int
	// Headers are further response headers to check; "" means absent.
	Headers map[string]string
	// Error is the documented error message of a 4xx, when there is one.
	Error string
	Want  []Stmt
	Vulns []Vuln

	// Pending names the phase that adds the behaviour; the case is skipped.
	Pending string
	// Superseded names the phase whose behaviour replaces this case's
	// expectation; that phase deletes the case. Informational only.
	Superseded string
	// KnownBug says how the product disagrees with the vendor document. The
	// case still runs: a failure is reported as a skip, a pass fails so the
	// marker is removed.
	KnownBug string
}

type body = map[string]any

// Stmt is one expected OpenVEX statement. Evidence names where the vendor
// document says it (file and location).
type Stmt struct {
	CVE, Supplier, Status, Justification, Timestamp, Notes string
	// Impact is the impact_statement, which the encoder writes for a
	// not_affected verdict the vendor gave no justification for.
	Impact   string
	Products []string
	Evidence string
}

// noJustification is the impact_statement pkg/openvex writes when a vendor
// states not_affected without a justification (OpenVEX requires one of the
// two).
const noJustification = "Not affected per vendor statement; no justification supplied."

// Vuln is one expected CycloneDX vulnerability after /v1/analyze. State and
// Justification are the analysis block's ("" when there is none).
type Vuln struct {
	ID, State, Justification string
	Affects                  []string
	Evidence                 string
}

func ss(s ...string) []string { return s }

func runCases(t *testing.T, cases []Case) {
	t.Helper()
	seen := map[string]bool{}
	for _, c := range cases {
		if seen[c.Name] {
			t.Fatalf("duplicate case name %q", c.Name)
		}
		seen[c.Name] = true
		t.Run(c.Name, func(t *testing.T) { runCase(t, c) })
	}
}

func runCase(t *testing.T, c Case) {
	for _, s := range c.Want {
		if s.Evidence == "" {
			t.Fatalf("expected statement %s %s %v has no evidence", s.CVE, s.Status, s.Products)
		}
	}
	for _, v := range c.Vulns {
		if v.Evidence == "" {
			t.Fatalf("expected vulnerability %s has no evidence", v.ID)
		}
	}
	if c.Pending != "" {
		t.Skip("pending: " + c.Pending)
	}
	errs := check(c)
	switch {
	case c.KnownBug != "" && len(errs) > 0:
		for _, e := range errs {
			t.Log(e)
		}
		t.Skip("KNOWN BUG: " + c.KnownBug)
	case c.KnownBug != "":
		t.Fatal("known bug fixed — remove KnownBug: " + c.KnownBug)
	default:
		for _, e := range errs {
			t.Error(e)
		}
	}
}

// check runs the query and returns every way the answer differs from the case.
func check(c Case) []string {
	raw, err := json.Marshal(c.Body)
	if err != nil {
		return []string{err.Error()}
	}
	resp, err := http.Post(env.serverURL+c.Endpoint, "application/json", bytes.NewReader(raw))
	if err != nil {
		return []string{err.Error()}
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	var errs []string
	if resp.StatusCode != c.Status {
		return []string{fmt.Sprintf("status %d, want %d: %s", resp.StatusCode, c.Status, respBody)}
	}
	if c.Status >= 400 {
		if c.Error != "" {
			var e struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(respBody, &e); err != nil || e.Error != c.Error {
				errs = append(errs, fmt.Sprintf("error body %s, want error %q", respBody, c.Error))
			}
		}
		return errs
	}
	if got := resp.Header.Get("X-Reel-Statements"); got != strconv.Itoa(c.Rows) {
		errs = append(errs, fmt.Sprintf("X-Reel-Statements %q, want %d", got, c.Rows))
	}
	for _, h := range sortedKeys(c.Headers) {
		if got := resp.Header.Get(h); got != c.Headers[h] {
			errs = append(errs, fmt.Sprintf("%s %q, want %q", h, got, c.Headers[h]))
		}
	}
	if c.Status != http.StatusOK {
		return errs
	}
	openVEX := c.Endpoint == epStatements || (c.Endpoint == epAnalyze && len(c.Want) > 0)
	switch {
	case openVEX:
		if err := validateOpenVEX(respBody); err != nil {
			errs = append(errs, "not valid OpenVEX 0.2.0: "+err.Error())
		}
		errs = append(errs, compareStatements(respBody, c.Want)...)
	case c.Endpoint == epAnalyze:
		errs = append(errs, compareVulns(respBody, c.Vulns)...)
	default:
		errs = append(errs, "unknown endpoint "+c.Endpoint)
	}
	return errs
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// The OpenVEX 0.2.0 JSON schema pkg/openvex's own tests validate against.
var (
	schemaOnce sync.Once
	schema     *jsonschema.Schema
	schemaErr  error
)

func validateOpenVEX(raw []byte) error {
	schemaOnce.Do(func() {
		var b []byte
		b, schemaErr = os.ReadFile(filepath.Join(repoRoot(), "pkg", "openvex", "testdata", "openvex_json_schema_0.2.0.json"))
		if schemaErr != nil {
			return
		}
		var doc any
		if doc, schemaErr = jsonschema.UnmarshalJSON(bytes.NewReader(b)); schemaErr != nil {
			return
		}
		c := jsonschema.NewCompiler()
		if schemaErr = c.AddResource("openvex.json", doc); schemaErr != nil {
			return
		}
		schema, schemaErr = c.Compile("openvex.json")
	})
	if schemaErr != nil {
		return fmt.Errorf("load schema: %w", schemaErr)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	return schema.Validate(inst)
}

type gotDoc struct {
	Statements []struct {
		Vulnerability struct {
			Name string `json:"name"`
		} `json:"vulnerability"`
		Products []struct {
			ID          string `json:"@id"`
			Identifiers *struct {
				PURL  string `json:"purl"`
				CPE22 string `json:"cpe22"`
				CPE23 string `json:"cpe23"`
			} `json:"identifiers"`
		} `json:"products"`
		Status          string `json:"status"`
		StatusNotes     string `json:"status_notes"`
		Justification   string `json:"justification"`
		ImpactStatement string `json:"impact_statement"`
		Supplier        string `json:"supplier"`
		Timestamp       string `json:"timestamp"`
	} `json:"statements"`
}

func stmtKey(s Stmt) string {
	p := append([]string(nil), s.Products...)
	sort.Strings(p)
	return strings.Join([]string{s.CVE, s.Supplier, s.Status, s.Justification, s.Impact, s.Timestamp, s.Notes, strings.Join(p, " | ")}, " ‖ ")
}

func compareStatements(raw []byte, want []Stmt) []string {
	var doc gotDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return []string{"decode OpenVEX: " + err.Error()}
	}
	var got []Stmt
	for _, s := range doc.Statements {
		g := Stmt{CVE: s.Vulnerability.Name, Supplier: s.Supplier, Status: s.Status,
			Justification: s.Justification, Impact: s.ImpactStatement, Timestamp: s.Timestamp, Notes: s.StatusNotes}
		for _, p := range s.Products {
			id := p.ID
			if p.Identifiers != nil {
				switch {
				case p.Identifiers.PURL != "":
					id = p.Identifiers.PURL
				case p.Identifiers.CPE23 != "":
					id = p.Identifiers.CPE23
				case p.Identifiers.CPE22 != "":
					id = p.Identifiers.CPE22
				}
			}
			g.Products = append(g.Products, id)
		}
		got = append(got, g)
	}
	return diff(got, want, stmtKey)
}

type gotSBOM struct {
	Vulnerabilities []struct {
		ID       string `json:"id"`
		Analysis *struct {
			State         string `json:"state"`
			Justification string `json:"justification"`
		} `json:"analysis"`
		Affects []struct {
			Ref string `json:"ref"`
		} `json:"affects"`
	} `json:"vulnerabilities"`
}

func vulnKey(v Vuln) string {
	a := append([]string(nil), v.Affects...)
	sort.Strings(a)
	return strings.Join([]string{v.ID, v.State, v.Justification, strings.Join(a, " | ")}, " ‖ ")
}

func compareVulns(raw []byte, want []Vuln) []string {
	var doc gotSBOM
	if err := json.Unmarshal(raw, &doc); err != nil {
		return []string{"decode CycloneDX: " + err.Error()}
	}
	var got []Vuln
	for _, v := range doc.Vulnerabilities {
		g := Vuln{ID: v.ID}
		if v.Analysis != nil {
			g.State, g.Justification = v.Analysis.State, v.Analysis.Justification
		}
		for _, a := range v.Affects {
			g.Affects = append(g.Affects, a.Ref)
		}
		got = append(got, g)
	}
	return diff(got, want, vulnKey)
}

// diff compares two multisets by key and describes what is missing and extra.
func diff[T any](got, want []T, key func(T) string) []string {
	count := map[string]int{}
	for _, w := range want {
		count[key(w)]++
	}
	for _, g := range got {
		count[key(g)]--
	}
	var missing, extra []string
	for k, n := range count {
		for ; n > 0; n-- {
			missing = append(missing, k)
		}
		for ; n < 0; n++ {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	var errs []string
	for _, m := range missing {
		errs = append(errs, "missing:    "+m)
	}
	for _, e := range extra {
		errs = append(errs, "unexpected: "+e)
	}
	return errs
}

// TestSchemaValidatorBites proves the schema check is live: an OpenVEX
// document with no statements (the schema's minItems 1) is rejected.
func TestSchemaValidatorBites(t *testing.T) {
	doc := `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://openvex.dev/docs/public/vex-x","author":"a","timestamp":"2026-10-03T00:00:00Z","version":1,"statements":[]}`
	if err := validateOpenVEX([]byte(doc)); err == nil {
		t.Fatal("a document with no statements validated against the OpenVEX 0.2.0 schema")
	}
}
