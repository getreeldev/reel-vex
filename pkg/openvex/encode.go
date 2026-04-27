package openvex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/getreeldev/reel-vex/pkg/db"
)

// Author is the document-level author string emitted by reel-vex. OpenVEX
// ties author identity to signatures in practice; reel-vex is an aggregator
// that doesn't sign (yet), so we declare the aggregator role explicitly.
const (
	Author = "reel-vex aggregator <vex@getreel.dev>"
	Role   = "aggregator"
)

// DocIDPrefix is the namespace reel-vex uses for @id generation. Follows
// the openvex convention: https://openvex.dev/docs/public/vex-<sha256>.
const DocIDPrefix = "https://openvex.dev/docs/public/vex-"

// now is overridable in tests so we can assert deterministic output.
var now = func() time.Time { return time.Now().UTC() }

// Encode translates reel-vex DB statements into an OpenVEX 0.2.0 document.
// baseToInputs maps each candidate base_id back to the user-supplied
// products (in base form) that produced it during resolve-time expansion;
// those inputs land in products[] so a consumer like Trivy can match
// statements keyed by CPE using the PURL the user originally sent.
// baseToReason maps each candidate base_id to the rule that produced it
// ("direct", "via_alias", "via_cpe_prefix") — carried into each statement's
// status_notes for diagnostic traceability.
//
// Statements are kept 1:1 with DB rows — each CSAF + OVAL source stays
// distinguishable via supplier + status_notes. Deterministic output:
// statements are sorted by a stable key before serialization, so two
// identical calls produce byte-identical documents (sans timestamp, which
// is emitted once at doc level).
func Encode(stmts []db.Statement, baseToInputs map[string][]string, baseToReason map[string]string) Document {
	ts := now().Format(time.RFC3339)

	sorted := make([]db.Statement, len(stmts))
	copy(sorted, stmts)
	sort.SliceStable(sorted, func(i, j int) bool {
		return stmtKey(sorted[i]) < stmtKey(sorted[j])
	})

	out := make([]Statement, 0, len(sorted))
	for _, s := range sorted {
		out = append(out, toStatement(s, baseToInputs, baseToReason))
	}

	doc := Document{
		Context:    Context,
		Author:     Author,
		Role:       Role,
		Timestamp:  ts,
		Version:    1,
		Statements: out,
	}
	doc.ID = docID(doc)
	return doc
}

// docID computes a deterministic @id from the document body. Hashes a
// canonical JSON serialization with the @id, timestamp, and last_updated
// fields zeroed so the identity depends on content only.
func docID(d Document) string {
	probe := d
	probe.ID = ""
	probe.Timestamp = ""
	probe.LastUpdated = ""
	raw, _ := json.Marshal(probe)
	sum := sha256.Sum256(raw)
	return DocIDPrefix + hex.EncodeToString(sum[:])
}

// stmtKey produces a stable sort key for DB rows. Ordered by (cve, vendor,
// source_format, product_id) so the same input set always emits the same
// statement order.
func stmtKey(s db.Statement) string {
	return s.CVE + "\x00" + s.Vendor + "\x00" + s.SourceFormat + "\x00" + s.ProductID
}

// toStatement converts one DB row into an OpenVEX Statement. Rules:
//
//   - Products come from baseToInputs[stmt.BaseID]; these are the user's
//     original inputs (base form) that expanded to match this row. Fallback
//     to the statement's own ProductID when the map is empty (defensive —
//     the join shouldn't allow it in practice).
//   - PURL inputs land in identifiers.purl AND @id (Trivy matches on PURL).
//   - CPE inputs land in identifiers.cpe23 only (Trivy ignores CPEs; other
//     consumers can still use them).
//   - Spec semantics: not_affected emits justification (or an impact_statement
//     fallback when the upstream didn't supply one); affected emits a
//     generic action_statement.
//   - Supplier carries the source vendor; status_notes carries
//     source_format + match_reason for diagnostics (reel-vex fields with no
//     direct OpenVEX equivalent).
func toStatement(s db.Statement, baseToInputs map[string][]string, baseToReason map[string]string) Statement {
	rawInputs := baseToInputs[s.BaseID]
	if len(rawInputs) == 0 {
		rawInputs = []string{s.ProductID}
	}
	inputs := make([]string, len(rawInputs))
	copy(inputs, rawInputs)
	sort.Strings(inputs)
	products := make([]Component, 0, len(inputs))
	for _, in := range inputs {
		products = append(products, componentFor(in))
	}

	// status_notes carries diagnostic provenance reel-vex wants to surface
	// without a custom OpenVEX field. User-sourced rows (no upstream
	// feed) skip the source_format= prefix entirely.
	var notesParts []string
	if s.SourceFormat != "" {
		notesParts = append(notesParts, "source_format="+s.SourceFormat)
	}
	if reason := baseToReason[s.BaseID]; reason != "" {
		notesParts = append(notesParts, "match_reason="+reason)
	}
	notes := strings.Join(notesParts, "; ")
	out := Statement{
		Vulnerability: Vulnerability{Name: s.CVE},
		Products:      products,
		Status:        s.Status,
		StatusNotes:   notes,
		Supplier:      s.Vendor,
	}
	if s.Updated != "" {
		out.Timestamp = s.Updated
	}
	switch s.Status {
	case StatusNotAffected:
		if s.Justification != "" {
			out.Justification = s.Justification
		} else {
			out.ImpactStatement = "Not affected per vendor statement; no justification supplied."
		}
	case StatusAffected:
		out.ActionStatement = "Follow vendor advisory for remediation."
	}
	return out
}

// componentFor classifies an identifier and places it in the right
// OpenVEX Component field. PURLs get both @id and identifiers.purl so
// strict-@id-only and identifiers-aware consumers both work.
func componentFor(id string) Component {
	switch {
	case strings.HasPrefix(id, "pkg:"):
		return Component{
			ID:          id,
			Identifiers: &Identifiers{PURL: id},
		}
	case strings.HasPrefix(id, "cpe:"):
		return Component{
			Identifiers: &Identifiers{CPE23: id},
		}
	default:
		return Component{ID: id}
	}
}

// Validate performs cheap structural checks that catch encoder regressions
// before an OpenVEX consumer does. Not a substitute for JSON Schema
// validation in tests, but useful as a defense-in-depth check.
func Validate(d Document) error {
	if d.Context != Context {
		return fmt.Errorf("@context must be %q", Context)
	}
	if d.ID == "" {
		return fmt.Errorf("@id required")
	}
	if d.Author == "" {
		return fmt.Errorf("author required")
	}
	if d.Timestamp == "" {
		return fmt.Errorf("timestamp required")
	}
	if d.Version == 0 {
		return fmt.Errorf("version required (integer ≥1)")
	}
	for i, s := range d.Statements {
		if s.Vulnerability.Name == "" {
			return fmt.Errorf("statement[%d]: vulnerability.name required", i)
		}
		if s.Status == "" {
			return fmt.Errorf("statement[%d]: status required", i)
		}
		if len(s.Products) == 0 {
			return fmt.Errorf("statement[%d]: at least one product required", i)
		}
		if s.Status == StatusNotAffected && s.Justification == "" && s.ImpactStatement == "" {
			return fmt.Errorf("statement[%d]: not_affected requires justification or impact_statement", i)
		}
	}
	return nil
}
