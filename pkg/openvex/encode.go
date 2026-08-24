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
// Rows are converted 1:1 and then grouped (see group): rows that make the
// same assertion about different subjects collapse into one statement whose
// products[] is the union. Each CSAF + OVAL source stays distinguishable,
// because supplier and status_notes are both part of the merge key.
// Deterministic output: statements are sorted by a stable key before
// grouping and products are ordered within each group, so two identical
// calls produce byte-identical documents (sans timestamp, which is emitted
// once at doc level).
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
	out = group(out)

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

// group merges statements that make the same assertion about different
// subjects into a single statement carrying all of them in products[].
//
// This is what OpenVEX's products[] array is for, and skipping it is not just
// verbose — it is invalid. The 0.2.0 schema declares statements with
// `uniqueItems: true`, and a query that supplies products echoes the caller's
// identifier (base form: no version, no arch) rather than each row's own
// product_id, so the eight architectures × five package versions a distro
// publishes for one advisory all render as the *same* statement. Before
// grouping, an SBOM query for ubuntu:22.04 returned 13,543 statements of
// which 12,215 were byte-identical duplicates, and the document failed schema
// validation.
//
// Two rows merge only when they agree on every statement-level field, so no
// information is lost: a different verdict, vendor, timestamp, justification,
// or provenance keeps them apart. status_notes carries source_format,
// match_reason and scope, which is why it must stay in the key — otherwise a
// CSAF row and an OVAL row, or a scoped Rancher verdict and an unscoped one,
// would fuse into a single statement that misreports its own provenance.
func group(in []Statement) []Statement {
	idx := make(map[string]int, len(in))
	out := make([]Statement, 0, len(in))
	for _, s := range in {
		k := groupKey(s)
		if i, seen := idx[k]; seen {
			out[i].Products = append(out[i].Products, s.Products...)
			continue
		}
		// Copy the products slice before it can be appended to: the caller's
		// backing array must not be written through.
		s.Products = append([]Component(nil), s.Products...)
		idx[k] = len(out)
		out = append(out, s)
	}
	for i := range out {
		out[i].Products = dedupeComponents(out[i].Products)
	}
	return out
}

// groupKey is the statement with its subjects removed — two statements
// producing the same key are the same assertion about different products.
//
// Marshalling the whole struct rather than naming fields is deliberate: a
// field added to Statement later joins the merge key automatically. A
// hand-written key would silently start over-merging the day someone wires up
// a new provenance or impact field, and over-merging is how a document starts
// telling a consumer something the vendor never said.
func groupKey(s Statement) string {
	probe := s
	probe.Products = nil
	b, _ := json.Marshal(probe)
	return string(b)
}

// dedupeComponents sorts a group's products and drops exact repeats. The
// schema puts uniqueItems on products[] too, so the dedupe is required and
// not merely tidy.
//
// Ordering is by identifier first so the output matches the order the encoder
// already produced for a single row (toStatement sorts its inputs as plain
// strings); the serialized form is only a tiebreaker for the pathological case
// of two components sharing an identifier but differing elsewhere.
func dedupeComponents(in []Component) []Component {
	type keyed struct {
		id  string
		raw string
		c   Component
	}
	ks := make([]keyed, 0, len(in))
	for _, c := range in {
		b, _ := json.Marshal(c)
		ks = append(ks, keyed{id: componentID(c), raw: string(b), c: c})
	}
	sort.SliceStable(ks, func(i, j int) bool {
		if ks[i].id != ks[j].id {
			return ks[i].id < ks[j].id
		}
		return ks[i].raw < ks[j].raw
	})
	out := make([]Component, 0, len(ks))
	prev := ""
	for i, k := range ks {
		if i > 0 && k.raw == prev {
			continue
		}
		prev = k.raw
		out = append(out, k.c)
	}
	return out
}

// componentID returns the identifier a Component is ordered by: @id when set
// (every PURL carries one), else whichever identifier scheme is populated.
func componentID(c Component) string {
	if c.ID != "" {
		return c.ID
	}
	if c.Identifiers == nil {
		return ""
	}
	switch {
	case c.Identifiers.PURL != "":
		return c.Identifiers.PURL
	case c.Identifiers.CPE23 != "":
		return c.Identifiers.CPE23
	default:
		return c.Identifiers.CPE22
	}
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
//     source_format + match_reason (+ scope for product-scoped rows) for
//     diagnostics (reel-vex fields with no direct OpenVEX equivalent).
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
	// Product-scoped rows (Rancher VEX) disclose the scope they were asserted
	// under: the consumer named it (the image being scanned), and surfacing it
	// makes the conditional nature of the verdict explicit in the document.
	if s.Scope != "" {
		notesParts = append(notesParts, "scope="+s.Scope)
	}
	// Conversion provenance for user VEX normalised on the way in (CycloneDX ->
	// OpenVEX). Already in `key=value; ...` shape, so append verbatim.
	if s.Notes != "" {
		notesParts = append(notesParts, s.Notes)
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
