// Package uservex parses user-supplied OpenVEX 0.2.0 documents into
// reel-vex's internal statement representation and merges them with vendor
// data using user-override semantics.
//
// User VEX is in-memory transit data only: parsed, merged, returned,
// discarded. Nothing in this package logs or persists user payloads.
//
// Inbound format is OpenVEX 0.2.0, or CycloneDX VEX which is normalised to
// OpenVEX on the way in (see Parse). The reel-vex-native flat shape is not
// accepted as input — it is a denormalised response format, not an
// interchange format.
package uservex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/getreeldev/cyclonedx-to-openvex/crosswalk"
	"github.com/getreeldev/cyclonedx-to-openvex/translator"
	"github.com/getreeldev/reel-vex/pkg/csaf"
	"github.com/getreeldev/reel-vex/pkg/db"
	"github.com/getreeldev/reel-vex/pkg/openvex"
)

// Default limits applied to inbound user VEX submissions. Each violation
// returns a typed error so the HTTP handler can map to 400 (limit overflow)
// versus 422 (shape violation). MaxStatementsTotal is the default for
// Options.MaxStatements and can be raised per-instance via the
// -max-user-vex-statements server flag; the other two are fixed.
const (
	MaxDocsPerRequest = 10
	// MaxStatementsTotal bounds the flatten fan-out per request. Sized to admit
	// real vendor VEX documents (a single tool-exported doc routinely carries
	// thousands of statements) while staying well under the body-size cap.
	MaxStatementsTotal      = 25000
	MaxProductsPerStatement = 100
)

// Sentinel errors. 400-class (limit overflows) and 422-class (shape
// violations) are distinguished via IsClientError.
var (
	ErrTooManyDocs       = errors.New("too many user_vex documents")
	ErrTooManyStatements = errors.New("too many user statements")
	ErrTooManyProducts   = errors.New("too many products in a user statement")

	ErrInvalidContext           = errors.New("user_vex doc has invalid @context (must be https://openvex.dev/ns/v0.2.0)")
	ErrInvalidStatus            = errors.New("user statement has invalid status")
	ErrInvalidJustification     = errors.New("user statement has invalid justification")
	ErrJustificationMissing     = errors.New("user statement with status=not_affected requires a justification")
	ErrJustificationMisplaced   = errors.New("user statement justification only valid with status=not_affected")
	ErrVulnerabilityNameMissing = errors.New("user statement is missing vulnerability.name")
	ErrNoProducts               = errors.New("user statement has no products")
	ErrProductNoIdentifier      = errors.New("user product has no usable identifier (need @id, identifiers.purl, identifiers.cpe22, or identifiers.cpe23)")
)

// IsClientError reports whether err is a 400-class violation (limit overflow).
// All other parse / validate errors are 422-class shape violations.
func IsClientError(err error) bool {
	return errors.Is(err, ErrTooManyDocs) ||
		errors.Is(err, ErrTooManyStatements) ||
		errors.Is(err, ErrTooManyProducts)
}

// Options tunes Parse.
type Options struct {
	// RejectLossy, when true, drops any statement whose CycloneDX->OpenVEX
	// mapping is not exact (lossy/contested) instead of normalising it. The
	// dropped count is reported in Info. Default false = normalise everything.
	RejectLossy bool
	// MaxStatements caps the flattened statement fan-out per request. <= 0 uses
	// MaxStatementsTotal. Wired from the -max-user-vex-statements server flag so
	// a self-hoster can raise it.
	MaxStatements int
}

// Info summarises what Parse did to inbound VEX so the caller can surface it
// (counts only — never statement content; user VEX is never logged/persisted).
type Info struct {
	Converted int // statements normalised from CycloneDX vocabulary
	Lossy     int // of those, with a lossy mapping
	Contested int // of those, with a contested mapping
	Skipped   int // statements dropped (invalid/unmappable, or reject-lossy)
}

// Parse decodes one or more user-supplied VEX documents into db.Statement rows.
// requestTime is the fallback timestamp used when neither the per-statement nor
// the doc-level timestamp is set.
//
// Input is OpenVEX 0.2.0 (@context = "https://openvex.dev/ns/v0.2.0") OR a
// CycloneDX BOM carrying VEX, which is converted to OpenVEX on the way in via
// the cyclonedx-to-openvex library:
//
//   - a CycloneDX BOM (bomFormat="CycloneDX") is converted whole;
//   - an OpenVEX envelope that carries CycloneDX status/justification
//     vocabulary (e.g. requires_environment) has those values remapped in place.
//
// Conversion provenance rides in each row's Notes (-> output status_notes); the
// mapping is from the published, fidelity-flagged crosswalk. Plain OpenVEX is
// left untouched. One statement with N distinct product identifiers yields N
// rows. User rows carry SourceFormat="" so encoders can tell them from vendor.
func Parse(docs []json.RawMessage, requestTime time.Time, opts Options) ([]db.Statement, Info, error) {
	var info Info
	if len(docs) > MaxDocsPerRequest {
		return nil, info, fmt.Errorf("%w: got %d, max %d", ErrTooManyDocs, len(docs), MaxDocsPerRequest)
	}
	maxStatements := opts.MaxStatements
	if maxStatements <= 0 {
		maxStatements = MaxStatementsTotal
	}

	var out []db.Statement
	total := 0
	for i, raw := range docs {
		// Route CycloneDX BOMs through the converter, then parse the result as a
		// normal OpenVEX doc (it is valid OpenVEX, with provenance in status_notes).
		fromCycloneDX := false
		var probe struct {
			BOMFormat string `json:"bomFormat"`
		}
		_ = json.Unmarshal(raw, &probe)
		if probe.BOMFormat == "CycloneDX" {
			converted, err := convertCycloneDXBOM(raw, opts, &info)
			if err != nil {
				return nil, info, fmt.Errorf("doc[%d]: %w", i, err)
			}
			raw = converted
			fromCycloneDX = true
		}

		var doc openvex.Document
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, info, fmt.Errorf("doc[%d]: invalid JSON: %w", i, err)
		}
		if doc.Context != openvex.Context {
			return nil, info, fmt.Errorf("doc[%d]: %w (got %q)", i, ErrInvalidContext, doc.Context)
		}
		docTime := pickTimestamp(doc.Timestamp, requestTime)
		for j, stmt := range doc.Statements {
			total++
			if total > maxStatements {
				return nil, info, fmt.Errorf("%w: > %d", ErrTooManyStatements, maxStatements)
			}
			if len(stmt.Products) > MaxProductsPerStatement {
				return nil, info, fmt.Errorf("doc[%d].statement[%d]: %w (%d > %d)",
					i, j, ErrTooManyProducts, len(stmt.Products), MaxProductsPerStatement)
			}

			// In-place remap of CycloneDX vocabulary in an OpenVEX envelope.
			// Plain OpenVEX (valid vocab) is untouched; converted docs (above)
			// already carry valid vocab, so this no-ops for them.
			notes, skip := normalizeVocab(&stmt, opts, &info)
			if skip {
				info.Skipped++
				continue
			}
			// For converted CycloneDX BOMs, the provenance the converter wrote
			// into status_notes is the note to surface.
			if notes == "" && fromCycloneDX {
				notes = stmt.StatusNotes
			}

			// Tolerant: a single statement that isn't valid OpenVEX (bad/missing
			// status or justification, no product identifier) is dropped and
			// counted, not fatal — one malformed row mustn't sink a 10k-statement
			// upload. Numeric limits above stay hard (resource guards).
			if err := validateStatement(stmt); err != nil {
				info.Skipped++
				continue
			}
			rows, err := flattenStatement(stmt, pickTimestamp(stmt.Timestamp, docTime))
			if err != nil {
				info.Skipped++
				continue
			}
			if notes != "" {
				for k := range rows {
					rows[k].Notes = notes
				}
			}
			out = append(out, rows...)
		}
	}
	return out, info, nil
}

// convertCycloneDXBOM converts a CycloneDX BOM to an OpenVEX document (as JSON
// bytes, ready to re-parse) and folds the converter's counts into info.
func convertCycloneDXBOM(raw []byte, opts Options, info *Info) ([]byte, error) {
	doc, rep, err := translator.FromCycloneDX(bytes.NewReader(raw), translator.Options{RejectLossy: opts.RejectLossy})
	if err != nil {
		return nil, err
	}
	info.Converted += rep.StatementsEmitted
	info.Lossy += rep.Lossy
	info.Contested += rep.Contested
	info.Skipped += rep.Skipped
	return json.Marshal(doc)
}

// normalizeVocab rewrites CycloneDX status/justification vocabulary on an
// OpenVEX-shaped statement to its OpenVEX equivalent, via the crosswalk. It
// only touches values that are NOT already valid OpenVEX, so plain OpenVEX
// statements (and already-converted ones) are left alone. Returns provenance
// notes when it remapped (empty otherwise) and whether to skip the statement
// (a remapped not_affected with no justification can't be valid OpenVEX; or
// reject-lossy dropped it). Updates info's Converted/Lossy/Contested on success.
func normalizeVocab(stmt *openvex.Statement, opts Options, info *Info) (notes string, skip bool) {
	var parts []string
	worst := crosswalk.Exact
	remapped := false

	if !validStatuses[stmt.Status] {
		if e, ok := crosswalk.LookupStatus(stmt.Status); ok {
			parts = append(parts, "original_state="+stmt.Status)
			stmt.Status = e.OpenVEX
			worst = worseFidelity(worst, e.Fidelity)
			remapped = true
		}
	}
	if stmt.Justification != "" && !validJustifications[stmt.Justification] {
		if e, ok := crosswalk.LookupJustification(stmt.Justification); ok {
			parts = append(parts, "original_justification="+stmt.Justification)
			stmt.Justification = e.OpenVEX
			worst = worseFidelity(worst, e.Fidelity)
			remapped = true
		}
	}
	if !remapped {
		return "", false
	}
	// Remapped from CycloneDX false_positive (-> not_affected) with no
	// justification: can't be valid OpenVEX, so drop rather than error.
	if stmt.Status == openvex.StatusNotAffected && stmt.Justification == "" {
		return "", true
	}
	if opts.RejectLossy && worst != crosswalk.Exact {
		return "", true
	}
	info.Converted++
	switch worst {
	case crosswalk.Lossy:
		info.Lossy++
	case crosswalk.Contested:
		info.Contested++
	}
	parts = append([]string{"converted_from=cyclonedx-vex"}, parts...)
	parts = append(parts, "fidelity="+string(worst))
	return strings.Join(parts, "; "), false
}

// worseFidelity returns the less-faithful of two fidelities (exact < lossy < contested).
func worseFidelity(a, b crosswalk.Fidelity) crosswalk.Fidelity {
	rank := map[crosswalk.Fidelity]int{crosswalk.Exact: 0, crosswalk.Lossy: 1, crosswalk.Contested: 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// pickTimestamp returns the parsed RFC3339 override, or the fallback when
// the override is empty / unparseable. Never returns a zero time as long as
// fallback is non-zero (the caller passes request time).
func pickTimestamp(override string, fallback time.Time) time.Time {
	if override != "" {
		if t, err := time.Parse(time.RFC3339, override); err == nil {
			return t
		}
	}
	return fallback
}

// flattenStatement converts one OpenVEX statement to one or more db.Statement
// rows — one per distinct product identifier carried by that statement.
//
// Identifiers are collected from each product's @id and its identifiers
// {purl, cpe22, cpe23} fields and deduplicated. base_id is computed via
// csaf.SplitPURL so the user's identifier matches a vendor row keyed
// to the same base regardless of @version / qualifier noise.
//
// SourceFormat is left empty on user rows. Vendor flows through
// supplier; an empty supplier is preserved verbatim.
func flattenStatement(stmt openvex.Statement, ts time.Time) ([]db.Statement, error) {
	ids := openvex.CollectIdentifiers(stmt.Products)
	if len(ids) == 0 {
		return nil, ErrProductNoIdentifier
	}
	tsStr := ts.UTC().Format(time.RFC3339)
	var rows []db.Statement
	for _, id := range ids {
		base, version := csaf.SplitPURL(id)
		idType := "purl"
		if !strings.HasPrefix(id, "pkg:") {
			idType = "cpe"
		}
		rows = append(rows, db.Statement{
			Vendor:        stmt.Supplier,
			CVE:           stmt.Vulnerability.Name,
			ProductID:     id,
			BaseID:        base,
			Version:       version,
			IDType:        idType,
			Status:        stmt.Status,
			Justification: stmt.Justification,
			Updated:       tsStr,
			SourceFormat:  "",
		})
	}
	return rows, nil
}
