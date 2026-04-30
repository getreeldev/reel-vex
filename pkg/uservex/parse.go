// Package uservex parses user-supplied OpenVEX 0.2.0 documents into
// reel-vex's internal statement representation and merges them with vendor
// data using user-override semantics.
//
// User VEX is in-memory transit data only: parsed, merged, returned,
// discarded. Nothing in this package logs or persists user payloads.
//
// Inbound format is OpenVEX 0.2.0 only. The reel-vex-native flat shape is not
// accepted as input — it is a denormalised response format, not an
// interchange format.
package uservex

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/getreeldev/reel-vex/pkg/csaf"
	"github.com/getreeldev/reel-vex/pkg/db"
	"github.com/getreeldev/reel-vex/pkg/openvex"
)

// Limits applied to inbound user VEX submissions. Hardcoded; not
// configurable via flags or environment. Each violation returns a typed
// error so the HTTP handler can map to 400 (limit overflow) versus 422
// (shape violation).
const (
	MaxDocsPerRequest       = 10
	MaxStatementsTotal      = 1000
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

// Parse decodes one or more user-supplied OpenVEX 0.2.0 documents into
// db.Statement rows. requestTime is the fallback timestamp used when neither
// the per-statement nor the doc-level timestamp is set.
//
// Each input doc must carry @context = "https://openvex.dev/ns/v0.2.0".
//
// One OpenVEX statement with N distinct product identifiers yields N
// db.Statement rows (one per identifier). User rows carry SourceFormat=""
// so downstream encoders can distinguish user-sourced rows from
// vendor-feed rows.
func Parse(docs []json.RawMessage, requestTime time.Time) ([]db.Statement, error) {
	if len(docs) > MaxDocsPerRequest {
		return nil, fmt.Errorf("%w: got %d, max %d", ErrTooManyDocs, len(docs), MaxDocsPerRequest)
	}

	var out []db.Statement
	total := 0
	for i, raw := range docs {
		var doc openvex.Document
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("doc[%d]: invalid JSON: %w", i, err)
		}
		if doc.Context != openvex.Context {
			return nil, fmt.Errorf("doc[%d]: %w (got %q)", i, ErrInvalidContext, doc.Context)
		}
		docTime := pickTimestamp(doc.Timestamp, requestTime)
		for j, stmt := range doc.Statements {
			total++
			if total > MaxStatementsTotal {
				return nil, fmt.Errorf("%w: > %d", ErrTooManyStatements, MaxStatementsTotal)
			}
			if len(stmt.Products) > MaxProductsPerStatement {
				return nil, fmt.Errorf("doc[%d].statement[%d]: %w (%d > %d)",
					i, j, ErrTooManyProducts, len(stmt.Products), MaxProductsPerStatement)
			}
			if err := validateStatement(stmt); err != nil {
				return nil, fmt.Errorf("doc[%d].statement[%d]: %w", i, j, err)
			}
			rows, err := flattenStatement(stmt, pickTimestamp(stmt.Timestamp, docTime))
			if err != nil {
				return nil, fmt.Errorf("doc[%d].statement[%d]: %w", i, j, err)
			}
			out = append(out, rows...)
		}
	}
	return out, nil
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
