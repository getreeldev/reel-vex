// Package openvex emits OpenVEX 0.2.0 documents from reel-vex statements.
//
// The structs mirror the OpenVEX 0.2.0 schema
// (https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md). Stdlib-only;
// no OpenVEX library dependency on purpose — keeps the reel-vex binary
// self-contained and matches the oval-to-vex stance.
package openvex

// Context is the required @context IRI on every 0.2.0 document.
const Context = "https://openvex.dev/ns/v0.2.0"

// Document is a full OpenVEX document. All fields ordered to mirror the
// spec; JSON tags keep the `@`-prefixed keys encoded verbatim.
type Document struct {
	Context     string      `json:"@context"`
	ID          string      `json:"@id"`
	Author      string      `json:"author"`
	Role        string      `json:"role,omitempty"`
	Timestamp   string      `json:"timestamp"`
	LastUpdated string      `json:"last_updated,omitempty"`
	Version     int         `json:"version"`
	Tooling     string      `json:"tooling,omitempty"`
	Statements  []Statement `json:"statements"`
}

// Statement is a single assertion about a (vulnerability, product, status)
// triple. `Justification` is only meaningful when Status == "not_affected".
type Statement struct {
	ID                       string        `json:"@id,omitempty"`
	Version                  int           `json:"version,omitempty"`
	Timestamp                string        `json:"timestamp,omitempty"`
	LastUpdated              string        `json:"last_updated,omitempty"`
	Vulnerability            Vulnerability `json:"vulnerability"`
	Products                 []Component   `json:"products,omitempty"`
	Status                   string        `json:"status"`
	StatusNotes              string        `json:"status_notes,omitempty"`
	Justification            string        `json:"justification,omitempty"`
	ImpactStatement          string        `json:"impact_statement,omitempty"`
	ActionStatement          string        `json:"action_statement,omitempty"`
	ActionStatementTimestamp string        `json:"action_statement_timestamp,omitempty"`
	Supplier                 string        `json:"supplier,omitempty"`
}

// Vulnerability identifies the CVE or advisory. `Name` is the CVE ID; the
// spec requires this field to be an object (not a bare string) in 0.2.0.
type Vulnerability struct {
	ID          string   `json:"@id,omitempty"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
}

// Component identifies a product/subject. At least one of ID or Identifiers
// must carry a usable identifier (spec: anyOf [@id, identifiers]). Pointer
// on Identifiers so an empty struct drops out of the JSON instead of
// serializing as `"identifiers":{}` — the schema's anyOf-required rule on
// purl/cpe22/cpe23 rejects that shape.
type Component struct {
	ID          string       `json:"@id,omitempty"`
	Identifiers *Identifiers `json:"identifiers,omitempty"`
}

// Identifiers carries per-scheme identifiers. Only purl, cpe22, and cpe23
// are valid per the OpenVEX 0.2.0 schema (additionalProperties: false).
type Identifiers struct {
	PURL  string `json:"purl,omitempty"`
	CPE22 string `json:"cpe22,omitempty"`
	CPE23 string `json:"cpe23,omitempty"`
}

// Valid OpenVEX status enum values (v0.2.0).
const (
	StatusNotAffected        = "not_affected"
	StatusAffected           = "affected"
	StatusFixed              = "fixed"
	StatusUnderInvestigation = "under_investigation"
)

// Valid OpenVEX justification enum values (v0.2.0). `Justification` is only
// meaningful when Status == "not_affected".
const (
	JustificationComponentNotPresent              = "component_not_present"
	JustificationVulnerableCodeNotPresent         = "vulnerable_code_not_present"
	JustificationVulnerableCodeNotInExecutePath   = "vulnerable_code_not_in_execute_path"
	JustificationVulnerableCodeCannotBeControlled = "vulnerable_code_cannot_be_controlled_by_adversary"
	JustificationInlineMitigationsAlreadyExist    = "inline_mitigations_already_exist"
)
