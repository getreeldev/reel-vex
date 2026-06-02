package uservex

import (
	"fmt"

	"github.com/getreeldev/reel-vex/pkg/openvex"
)

// validStatuses mirrors the OpenVEX 0.2.0 status enum.
var validStatuses = map[string]bool{
	openvex.StatusNotAffected:        true,
	openvex.StatusAffected:           true,
	openvex.StatusFixed:              true,
	openvex.StatusUnderInvestigation: true,
}

// validJustifications mirrors the OpenVEX 0.2.0 justification enum. Only
// meaningful when status == not_affected.
var validJustifications = map[string]bool{
	openvex.JustificationComponentNotPresent:              true,
	openvex.JustificationVulnerableCodeNotPresent:         true,
	openvex.JustificationVulnerableCodeNotInExecutePath:   true,
	openvex.JustificationVulnerableCodeCannotBeControlled: true,
	openvex.JustificationInlineMitigationsAlreadyExist:    true,
}

// cyclonedxJustifications is the CycloneDX VEX analysis.justification enum.
// None of these are valid OpenVEX — a document using them is CycloneDX-flavoured,
// the most common real-world reason a "VEX" upload fails OpenVEX validation.
var cyclonedxJustifications = map[string]bool{
	"code_not_present":                true,
	"code_not_reachable":              true,
	"requires_configuration":          true,
	"requires_dependency":             true,
	"requires_environment":            true,
	"protected_by_compiler":           true,
	"protected_at_runtime":            true,
	"protected_at_perimeter":          true,
	"protected_by_mitigating_control": true,
}

// cyclonedxStates is the CycloneDX VEX analysis.state enum, minus not_affected
// (which is also a valid OpenVEX status, so it must not be flagged).
var cyclonedxStates = map[string]bool{
	"resolved":               true,
	"resolved_with_pedigree": true,
	"exploitable":            true,
	"in_triage":              true,
	"false_positive":         true,
}

// validateStatement enforces the inbound shape rules. Distinct from
// pkg/openvex.Validate, which is outbound-focused (requires fields like @id
// and author that the server fills in, not the user).
//
// Inbound rules:
//   - vulnerability.name must be non-empty (we have nothing to merge against without a CVE).
//   - status must be a valid OpenVEX 0.2.0 enum value.
//   - justification, when present, must be a valid enum value AND status must be not_affected.
//   - status==not_affected requires a justification.
//   - products[] must be non-empty (per OpenVEX schema; also no merge target without it).
//
// Per-product identifier presence is checked later in flattenStatement so
// the error points at the product index rather than failing wholesale here.
func validateStatement(stmt openvex.Statement) error {
	if stmt.Vulnerability.Name == "" {
		return ErrVulnerabilityNameMissing
	}
	if !validStatuses[stmt.Status] {
		if cyclonedxStates[stmt.Status] {
			return fmt.Errorf("%w (found status %q)", ErrCycloneDXVocabulary, stmt.Status)
		}
		return fmt.Errorf("%w: %q", ErrInvalidStatus, stmt.Status)
	}
	if stmt.Justification != "" {
		if !validJustifications[stmt.Justification] {
			if cyclonedxJustifications[stmt.Justification] {
				return fmt.Errorf("%w (found justification %q)", ErrCycloneDXVocabulary, stmt.Justification)
			}
			return fmt.Errorf("%w: %q", ErrInvalidJustification, stmt.Justification)
		}
		if stmt.Status != openvex.StatusNotAffected {
			return ErrJustificationMisplaced
		}
	}
	if stmt.Status == openvex.StatusNotAffected && stmt.Justification == "" {
		return ErrJustificationMissing
	}
	if len(stmt.Products) == 0 {
		return ErrNoProducts
	}
	return nil
}
