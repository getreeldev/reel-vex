package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/getreeldev/reel-vex/pkg/db"
)

const (
	maxSBOMSize       = 5 << 20 // 5MB
	maxSBOMComponents = 50000
	maxSBOMVulns      = 10000
)

func (s *Server) handleSBOM(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > maxSBOMSize {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large (max 5MB)")
		return
	}

	var sbom map[string]any
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSBOMSize)).Decode(&sbom); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	components := extractComponents(sbom)
	vulns := extractVulnerabilities(sbom)

	if len(components) > maxSBOMComponents {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("too many components (max %d)", maxSBOMComponents))
		return
	}
	if len(vulns) > maxSBOMVulns {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("too many vulnerabilities (max %d)", maxSBOMVulns))
		return
	}

	// Nothing to resolve — return as-is.
	if len(components) == 0 || len(vulns) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sbom)
		return
	}

	// Collect component identifiers, then expand: PURLs get stripped of
	// version/qualifiers (so "log4j@1.2.17" matches "log4j"); CPEs get their
	// 5-part prefix added as an alternative candidate (RedHat contract).
	rawIDs := make([]string, 0, len(components))
	seen := make(map[string]struct{})
	for _, c := range components {
		for _, id := range c {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			rawIDs = append(rawIDs, id)
		}
	}
	baseToReason := expandProducts(rawIDs)
	products := make([]string, 0, len(baseToReason))
	for b := range baseToReason {
		products = append(products, b)
	}

	cveIDs := make([]string, 0, len(vulns))
	for _, id := range vulns {
		cveIDs = append(cveIDs, id)
	}

	stmts, err := s.db.QueryResolve(cveIDs, products)
	if err != nil {
		slog.Error("sbom resolve failed", "error", err)
		writeError(w, http.StatusInternalServerError, "resolve failed")
		return
	}

	if len(stmts) > 0 {
		annotateSBOM(sbom, stmts)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sbom)
}

// extractComponents returns a map of component index to product IDs (purls and cpes).
func extractComponents(sbom map[string]any) map[int][]string {
	result := make(map[int][]string)

	comps, ok := sbom["components"].([]any)
	if !ok {
		return result
	}

	for i, raw := range comps {
		comp, ok := raw.(map[string]any)
		if !ok {
			continue
		}

		var ids []string
		if purl, ok := comp["purl"].(string); ok && purl != "" {
			ids = append(ids, purl)
		}
		if cpe, ok := comp["cpe"].(string); ok && cpe != "" {
			ids = append(ids, cpe)
		}
		if len(ids) > 0 {
			result[i] = ids
		}
	}
	return result
}

// extractVulnerabilities returns a map of vulnerability index to CVE ID.
func extractVulnerabilities(sbom map[string]any) map[int]string {
	result := make(map[int]string)

	vulns, ok := sbom["vulnerabilities"].([]any)
	if !ok {
		return result
	}

	for i, raw := range vulns {
		vuln, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if id, ok := vuln["id"].(string); ok && id != "" {
			result[i] = id
		}
	}
	return result
}

// annotateSBOM adds VEX analysis to vulnerabilities in the SBOM.
func annotateSBOM(sbom map[string]any, stmts []db.Statement) {
	// Group statements by CVE, pick best status per CVE.
	type resolved struct {
		state         string
		justification string
		detail        string
	}
	byCVE := make(map[string]*resolved)

	for _, s := range stmts {
		r, exists := byCVE[s.CVE]
		if !exists {
			r = &resolved{}
			byCVE[s.CVE] = r
		}

		mappedState := mapStatusToCycloneDX(s.Status)
		if !exists || statusPriority(mappedState) > statusPriority(r.state) {
			r.state = mappedState
			r.justification = mapJustificationToCycloneDX(s.Justification)
		}

		// Build detail string with all vendor statements.
		entry := s.Vendor + ": " + s.Status
		if s.Justification != "" {
			entry += " (" + s.Justification + ")"
		}
		if r.detail != "" {
			r.detail += "; "
		}
		r.detail += entry
	}

	vulns, ok := sbom["vulnerabilities"].([]any)
	if !ok {
		return
	}

	for i, raw := range vulns {
		vuln, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		id, ok := vuln["id"].(string)
		if !ok {
			continue
		}
		r, exists := byCVE[id]
		if !exists {
			continue
		}

		analysis := map[string]any{
			"state":  r.state,
			"detail": r.detail,
		}
		if r.justification != "" {
			analysis["justification"] = r.justification
		}
		vuln["analysis"] = analysis
		vulns[i] = vuln
	}
}

// mapStatusToCycloneDX converts our DB status to CycloneDX analysis state.
func mapStatusToCycloneDX(status string) string {
	switch status {
	case "not_affected":
		return "not_affected"
	case "fixed":
		return "resolved"
	case "under_investigation":
		return "in_triage"
	case "affected":
		return "exploitable"
	default:
		return "in_triage"
	}
}

// mapJustificationToCycloneDX converts our DB justification to CycloneDX justification.
func mapJustificationToCycloneDX(justification string) string {
	switch justification {
	case "component_not_present":
		return "code_not_present"
	case "vulnerable_code_not_present":
		return "code_not_present"
	case "vulnerable_code_not_in_execute_path":
		return "code_not_reachable"
	case "inline_mitigations_already_exist":
		return "protected_by_mitigating_control"
	default:
		return ""
	}
}

// statusPriority returns a priority score for CycloneDX states.
// Higher = more actionable (better for the consumer).
func statusPriority(state string) int {
	switch state {
	case "not_affected":
		return 4
	case "resolved":
		return 3
	case "in_triage":
		return 2
	case "exploitable":
		return 1
	default:
		return 0
	}
}

