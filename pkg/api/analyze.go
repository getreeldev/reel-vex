package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/getreeldev/reel-vex/pkg/customervex"
	"github.com/getreeldev/reel-vex/pkg/db"
	"github.com/getreeldev/reel-vex/pkg/openvex"
)

const (
	maxAnalyzeBodySize = 5 << 20 // 5MB — covers SBOM + optional customer_vex.
	maxSBOMComponents  = 50000
	maxSBOMVulns       = 10000
)

// analyzeRequest wraps the inputs accepted by /v1/analyze.
//
// At least one of SBOM or CustomerVEX is required. SBOM is a CycloneDX 1.4+
// document inlined as JSON; CustomerVEX is one or more OpenVEX 0.2.0
// documents. The native reel-vex flat format is not accepted as input
// anywhere in the API.
type analyzeRequest struct {
	SBOM        json.RawMessage   `json:"sbom,omitempty"`
	CustomerVEX []json.RawMessage `json:"customer_vex,omitempty"`
}

// handleAnalyze routes by input shape:
//   - sbom only          → annotated CycloneDX (vendor data only).
//   - customer_vex only  → merged OpenVEX 0.2.0 doc.
//   - both               → annotated CycloneDX with vendor + customer merged.
//
// Customer statements override vendor statements on (cve, base_id) collision.
// On customer-asserted CVEs the SBOM-annotation rollup considers only customer
// rows, even when vendor rows on the same CVE sit at a different base_id —
// this guards against the higher-priority vendor not_affected outranking a
// customer affected on a different identifier.
func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > maxAnalyzeBodySize {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large (max 5MB)")
		return
	}
	var req analyzeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAnalyzeBodySize)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	hasSBOM := len(req.SBOM) > 0 && string(req.SBOM) != "null"
	hasCustomerVEX := len(req.CustomerVEX) > 0
	if !hasSBOM && !hasCustomerVEX {
		writeError(w, http.StatusBadRequest, "at least one of sbom or customer_vex required")
		return
	}

	// 1. Parse customer VEX (if any). Validation + limit checks live in
	//    customervex.Parse. Map ErrTooMany* errors to 400; everything else
	//    is a 422 shape violation.
	var customerStmts []db.Statement
	if hasCustomerVEX {
		parsed, err := customervex.Parse(req.CustomerVEX, time.Now().UTC())
		if err != nil {
			status := http.StatusUnprocessableEntity
			if customervex.IsClientError(err) {
				status = http.StatusBadRequest
			}
			writeError(w, status, err.Error())
			return
		}
		customerStmts = parsed
	}

	// 2. Decode SBOM (if any) and extract its identifiers + CVE list.
	var sbom map[string]any
	var sbomComponentIDs []string
	var sbomCVEs []string
	if hasSBOM {
		if err := json.Unmarshal(req.SBOM, &sbom); err != nil {
			writeError(w, http.StatusBadRequest, "invalid sbom JSON")
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
		seen := make(map[string]bool)
		for _, ids := range components {
			for _, id := range ids {
				if !seen[id] {
					seen[id] = true
					sbomComponentIDs = append(sbomComponentIDs, id)
				}
			}
		}
		for _, id := range vulns {
			sbomCVEs = append(sbomCVEs, id)
		}
	}

	// 3. Build the query inputs for the vendor lookup — union of SBOM-derived
	//    and customer-derived (cves, base_ids). SBOM components run through
	//    the resolver so via_alias / via_cpe_prefix candidates surface.
	//    Customer base_ids are used directly: customer asserts on a specific
	//    identifier and we don't want resolver expansion to widen the claim.
	respBaseToReason, respBaseToInputs := s.expandProducts(sbomComponentIDs)
	queryBases := make(map[string]bool, len(respBaseToReason))
	for b := range respBaseToReason {
		queryBases[b] = true
	}
	queryCVEs := make(map[string]bool, len(sbomCVEs)+len(customerStmts))
	for _, c := range sbomCVEs {
		queryCVEs[c] = true
	}
	for _, c := range customerStmts {
		queryCVEs[c.CVE] = true
		queryBases[c.BaseID] = true
	}

	// 4. Query vendor data (skipped if either dimension is empty).
	var vendorStmts []db.Statement
	if len(queryCVEs) > 0 && len(queryBases) > 0 {
		cveSlice := make([]string, 0, len(queryCVEs))
		for c := range queryCVEs {
			cveSlice = append(cveSlice, c)
		}
		baseSlice := make([]string, 0, len(queryBases))
		for b := range queryBases {
			baseSlice = append(baseSlice, b)
		}
		var err error
		vendorStmts, err = s.db.QueryResolve(cveSlice, baseSlice, nil)
		if err != nil {
			slog.Error("analyze resolve failed", "error", err)
			writeError(w, http.StatusInternalServerError, "resolve failed")
			return
		}
	}

	// 5. Merge with customer-override semantics.
	merged, customerCVEs := customervex.Merge(vendorStmts, customerStmts)

	// 6. Extend the encoder maps with customer-row entries. customer.BaseID
	//    may collide with an SBOM-derived base; in that case the customer's
	//    match_reason wins (override). The customer's product_id is added
	//    to the input echo list so the OpenVEX encoder emits it verbatim.
	for _, c := range customerStmts {
		respBaseToReason[c.BaseID] = customervex.MatchReason
		alreadyEchoed := false
		for _, in := range respBaseToInputs[c.BaseID] {
			if in == c.ProductID {
				alreadyEchoed = true
				break
			}
		}
		if !alreadyEchoed {
			respBaseToInputs[c.BaseID] = append(respBaseToInputs[c.BaseID], c.ProductID)
		}
	}

	// 7. Output.
	w.Header().Set("Content-Type", "application/json")
	if hasSBOM {
		if len(merged) > 0 {
			annotateSBOM(sbom, merged, customerCVEs)
		}
		json.NewEncoder(w).Encode(sbom)
		return
	}
	// customer-vex-only: emit OpenVEX of the merged set. Empty merged set
	// can't happen in practice once parse succeeds (customer rows are
	// always in the merged set), but we 204 anyway to mirror /v1/resolve
	// and stay schema-valid.
	if len(merged) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	doc := openvex.Encode(merged, respBaseToInputs, respBaseToReason)
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		slog.Error("openvex encode failed", "error", err)
	}
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
//
// customerCVEs gates the override semantic: for any CVE the customer asserted
// on, vendor rows are excluded from the per-CVE rollup so the customer's
// claim wins absolutely — even when a higher-priority vendor not_affected
// sits at a different base_id for the same CVE.
func annotateSBOM(sbom map[string]any, stmts []db.Statement, customerCVEs map[string]bool) {
	type resolved struct {
		state         string
		justification string
		detail        string
	}
	byCVE := make(map[string]*resolved)

	for _, s := range stmts {
		// Override gate: on customer-asserted CVEs, drop vendor rows from
		// the rollup. Customer rows have SourceFormat="" (no upstream feed);
		// vendor rows always carry one of "csaf"/"oval".
		if customerCVEs[s.CVE] && s.SourceFormat != "" {
			continue
		}

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

		// Build detail string with all participating statements. Vendor rows
		// carry the vendor name; customer rows use the supplier they
		// self-disclosed (may be empty).
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
