package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/getreeldev/reel-vex/pkg/csaf"
	"github.com/getreeldev/reel-vex/pkg/db"
	"github.com/getreeldev/reel-vex/pkg/openvex"
	"github.com/getreeldev/reel-vex/pkg/uservex"
)

const (
	maxSBOMComponents = 50000
	maxSBOMVulns      = 10000
)

// analyzeRequest wraps the inputs accepted by /v1/analyze.
//
// At least one of SBOM or UserVEX is required. SBOM is a CycloneDX 1.4+
// document inlined as JSON; UserVEX is one or more OpenVEX 0.2.0
// documents. The native reel-vex flat format is not accepted as input
// anywhere in the API.
type analyzeRequest struct {
	SBOM    json.RawMessage   `json:"sbom,omitempty"`
	UserVEX []json.RawMessage `json:"user_vex,omitempty"`
	// RejectCycloneDXLossy makes inbound VEX normalisation strict: CycloneDX
	// values with no exact OpenVEX equivalent are dropped instead of mapped to
	// the nearest bucket. Default false = normalise everything (lossy mappings
	// are flagged in the result's status_notes).
	RejectCycloneDXLossy bool `json:"reject_cyclonedx_lossy,omitempty"`
}

// handleAnalyze routes by input shape:
//   - sbom only          → annotated CycloneDX (vendor data only).
//   - user_vex only  → merged OpenVEX 0.2.0 doc.
//   - both               → annotated CycloneDX with vendor + user merged.
//
// User statements override vendor statements on (cve, base_id) collision.
// On user-asserted CVEs the SBOM-annotation rollup considers only user
// rows, even when vendor rows on the same CVE sit at a different base_id —
// this guards against the higher-priority vendor not_affected outranking a
// user affected on a different identifier.
func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > s.sbomMaxBytes {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("request body too large (max %dMB)", s.sbomMaxBytes>>20))
		return
	}
	var req analyzeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, s.sbomMaxBytes)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	hasSBOM := len(req.SBOM) > 0 && string(req.SBOM) != "null"
	hasUserVEX := len(req.UserVEX) > 0
	if !hasSBOM && !hasUserVEX {
		writeError(w, http.StatusBadRequest, "at least one of sbom or user_vex required")
		return
	}

	// 1. Parse user VEX (if any). Validation + limit checks live in
	//    uservex.Parse. Map ErrTooMany* errors to 400; everything else
	//    is a 422 shape violation.
	var userStmts []db.Statement
	if hasUserVEX {
		parsed, info, err := uservex.Parse(req.UserVEX, time.Now().UTC(), uservex.Options{
			RejectLossy: req.RejectCycloneDXLossy,
		})
		if err != nil {
			status := http.StatusUnprocessableEntity
			if uservex.IsClientError(err) {
				status = http.StatusBadRequest
			}
			writeError(w, status, err.Error())
			return
		}
		userStmts = parsed
		// Surface inbound CycloneDX->OpenVEX normalisation so it's never silent
		// (counts only — user VEX content is never logged or echoed elsewhere).
		if info.Converted > 0 || info.Skipped > 0 {
			w.Header().Set("X-Reel-Converted", fmt.Sprintf("converted=%d; lossy=%d; contested=%d; skipped=%d",
				info.Converted, info.Lossy, info.Contested, info.Skipped))
		}
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

	// Scope context for product-scoped statements (Rancher VEX): the SBOM's
	// root subject (metadata.component — the scanned image/module). Passing it
	// authorises scoped statements for *this* product; without it they stay
	// withheld so they can't suppress findings for an unrelated image. nil for
	// the user-vex-only path (no SBOM, no product context). See db scope gate.
	scopes := extractRootScopes(sbom)

	// 3. Build the query inputs for the vendor lookup — union of SBOM-derived
	//    and user-derived (cves, base_ids). SBOM components run through
	//    the resolver so via_alias / via_cpe_prefix candidates surface.
	//    User base_ids are used directly: user asserts on a specific
	//    identifier and we don't want resolver expansion to widen the claim.
	respBaseToReason, respBaseToInputs := s.expandProducts(sbomComponentIDs)
	queryBases := make(map[string]bool, len(respBaseToReason))
	for b := range respBaseToReason {
		queryBases[b] = true
	}
	queryCVEs := make(map[string]bool, len(sbomCVEs)+len(userStmts))
	for _, c := range sbomCVEs {
		queryCVEs[c] = true
	}
	for _, c := range userStmts {
		queryCVEs[c.CVE] = true
		queryBases[c.BaseID] = true
	}

	// 4. Query vendor data. Two shapes, mirroring the scanner combos reel needs:
	//   - empty-vulns SBOM (components only): BROAD MODE — query every CVE
	//     touching the components, no CVE filter, then synthesise
	//     vulnerabilities[] from the result (step 6b). Capped by -statements-max.
	//   - non-empty-vulns SBOM (or user CVEs): query input CVEs × bases as
	//     before and only annotate existing entries; never add broad-mode CVEs
	//     on top. Rule: empty-in → populate; non-empty-in → annotate only.
	synthesize := hasSBOM && len(sbomCVEs) == 0
	var vendorStmts []db.Statement
	var truncated bool
	switch {
	case synthesize && len(queryBases) > 0:
		filters := db.QueryFilters{ProductBaseIDs: mapKeysSorted(queryBases), Scopes: scopes}
		if s.statementsMax > 0 {
			filters.Limit = s.statementsMax + 1 // +1 to detect truncation
		}
		var err error
		vendorStmts, err = s.db.QueryStatements(filters)
		if err != nil {
			slog.Error("analyze broad-mode query failed", "error", err)
			writeError(w, http.StatusInternalServerError, "query failed")
			return
		}
		if s.statementsMax > 0 && len(vendorStmts) > s.statementsMax {
			vendorStmts = vendorStmts[:s.statementsMax]
			truncated = true
		}
	case len(queryCVEs) > 0 && len(queryBases) > 0:
		var err error
		vendorStmts, err = s.db.QueryStatements(db.QueryFilters{
			CVEs:           mapKeysSorted(queryCVEs),
			ProductBaseIDs: mapKeysSorted(queryBases),
			Scopes:         scopes,
		})
		if err != nil {
			slog.Error("analyze query failed", "error", err)
			writeError(w, http.StatusInternalServerError, "query failed")
			return
		}
	}

	// 5. Merge with user-override semantics.
	merged, userCVEs := uservex.Merge(vendorStmts, userStmts)

	// 6. Extend the encoder maps with user-row entries. user.BaseID
	//    may collide with an SBOM-derived base; in that case the user's
	//    match_reason wins (override). The user's product_id is added
	//    to the input echo list so the OpenVEX encoder emits it verbatim.
	for _, c := range userStmts {
		respBaseToReason[c.BaseID] = uservex.MatchReason
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

	// 6b. Empty-vulns path: synthesise vulnerabilities[] from the merged set so
	//     annotateSBOM (below) populates analysis on them. Each affects[].ref is
	//     the FULL component identifier that resolved to the statement's base_id
	//     — not the resolver's base form (respBaseToInputs holds bases, which
	//     would not match a component's versioned purl in the BOM-Link rewrite).
	//     The non-empty path leaves the SBOM's own vulnerabilities[] untouched.
	if synthesize {
		baseToComponents := make(map[string][]string)
		seen := make(map[string]map[string]bool)
		addComp := func(base, full string) {
			if seen[base] == nil {
				seen[base] = make(map[string]bool)
			}
			if !seen[base][full] {
				seen[base][full] = true
				baseToComponents[base] = append(baseToComponents[base], full)
			}
		}
		for _, cid := range sbomComponentIDs {
			for _, cand := range s.resolver.Expand(cid) {
				addComp(cand.ID, cid)
			}
		}
		for _, c := range userStmts {
			addComp(c.BaseID, c.ProductID)
		}
		synthesizeVulnerabilities(sbom, merged, baseToComponents)
	}

	// 7. Output.
	w.Header().Set("Content-Type", "application/json")
	if hasSBOM {
		if len(merged) > 0 {
			annotateSBOM(sbom, merged, userCVEs)
		}
		// Rewrite affects[].ref to BOM-Link form regardless of whether vendor
		// data matched, so the response stays consumable by Trivy --vex even
		// when no statements were emitted.
		rewriteAffectsAsBOMLinks(sbom)
		if truncated {
			// Broad-mode synthesis hit the -statements-max cap; some CVEs were
			// dropped. Signal it out-of-band (header, 200) — never silently
			// truncate, and never an unsolicited 206 (see handleStatements).
			w.Header().Set("X-Reel-Truncated", "true")
		}
		json.NewEncoder(w).Encode(sbom)
		return
	}
	// user-vex-only: emit OpenVEX of the merged set. Empty merged set
	// can't happen in practice once parse succeeds (user rows are
	// always in the merged set), but we 204 anyway to mirror /v1/statements
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

// extractRootScopes returns the normalized scope identifiers for the SBOM's
// root subject — metadata.component's purl and/or cpe (the image/module being
// scanned). These authorise product-scoped vendor statements (Rancher VEX)
// whose scope matches; without them such statements are withheld. Returns nil
// when the SBOM has no metadata.component identifier. Normalised via
// csaf.NormalizeScope so the value matches the scope stored at ingest.
func extractRootScopes(sbom map[string]any) []string {
	meta, ok := sbom["metadata"].(map[string]any)
	if !ok {
		return nil
	}
	comp, ok := meta["component"].(map[string]any)
	if !ok {
		return nil
	}
	var out []string
	if purl, ok := comp["purl"].(string); ok && purl != "" {
		out = append(out, csaf.NormalizeScope(purl))
	}
	if cpe, ok := comp["cpe"].(string); ok && cpe != "" {
		out = append(out, csaf.NormalizeScope(cpe))
	}
	return out
}

// annotateSBOM adds VEX analysis to vulnerabilities in the SBOM.
//
// userCVEs gates the override semantic: for any CVE the user asserted
// on, vendor rows are excluded from the per-CVE rollup so the user's
// claim wins absolutely — even when a higher-priority vendor not_affected
// sits at a different base_id for the same CVE.
func annotateSBOM(sbom map[string]any, stmts []db.Statement, userCVEs map[string]bool) {
	type resolved struct {
		state         string
		justification string
		detail        string
	}
	byCVE := make(map[string]*resolved)

	for _, s := range stmts {
		// Override gate: on user-asserted CVEs, drop vendor rows from
		// the rollup. User rows have SourceFormat="" (no upstream feed);
		// vendor rows always carry one of "csaf"/"oval".
		if userCVEs[s.CVE] && s.SourceFormat != "" {
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
		// carry the vendor name; user rows use the supplier they
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

// rewriteAffectsAsBOMLinks rewrites each vulnerability's affects[].ref from
// raw PURL to a CycloneDX BOM-Link so consumers (Trivy --vex) can bind the
// VEX statement back to a scan finding via bom-ref. Format per CycloneDX 1.5:
//
//	urn:cdx:<serial-number>/<version>#<bom-ref>
//
// Best-effort: if the SBOM is missing serialNumber, or a component lacks a
// bom-ref, or an affects entry's ref doesn't match any component, the
// original .ref is preserved. The downstream tool then falls back to its
// own behaviour for that row (Trivy logs a parse warning); no other VEX
// statement in the document is affected.
func rewriteAffectsAsBOMLinks(sbom map[string]any) {
	serial, _ := sbom["serialNumber"].(string)
	if serial == "" {
		return
	}
	// CycloneDX BOM-Link spec uses the bare serial number without the URN
	// scheme prefix. Trivy SBOMs emit `urn:uuid:<uuid>` so strip that.
	serial = strings.TrimPrefix(serial, "urn:uuid:")

	version := 1
	if v, ok := sbom["version"].(float64); ok && v > 0 {
		version = int(v)
	}

	purlToBomRef := make(map[string]string)
	if comps, ok := sbom["components"].([]any); ok {
		for _, raw := range comps {
			comp, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			bomRef, _ := comp["bom-ref"].(string)
			purl, _ := comp["purl"].(string)
			if bomRef != "" && purl != "" {
				purlToBomRef[purl] = bomRef
			}
		}
	}

	vulns, ok := sbom["vulnerabilities"].([]any)
	if !ok {
		return
	}
	for _, raw := range vulns {
		vuln, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		affects, ok := vuln["affects"].([]any)
		if !ok {
			continue
		}
		for j, a := range affects {
			// CycloneDX allows affects[] entries to be objects {ref, versions[...]}
			// (Trivy emission) or plain strings (some hand-rolled SBOMs).
			switch ref := a.(type) {
			case map[string]any:
				purl, _ := ref["ref"].(string)
				if bomRef, ok := purlToBomRef[purl]; ok {
					ref["ref"] = fmt.Sprintf("urn:cdx:%s/%d#%s", serial, version, bomRef)
					affects[j] = ref
				}
			case string:
				if bomRef, ok := purlToBomRef[ref]; ok {
					affects[j] = fmt.Sprintf("urn:cdx:%s/%d#%s", serial, version, bomRef)
				}
			}
		}
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

// synthesizeVulnerabilities populates sbom["vulnerabilities"] with one entry per
// CVE in stmts — used on the empty-vulns /v1/analyze path so the downstream
// annotate + BOM-Link steps run exactly as they do for a Trivy-populated SBOM.
// Each affects[].ref is the full component identifier (PURL/CPE) that resolved
// to the statement's base_id, so rewriteAffectsAsBOMLinks can bind it to the
// component's bom-ref. Entries and refs are sorted for deterministic output.
// Statements whose base maps to no component are skipped (nothing to attribute).
func synthesizeVulnerabilities(sbom map[string]any, stmts []db.Statement, baseToComponents map[string][]string) {
	refsByCVE := make(map[string]map[string]bool)
	for _, s := range stmts {
		comps := baseToComponents[s.BaseID]
		if len(comps) == 0 {
			continue
		}
		refs := refsByCVE[s.CVE]
		if refs == nil {
			refs = make(map[string]bool)
			refsByCVE[s.CVE] = refs
		}
		for _, c := range comps {
			refs[c] = true
		}
	}
	if len(refsByCVE) == 0 {
		return
	}

	cves := make([]string, 0, len(refsByCVE))
	for c := range refsByCVE {
		cves = append(cves, c)
	}
	sort.Strings(cves)

	vulns := make([]any, 0, len(cves))
	for _, cve := range cves {
		affects := make([]any, 0, len(refsByCVE[cve]))
		for _, ref := range mapKeysSorted(refsByCVE[cve]) {
			affects = append(affects, map[string]any{"ref": ref})
		}
		vulns = append(vulns, map[string]any{
			"id":      cve,
			"affects": affects,
		})
	}
	sbom["vulnerabilities"] = vulns
}

// mapKeysSorted returns a set's keys in sorted order — deterministic query args
// and output.
func mapKeysSorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
