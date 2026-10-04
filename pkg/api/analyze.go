package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/getreeldev/reel-vex/pkg/csaf"
	"github.com/getreeldev/reel-vex/pkg/db"
	"github.com/getreeldev/reel-vex/pkg/openvex"
	"github.com/getreeldev/reel-vex/pkg/uservex"
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
	// StrictArch narrows vendor matching to the architectures the SBOM's
	// components name. Off by default, same reasoning as on /v1/statements.
	// User-supplied VEX is never narrowed — the user asserted on a specific
	// identifier and we don't second-guess it.
	StrictArch bool `json:"strict_arch,omitempty"`
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
			RejectLossy:   req.RejectCycloneDXLossy,
			MaxStatements: s.maxUserVEXStatements,
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
	var sources map[string]string
	if hasSBOM {
		if err := json.Unmarshal(req.SBOM, &sbom); err != nil {
			writeError(w, http.StatusBadRequest, "invalid sbom JSON")
			return
		}
		components := extractComponents(sbom)
		vulns := extractVulnerabilities(sbom)
		if len(components) > s.maxSBOMComponents {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("too many components (max %d)", s.maxSBOMComponents))
			return
		}
		if len(vulns) > s.maxSBOMVulns {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("too many vulnerabilities (max %d)", s.maxSBOMVulns))
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
		sources = extractSourcePackages(sbom)
	}

	// Scope context for product-scoped statements (Rancher VEX): the SBOM's
	// root subject (metadata.component — the scanned image/module). Passing it
	// authorises scoped statements for *this* product; without it they stay
	// withheld so they can't suppress findings for an unrelated image. nil for
	// the user-vex-only path (no SBOM, no product context). See db scope gate.
	scopes := extractRootScopes(sbom)

	// 3. Build the query inputs for the vendor lookup — union of SBOM-derived
	//    and user-derived (cves, base_ids). SBOM components run through
	//    the resolver so via_alias / via_cpe_prefix candidates surface, and
	//    a Debian component's source package adds via_source_package ones.
	//    User base_ids are used directly: user asserts on a specific
	//    identifier and we don't want resolver expansion to widen the claim.
	//    Architecture narrowing (opt-in) is derived from the SBOM's own
	//    components, which carry the arch qualifier the base form drops.
	var arches []string
	if req.StrictArch {
		arches = requestArches(sbomComponentIDs)
	}
	archAllow := archAllowList(arches)
	// Exact-list vendor rows are matched against each component's own
	// version. User base_ids carry no pair, so a vendor row reached only
	// through a user statement keeps its whole list — and so is not withheld
	// as a source package's (sourceBases) either.
	respBaseToReason, respBaseToInputs, exactVersions, sourceBases := s.expandProducts(sbomComponentIDs, sources)
	queryBases := make(map[string]bool, len(respBaseToReason))
	for b := range respBaseToReason {
		queryBases[b] = true
	}
	queryCVEs := make(map[string]bool, len(sbomCVEs)+len(userStmts))
	for _, c := range sbomCVEs {
		queryCVEs[c] = true
	}
	userBases := make(map[string]bool, len(userStmts))
	for _, c := range userStmts {
		queryCVEs[c.CVE] = true
		queryBases[c.BaseID] = true
		userBases[c.BaseID] = true
	}
	sourceBases = slices.DeleteFunc(sourceBases, func(b string) bool { return userBases[b] })

	// Bound the CVE-mode query breadth (see analyzeMaxCVEs) — a cheap up-front
	// reject before tying up a connection. The covering index (base_id, cve)
	// keeps the query base-bound; -query-timeout is the hard backstop below.
	if len(queryCVEs) > s.analyzeMaxCVEs {
		writeError(w, http.StatusBadRequest, fmt.Sprintf(
			"analyze input matches too many CVEs (%d > %d) — narrow the products/CVEs or split the document into smaller uploads",
			len(queryCVEs), s.analyzeMaxCVEs))
		return
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
		filters := db.QueryFilters{ProductBaseIDs: mapKeysSorted(queryBases), Scopes: scopes, ArchAllow: archAllow, ExactVersions: exactVersions, SourceBases: sourceBases}
		if s.statementsMax > 0 {
			filters.Limit = s.statementsMax + 1 // +1 to detect truncation
		}
		var err error
		vendorStmts, err = s.db.QueryStatements(filters)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				writeError(w, http.StatusServiceUnavailable, "query timed out — input too broad or server busy; narrow the products/CVEs or split the document")
				return
			}
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
			ArchAllow:      archAllow,
			ExactVersions:  exactVersions,
			SourceBases:    sourceBases,
		})
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				writeError(w, http.StatusServiceUnavailable, "query timed out — input too broad or server busy; narrow the products/CVEs or split the document")
				return
			}
			slog.Error("analyze query failed", "error", err)
			writeError(w, http.StatusInternalServerError, "query failed")
			return
		}
	}

	// Exact arch check on vendor rows only (see filterByArch). After the
	// broad-mode page trim above, so truncation still describes the query.
	vendorStmts = filterByArch(vendorStmts, arches)

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
	//     the FULL component identifier a statement is about (idMatch.admits) —
	//     not the resolver's base form (respBaseToInputs holds bases, which
	//     would not match a component's versioned purl in the BOM-Link rewrite).
	//     The non-empty path leaves the SBOM's own vulnerabilities[] untouched.
	match := s.sbomMatches(sbomComponentIDs, sources)
	if synthesize {
		userRefs := make(map[string][]string)
		for _, c := range userStmts {
			userRefs[c.BaseID] = append(userRefs[c.BaseID], c.ProductID)
		}
		synthesizeVulnerabilities(sbom, merged, match, userRefs)
	}

	// 7. Output.
	// Telemetry: query mode + result size ride response headers so the
	// fronting proxy's access log (the PostHog pipeline's source) can see
	// them — the proxy can't inspect request bodies, and the response body
	// stays untouched. Mirrors handleStatements.
	mode := "cve"
	if synthesize {
		mode = "broad"
	}
	w.Header().Set("X-Reel-Mode", mode)
	w.Header().Set("X-Reel-Statements", strconv.Itoa(len(merged)))
	if h := archHeader(arches); h != "" {
		w.Header().Set("X-Reel-Arch", h)
	}
	w.Header().Set("Content-Type", "application/json")
	if hasSBOM {
		if len(merged) > 0 {
			annotateSBOM(sbom, merged, userCVEs, match)
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
	w.Header().Set("X-Reel-Grouped", strconv.Itoa(len(doc.Statements)))
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

// The CycloneDX properties in which Trivy records the source package a binary
// package was built from. Trivy splits the source version as dpkg does:
// SrcVersion is the upstream version, SrcRelease the Debian revision (absent
// for a native package), and SrcEpoch is written only when non-zero.
const (
	propSrcName    = "aquasecurity:trivy:SrcName"
	propSrcVersion = "aquasecurity:trivy:SrcVersion"
	propSrcRelease = "aquasecurity:trivy:SrcRelease"
	propSrcEpoch   = "aquasecurity:trivy:SrcEpoch"
)

// debianPURLPrefix is the ecosystem whose vendor rows name source packages.
// Debian OVAL states every verdict per source package (zlib), while a scanner
// lists the binaries built from it (zlib1g). Ubuntu's feeds name binaries —
// the USN OVAL lists each binary package, and Canonical's OpenVEX lists
// binaries and sources as exact builds — so pkg:deb/ubuntu gets no source
// candidate.
const debianPURLPrefix = "pkg:deb/debian/"

// extractSourcePackages maps the purl of every Debian component built from a
// source package of another name to that source package's purl (sourcePURL).
func extractSourcePackages(sbom map[string]any) map[string]string {
	out := make(map[string]string)
	comps, _ := sbom["components"].([]any)
	for _, raw := range comps {
		comp, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		purl, _ := comp["purl"].(string)
		if _, seen := out[purl]; seen {
			continue
		}
		if src := sourcePURL(purl, componentProperties(comp)); src != "" {
			out[purl] = src
		}
	}
	return out
}

// componentProperties returns a CycloneDX component's properties by name.
func componentProperties(comp map[string]any) map[string]string {
	props, _ := comp["properties"].([]any)
	out := make(map[string]string, len(props))
	for _, raw := range props {
		p, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name, _ := p["name"].(string)
		value, _ := p["value"].(string)
		if name != "" {
			out[name] = value
		}
	}
	return out
}

// sourcePURL returns the purl of the source package a Debian binary package
// was built from, as the vendor rows name it — pkg:deb/debian/<SrcName> with
// the binary's distro qualifier as written, and the source version
// [SrcVersion-SrcRelease] with a non-zero SrcEpoch as the epoch qualifier. The
// version is carried for matching against the fixed-in boundaries Debian
// states per source package, which the next phase (boundary feeds) compares;
// nothing compares it today, because a source candidate is paired with no
// version and never admits an exact-list row:
//
//	pkg:deb/debian/zlib1g@1.2.13.dfsg-1?arch=amd64&distro=debian-12.15&epoch=1
//	  SrcName zlib, SrcVersion 1.2.13.dfsg, SrcRelease 1, SrcEpoch 1
//	→ pkg:deb/debian/zlib@1.2.13.dfsg-1?distro=debian-12.15&epoch=1
//
// "" when the component is not a Debian package, names no source package, or
// names its own: a binary called like its source is already looked up as
// itself.
func sourcePURL(purl string, props map[string]string) string {
	src := props[propSrcName]
	if src == "" || !strings.HasPrefix(purl, debianPURLPrefix) {
		return ""
	}
	versionless, _ := csaf.StripPURLVersion(purl)
	name := versionless[len(debianPURLPrefix):]
	if i := strings.IndexAny(name, "?#"); i >= 0 {
		name = name[:i]
	}
	if csaf.UnescapeVersion(name) == src {
		return ""
	}
	out := debianPURLPrefix + src
	if v := props[propSrcVersion]; v != "" {
		if r := props[propSrcRelease]; r != "" {
			v += "-" + r
		}
		out += "@" + v
	}
	var quals []string
	if d := purlQualifier(purl, "distro"); d != "" {
		quals = append(quals, "distro="+d)
	}
	if e := props[propSrcEpoch]; strings.Trim(e, "0") != "" {
		quals = append(quals, "epoch="+e)
	}
	if len(quals) > 0 {
		out += "?" + strings.Join(quals, "&")
	}
	return out
}

// purlQualifier returns a PURL qualifier's value as written (not decoded), or
// "" when the identifier does not carry it.
func purlQualifier(purl, key string) string {
	q := strings.IndexByte(purl, '?')
	if q < 0 {
		return ""
	}
	qualifiers := purl[q+1:]
	if i := strings.IndexByte(qualifiers, '#'); i >= 0 {
		qualifiers = qualifiers[:i]
	}
	for _, kv := range strings.Split(qualifiers, "&") {
		if v, ok := strings.CutPrefix(kv, key+"="); ok {
			return v
		}
	}
	return ""
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
// A vulnerability that names its components (affects[].ref, a bom-ref, a purl
// or a BOM-Link, as Trivy writes them) is judged per component: a row counts
// for a component only when it is a statement about it (idMatch.admits — an
// exact-list row only at a listed version, and never through a source
// package), each component's verdict is the rollup of its own rows, and the
// vulnerability is annotated only when every component it names has a verdict
// and they agree. One analysis applies to every component of the entry, so a
// verdict stated for one version or one package must not be read as the
// other's: when they disagree, or one has none, the entry is left as it came.
// A vulnerability that names no component the SBOM holds has nothing to
// attribute rows to, and gets the rollup of every row of its CVE.
//
// userCVEs gates the override semantic: for any CVE the user asserted
// on, vendor rows are excluded and the user's rows are rolled up for the whole
// CVE, so the user's claim wins absolutely — even when a higher-priority
// vendor not_affected sits at a different base_id for the same CVE.
func annotateSBOM(sbom map[string]any, stmts []db.Statement, userCVEs map[string]bool, match sbomMatch) {
	byCVE := make(map[string][]db.Statement)
	for _, s := range stmts {
		// Override gate: on user-asserted CVEs, drop vendor rows from
		// the rollup. User rows have SourceFormat="" (no upstream feed);
		// vendor rows always carry one (csaf, oval, openvex, secdb,
		// updateinfo).
		if userCVEs[s.CVE] && s.SourceFormat != "" {
			continue
		}
		byCVE[s.CVE] = append(byCVE[s.CVE], s)
	}

	vulns, ok := sbom["vulnerabilities"].([]any)
	if !ok {
		return
	}
	refs := componentRefs(sbom)

	for i, raw := range vulns {
		vuln, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		id, ok := vuln["id"].(string)
		if !ok {
			continue
		}
		rows := byCVE[id]
		if len(rows) == 0 {
			continue
		}
		var r verdict
		if comps := affectedComponents(vuln, refs); userCVEs[id] || len(comps) == 0 {
			r = rollup(rows)
		} else if r, ok = agreedVerdict(rows, comps, match); !ok {
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

// verdict is a CycloneDX analysis: its state and justification, and a detail
// naming every statement that took part.
type verdict struct {
	state         string
	justification string
	detail        string
}

// rollup folds rows into one verdict: the highest-priority state
// (statusPriority) with the justification of the first row that stated it,
// and every row in the detail.
func rollup(rows []db.Statement) verdict {
	var r verdict
	for i, s := range rows {
		mappedState := mapStatusToCycloneDX(s.Status)
		if i == 0 || statusPriority(mappedState) > statusPriority(r.state) {
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
	return r
}

// agreedVerdict is the verdict that holds for every component of a
// vulnerability: each component (its identifiers) gets the rollup of the rows
// about it, and the components must agree on the state. The justification is
// kept only when they agree on it too; the detail names every row that applied
// to any of them. false when a component has no row, or the states differ.
func agreedVerdict(rows []db.Statement, comps [][]string, match sbomMatch) (verdict, bool) {
	var out verdict
	used := make([]bool, len(rows))
	for n, ids := range comps {
		var own []db.Statement
		for i, s := range rows {
			if match.admits(ids, s) {
				own = append(own, s)
				used[i] = true
			}
		}
		if len(own) == 0 {
			return verdict{}, false
		}
		r := rollup(own)
		switch {
		case n == 0:
			out = r
		case r.state != out.state:
			return verdict{}, false
		case r.justification != out.justification:
			out.justification = ""
		}
	}
	var applied []db.Statement
	for i, s := range rows {
		if used[i] {
			applied = append(applied, s)
		}
	}
	out.detail = rollup(applied).detail
	return out, true
}

// componentRefs maps every name an affects[].ref may use for a component —
// its bom-ref, purl and cpe — to the component's identifiers.
func componentRefs(sbom map[string]any) map[string][]string {
	out := make(map[string][]string)
	comps, _ := sbom["components"].([]any)
	for _, raw := range comps {
		comp, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		var ids []string
		for _, k := range []string{"purl", "cpe"} {
			if v, _ := comp[k].(string); v != "" {
				ids = append(ids, v)
			}
		}
		if len(ids) == 0 {
			continue
		}
		bomRef, _ := comp["bom-ref"].(string)
		for _, name := range append([]string{bomRef}, ids...) {
			if _, seen := out[name]; name != "" && !seen {
				out[name] = ids
			}
		}
	}
	return out
}

// affectedComponents returns the identifiers of each SBOM component a
// vulnerability's affects[] names, once per component. A ref may be a bare
// bom-ref, a purl, or a BOM-Link (urn:cdx:<serial>/<version>#<bom-ref>); a ref
// naming no component the SBOM holds is skipped.
func affectedComponents(vuln map[string]any, refs map[string][]string) [][]string {
	affects, _ := vuln["affects"].([]any)
	var out [][]string
	seen := make(map[string]bool)
	for _, a := range affects {
		var ref string
		switch v := a.(type) {
		case map[string]any:
			ref, _ = v["ref"].(string)
		case string:
			ref = v
		}
		if strings.HasPrefix(ref, "urn:cdx:") {
			if _, frag, ok := strings.Cut(ref, "#"); ok {
				if u, err := url.PathUnescape(frag); err == nil {
					frag = u
				}
				ref = frag
			}
		}
		ids, ok := refs[ref]
		if !ok || seen[ids[0]] {
			continue
		}
		seen[ids[0]] = true
		out = append(out, ids)
	}
	return out
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
// Each affects[].ref is the full component identifier (PURL/CPE) a statement is
// about (sbomMatch.refs), so rewriteAffectsAsBOMLinks can bind it to the
// component's bom-ref; a user statement also names its own product
// (userRefs, by base). Entries and refs are sorted for deterministic output.
// Statements about no component are skipped (nothing to attribute).
func synthesizeVulnerabilities(sbom map[string]any, stmts []db.Statement, match sbomMatch, userRefs map[string][]string) {
	refsByCVE := make(map[string]map[string]bool)
	for _, s := range stmts {
		comps := match.refs(s)
		if s.SourceFormat == "" {
			comps = append(comps, userRefs[s.BaseID]...)
		}
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

// idMatch is one SBOM identifier (a component's purl or cpe) as /v1/analyze
// attributes vendor rows to it.
type idMatch struct {
	id      string
	version string          // csaf.MatchVersion(id); empty for none
	bases   map[string]bool // the resolver's candidates for the identifier
	source  map[string]bool // candidates reached only through its source package
}

// admits reports whether row s is a statement about this identifier. The
// store's exact-list filter pools every version an SBOM names for one base,
// so a row it returns may hold another component's version: an exact-list row
// with a list is about this identifier only when the identifier names no
// version or one in the list. A row reached through the source package never
// is when it is an exact list, which names the vendor's builds of the package
// itself (db.QueryFilters.SourceBases).
func (m *idMatch) admits(s db.Statement) bool {
	if m.bases[s.BaseID] {
		return s.VersionKind != db.VersionKindExact || len(s.Versions) == 0 || m.version == "" || slices.Contains(s.Versions, m.version)
	}
	return m.source[s.BaseID] && s.VersionKind != db.VersionKindExact
}

// sbomMatch is every SBOM identifier's idMatch, by identifier and by each base
// it reaches.
type sbomMatch struct {
	byID   map[string]*idMatch
	byBase map[string][]*idMatch
}

// sbomMatches builds the idMatch of each identifier; sources maps a component
// purl to its source package's purl (extractSourcePackages).
func (s *Server) sbomMatches(ids []string, sources map[string]string) sbomMatch {
	out := sbomMatch{byID: make(map[string]*idMatch, len(ids)), byBase: make(map[string][]*idMatch)}
	for _, id := range ids {
		if out.byID[id] != nil {
			continue
		}
		m := &idMatch{id: id, version: csaf.MatchVersion(id), bases: make(map[string]bool), source: make(map[string]bool)}
		for _, cand := range s.resolver.Expand(id) {
			m.bases[cand.ID] = true
			out.byBase[cand.ID] = append(out.byBase[cand.ID], m)
		}
		if src := sources[id]; src != "" {
			for _, cand := range s.resolver.Expand(src) {
				if !m.bases[cand.ID] && !m.source[cand.ID] {
					m.source[cand.ID] = true
					out.byBase[cand.ID] = append(out.byBase[cand.ID], m)
				}
			}
		}
		out.byID[id] = m
	}
	return out
}

// refs returns the identifiers row s is a statement about.
func (sm sbomMatch) refs(s db.Statement) []string {
	var out []string
	for _, m := range sm.byBase[s.BaseID] {
		if m.admits(s) {
			out = append(out, m.id)
		}
	}
	return out
}

// admits reports whether row s is a statement about any of one component's
// identifiers.
func (sm sbomMatch) admits(ids []string, s db.Statement) bool {
	for _, id := range ids {
		if m := sm.byID[id]; m != nil && m.admits(s) {
			return true
		}
	}
	return false
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
