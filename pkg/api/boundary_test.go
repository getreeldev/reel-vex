package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/getreeldev/reel-vex/pkg/db"
	"github.com/getreeldev/reel-vex/pkg/db/dbtest"
)

// Boundary rows: a fixed-in version answers a versioned query only at or
// above it, under the identifier the caller sent.

const boundaryCVE = "CVE-2022-37434"

func boundaryServer(t *testing.T) *Server {
	t.Helper()
	store := dbtest.New()
	t.Cleanup(func() { store.Close() })
	row := func(vendor, base, status, version, format string) db.Statement {
		s := db.Statement{Vendor: vendor, CVE: boundaryCVE, ProductID: base, BaseID: base, IDType: "purl", Status: status,
			Updated: "2026-10-03T00:00:00Z", SourceFormat: format}
		if version != "" {
			s.Versions = []string{version}
			s.VersionKind = db.VersionKindBoundary
		}
		return s
	}
	if err := store.BulkInsert([]db.Statement{
		row("debian", "pkg:deb/debian/zlib?distro=debian-12", "fixed", "1:1.2.11.dfsg-4.1", "oval"),
		row("debian", "pkg:deb/debian/389-ds-base?distro=debian-12", "affected", "", "oval"),
		row("oracle", "pkg:rpm/oracle/sudo?distro=oracle-8", "fixed", "0:1.9.5p2-1.el8_9", "oval"),
	}); err != nil {
		t.Fatal(err)
	}
	return NewServer(store, nil)
}

func TestBoundary_Statements(t *testing.T) {
	srv := boundaryServer(t)
	const (
		zlibBelow = "pkg:deb/debian/zlib@1:1.2.11.dfsg-2?arch=source&distro=debian-12"
		zlibAt    = "pkg:deb/debian/zlib@1:1.2.11.dfsg-4.1?arch=source&distro=debian-12"
		zlibAbove = "pkg:deb/debian/zlib@1.2.13.dfsg-1?arch=source&distro=debian-12.11&epoch=1"
		zlibNoEp  = "pkg:deb/debian/zlib@1.2.13.dfsg-1?arch=source&distro=debian-12"
		zlibBare  = "pkg:deb/debian/zlib?distro=debian-12"
		sudoAt    = "pkg:rpm/oracle/sudo@1.9.5p2-1.el8_9?arch=x86_64&distro=oracle-8.10"
		sudoBelow = "pkg:rpm/oracle/sudo@1.9.5p2-1.el8_8?arch=x86_64&distro=oracle-8"
		ds389     = "pkg:deb/debian/389-ds-base@2.3.1+dfsg1-1+deb12u1?arch=amd64&distro=debian-12"
	)
	fixed := func(vendor string, ids ...string) string { return boundaryLine(vendor, "fixed", ids...) }
	cases := []struct {
		name     string
		req      statementsRequest
		rows     int
		want     []string
		wantNote string
	}{
		{"below the fixed-in version: nothing", statementsRequest{CVEs: []string{boundaryCVE}, Products: []string{zlibBelow}}, 0, nil, ""},
		{"at it: fixed, under the identifier as sent", statementsRequest{CVEs: []string{boundaryCVE}, Products: []string{zlibAt}}, 1,
			[]string{fixed("debian", zlibAt)}, "match_reason=direct"},
		{"above it, epoch as a qualifier", statementsRequest{CVEs: []string{boundaryCVE}, Products: []string{zlibAbove}}, 1,
			[]string{fixed("debian", zlibAbove)}, ""},
		{"no epoch is epoch 0, below 1:", statementsRequest{CVEs: []string{boundaryCVE}, Products: []string{zlibNoEp}}, 0, nil, ""},
		{"no version: the base form, as before", statementsRequest{CVEs: []string{boundaryCVE}, Products: []string{zlibBare}}, 1,
			[]string{fixed("debian", zlibBare)}, ""},
		{"one product below and one above: only the one above is named", statementsRequest{CVEs: []string{boundaryCVE}, Products: []string{zlibBelow, zlibAbove}}, 1,
			[]string{fixed("debian", zlibAbove)}, ""},
		{"one below and one with no version: only the versionless one is named", statementsRequest{CVEs: []string{boundaryCVE}, Products: []string{zlibBelow, zlibBare}}, 1,
			[]string{fixed("debian", zlibBare)}, ""},
		{"rpm at the boundary", statementsRequest{CVEs: []string{boundaryCVE}, Products: []string{sudoAt}}, 1,
			[]string{fixed("oracle", sudoAt)}, ""},
		{"rpm below", statementsRequest{CVEs: []string{boundaryCVE}, Products: []string{sudoBelow}}, 0, nil, ""},
		{"a verdict with no version is unchanged", statementsRequest{CVEs: []string{boundaryCVE}, Products: []string{ds389}}, 1,
			[]string{boundaryLine("debian", "affected", "pkg:deb/debian/389-ds-base?distro=debian-12")}, ""},
		{"broad mode counts only the rows kept", statementsRequest{Products: []string{zlibBelow, sudoAt}}, 1,
			[]string{fixed("oracle", sudoAt)}, ""},
		{"CVE only: the vendor's identifier, as before", statementsRequest{CVEs: []string{boundaryCVE}, Vendors: []string{"debian"}, Statuses: []string{"fixed"}}, 1,
			[]string{fixed("debian", "pkg:deb/debian/zlib?distro=debian-12")}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w, got := postExact(t, srv, c.req)
			if h := w.Header().Get("X-Reel-Statements"); h != strconv.Itoa(c.rows) {
				t.Errorf("X-Reel-Statements = %s, want %d", h, c.rows)
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
			if body := rawStatements(srv, c.req); c.wantNote != "" && !strings.Contains(body, c.wantNote) {
				t.Errorf("body has no %q: %s", c.wantNote, body)
			}
		})
	}
}

// rawStatements is the body /v1/statements answers req with (postExact
// decodes it, which consumes it).
func rawStatements(srv *Server, req statementsRequest) string {
	body, _ := json.Marshal(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest("POST", "/v1/statements", bytes.NewReader(body)))
	return w.Body.String()
}

// boundaryLine is renderDoc's line for one statement of boundaryCVE.
func boundaryLine(vendor, status string, ids ...string) string {
	return boundaryCVE + " " + vendor + " " + status + " " + strings.Join(ids, " ")
}

// TestBoundary_SourcePackage: a Debian binary answered through its source
// package is compared by the source version, and named as sent; /v1/analyze
// attributes the row only to the component whose source version reaches it.
func TestBoundary_SourcePackage(t *testing.T) {
	srv := boundaryServer(t)
	const (
		zlib1g  = "pkg:deb/debian/zlib1g@1.2.13.dfsg-1?arch=amd64&distro=debian-12.15&epoch=1"
		zlibOld = "pkg:deb/debian/zlib1g-dev@1.2.11.dfsg-2?arch=amd64&distro=debian-12.15&epoch=1"
	)
	comp := func(purl, ref, version, release string) map[string]any {
		return map[string]any{"type": "library", "purl": purl, "bom-ref": ref, "properties": []any{
			map[string]any{"name": propSrcName, "value": "zlib"},
			map[string]any{"name": propSrcVersion, "value": version},
			map[string]any{"name": propSrcRelease, "value": release},
			map[string]any{"name": propSrcEpoch, "value": "1"},
		}}
	}
	sbom := func(vulns []any, comps ...map[string]any) map[string]any {
		cs := []any{}
		for _, c := range comps {
			cs = append(cs, c)
		}
		out := map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": "urn:uuid:1", "components": cs}
		if vulns != nil {
			out["vulnerabilities"] = vulns
		}
		return out
	}
	newer, older := comp(zlib1g, "a", "1.2.13.dfsg", "1"), comp(zlibOld, "b", "1.2.11.dfsg", "2")

	t.Run("statements: below the source boundary, nothing", func(t *testing.T) {
		raw, _ := json.Marshal(sbom(nil, older))
		w, _ := postExact(t, srv, statementsRequest{SBOM: raw})
		if w.Code != http.StatusNoContent {
			t.Errorf("status %d, want 204: %s", w.Code, w.Body.String())
		}
	})
	t.Run("statements: above it, the binary as sent", func(t *testing.T) {
		raw, _ := json.Marshal(sbom(nil, newer, older))
		w, got := postExact(t, srv, statementsRequest{SBOM: raw})
		if want := []string{boundaryLine("debian", "fixed", zlib1g)}; !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
		if body := rawStatements(srv, statementsRequest{SBOM: raw}); w.Code != http.StatusOK || !strings.Contains(body, "match_reason=via_source_package") {
			t.Errorf("no via_source_package: %s", body)
		}
	})

	analyze := func(t *testing.T, s map[string]any) []any {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"sbom": s})
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest("POST", "/v1/analyze", bytes.NewReader(body)))
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		var res map[string]any
		json.Unmarshal(w.Body.Bytes(), &res)
		vulns, _ := res["vulnerabilities"].([]any)
		return vulns
	}
	affecting := func(refs ...string) []any {
		aff := []any{}
		for _, r := range refs {
			aff = append(aff, map[string]any{"ref": r})
		}
		return []any{map[string]any{"id": boundaryCVE, "affects": aff}}
	}
	t.Run("analyze synthesises the CVE for the component above only", func(t *testing.T) {
		vulns := analyze(t, sbom(nil, newer, older))
		if len(vulns) != 1 {
			t.Fatalf("vulnerabilities = %v", vulns)
		}
		affects, _ := vulns[0].(map[string]any)["affects"].([]any)
		if len(affects) != 1 || affects[0].(map[string]any)["ref"] != "urn:cdx:1/1#a" {
			t.Errorf("affects = %v, want zlib1g (a) only", affects)
		}
	})
	t.Run("analyze annotates the component above, not the one below", func(t *testing.T) {
		if a, _ := analyze(t, sbom(affecting(zlib1g), newer, older))[0].(map[string]any)["analysis"].(map[string]any); a["state"] != "resolved" {
			t.Errorf("zlib1g: analysis = %v, want resolved", a)
		}
		if a := analyze(t, sbom(affecting(zlibOld), newer, older))[0].(map[string]any)["analysis"]; a != nil {
			t.Errorf("zlib1g-dev below the boundary: analysis = %v, want none", a)
		}
		if a := analyze(t, sbom(affecting(zlib1g, zlibOld), newer, older))[0].(map[string]any)["analysis"]; a != nil {
			t.Errorf("both: analysis = %v, want none (one component has no verdict)", a)
		}
	})
}
