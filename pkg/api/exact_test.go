package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ulikunitz/xz"

	"github.com/getreeldev/reel-vex/pkg/db"
	"github.com/getreeldev/reel-vex/pkg/db/dbtest"
	"github.com/getreeldev/reel-vex/pkg/ingest"
	"github.com/getreeldev/reel-vex/pkg/openvex"
	"github.com/getreeldev/reel-vex/pkg/source"
	"github.com/getreeldev/reel-vex/pkg/source/ranchervex"
	"github.com/getreeldev/reel-vex/pkg/source/ubuntuvex"
)

// Exact-list feeds end to end: Canonical's and Rancher's documents go through
// the real adapters and the ingest orchestrator into the store, then out
// through /v1/statements and /v1/analyze.

const (
	exactCVE   = "CVE-2024-1234"
	otherCVE   = "CVE-2024-6666"
	epochCVE   = "CVE-2024-5555"
	rancherCVE = "CVE-2024-3000"
	rancherImg = "pkg:oci/rancher/rancher-agent"
)

// ubuntuDocs is the canonical example (CVE-2024-1234, Ubuntu 22.04) as
// Canonical writes it — one product per binary version, an arm64 build
// listing two versions — plus openssl listed by another CVE at another
// version, and an inline-epoch '+dfsg' version on 18.04.
func ubuntuDocs() map[string]openvex.Document {
	jammy := func(name, version, arch string) openvex.Component {
		return openvex.Component{ID: "pkg:deb/ubuntu/" + name + "@" + version + "?arch=" + arch + "&distro=jammy"}
	}
	st := func(cve, status, justification string, products ...openvex.Component) openvex.Statement {
		return openvex.Statement{Vulnerability: openvex.Vulnerability{Name: cve}, Status: status,
			Justification: justification, Timestamp: "2026-04-01T00:00:00Z", Products: products}
	}
	return map[string]openvex.Document{
		"vex/cve/2024/" + exactCVE + ".json": {Context: openvex.Context, Version: 1, Statements: []openvex.Statement{
			st(exactCVE, "fixed", "", jammy("openssl", "1.10", "amd64"), jammy("openssl", "1.11", "amd64"),
				jammy("openssl", "1.11", "arm64"), jammy("openssl", "1.12", "arm64"), jammy("glibc", "2.35-2", "amd64")),
			st(exactCVE, "not_affected", "vulnerable_code_not_present", jammy("zlib", "1.2", "amd64"), jammy("zlib", "1.3", "amd64")),
			st(exactCVE, "affected", "", jammy("curl", "7.81", "amd64"), jammy("glibc", "2.35-1", "amd64")),
		}},
		"vex/cve/2024/" + otherCVE + ".json": {Context: openvex.Context, Version: 1, Statements: []openvex.Statement{
			st(otherCVE, "affected", "", jammy("openssl", "1.13", "amd64")),
		}},
		"vex/cve/2024/" + epochCVE + ".json": {Context: openvex.Context, Version: 1, Statements: []openvex.Statement{
			st(epochCVE, "fixed", "", openvex.Component{ID: "pkg:deb/ubuntu/bind9@1:9.11.3+dfsg-1ubuntu1.17?arch=amd64&distro=bionic"}),
		}},
	}
}

func ubuntuTarball(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	xw, err := xz.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(xw)
	docs := ubuntuDocs()
	names := make([]string, 0, len(docs))
	for n := range docs {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		b, _ := json.Marshal(docs[n])
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write(b)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := xw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// rancherSnapshot is a one-package VEX Hub snapshot: x/net not_affected at two
// versions inside one image, and a deb subcomponent stated with no version.
func rancherSnapshot(t *testing.T) []byte {
	t.Helper()
	doc := openvex.Document{Context: openvex.Context, Version: 1, Timestamp: "2026-04-01T00:00:00Z", Statements: []openvex.Statement{
		{Vulnerability: openvex.Vulnerability{Name: rancherCVE}, Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path",
			Products: []openvex.Component{{ID: rancherImg, Subcomponents: []openvex.Component{{ID: "pkg:golang/golang.org/x/net@v0.17.0"}}}}},
		{Vulnerability: openvex.Vulnerability{Name: rancherCVE}, Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path",
			Products: []openvex.Component{{ID: rancherImg, Subcomponents: []openvex.Component{{ID: "pkg:golang/golang.org/x/net@v0.18.0"}}}}},
		{Vulnerability: openvex.Vulnerability{Name: rancherCVE}, Status: "not_affected", Justification: "vulnerable_code_not_present",
			Products: []openvex.Component{{ID: rancherImg, Subcomponents: []openvex.Component{{ID: "pkg:deb/ubuntu/inetutils-ping"}}}}},
	}}
	docBytes, _ := json.Marshal(doc)
	index := []byte(`{"version":1,"packages":[{"id":"pkg:golang/golang.org/x/net","location":"pkg/golang/x-net/vex.json"}]}`)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, e := range []struct {
		name string
		body []byte
	}{{"vexhub-main/index.json", index}, {"vexhub-main/pkg/golang/x-net/vex.json", docBytes}} {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write(e.body)
	}
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

func serveBytes(t *testing.T, payload []byte) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		if r.Method == http.MethodGet {
			w.Write(payload)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/feed"
}

// exactServer ingests both feeds through their adapters, adds a Debian OVAL
// legacy row (empty version_kind) beside them, and returns a server over the store.
func exactServer(t *testing.T) *Server {
	t.Helper()
	store := dbtest.New()
	ub, err := ubuntuvex.New(source.AdapterConfig{ID: "ubuntu-vex", URL: serveBytes(t, ubuntuTarball(t))})
	if err != nil {
		t.Fatal(err)
	}
	ra, err := ranchervex.New(source.AdapterConfig{ID: "rancher-vex", URL: serveBytes(t, rancherSnapshot(t))})
	if err != nil {
		t.Fatal(err)
	}
	if err := ingest.Run(context.Background(), []source.Adapter{ub, ra}, nil, store, ingest.Options{SweepMaxFraction: 0.5}); err != nil {
		t.Fatal(err)
	}
	if err := store.BulkInsert([]db.Statement{{Vendor: "debian", CVE: exactCVE, ProductID: "pkg:deb/debian/zlib?distro=debian-12",
		BaseID: "pkg:deb/debian/zlib?distro=debian-12", Versions: []string{"1:1.2.13.dfsg-1"}, IDType: "purl", Status: "fixed",
		Updated: "2026-04-01T00:00:00Z", SourceFormat: "oval"}}); err != nil {
		t.Fatal(err)
	}
	return NewServer(store, nil)
}

func postExact(t *testing.T, srv *Server, req statementsRequest) (*httptest.ResponseRecorder, []string) {
	t.Helper()
	body, _ := json.Marshal(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest("POST", "/v1/statements", bytes.NewReader(body)))
	if w.Code == http.StatusNoContent {
		return w, nil
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	return w, renderDoc(decodeOpenVEX(t, w))
}

// renderDoc is one line per statement: supplier, status, then its products.
func renderDoc(doc openvex.Document) []string {
	var out []string
	for _, s := range doc.Statements {
		ids := make([]string, 0, len(s.Products))
		for _, p := range s.Products {
			id := p.ID
			if id == "" && p.Identifiers != nil {
				id = p.Identifiers.CPE23
			}
			ids = append(ids, id)
		}
		out = append(out, s.Vulnerability.Name+" "+s.Supplier+" "+s.Status+" "+strings.Join(ids, " "))
	}
	return out
}

func amd64(name, version string) string {
	return "pkg:deb/ubuntu/" + name + "@" + version + "?arch=amd64&distro=ubuntu-22.04"
}

func arm64(name, version string) string {
	return "pkg:deb/ubuntu/" + name + "@" + version + "?arch=arm64&distro=ubuntu-22.04"
}

func TestExactLists_Statements(t *testing.T) {
	srv := exactServer(t)
	cases := []struct {
		name       string
		req        statementsRequest
		want       []string
		statements int
	}{
		{"openssl@1.11 gets fixed, at 1.11 only",
			statementsRequest{CVEs: []string{exactCVE}, Products: []string{amd64("openssl", "1.11")}},
			[]string{exactCVE + " ubuntu fixed " + amd64("openssl", "1.11") + " " + arm64("openssl", "1.11")}, 2},
		{"openssl@1.09 is listed nowhere: nothing",
			statementsRequest{CVEs: []string{exactCVE}, Products: []string{amd64("openssl", "1.09")}}, nil, 0},
		{"no version: every listed version under its own verdict",
			statementsRequest{CVEs: []string{exactCVE}, Products: []string{
				"pkg:deb/ubuntu/openssl?arch=amd64&distro=ubuntu-22.04", "pkg:deb/ubuntu/glibc?distro=ubuntu-22.04"}},
			[]string{
				exactCVE + " ubuntu affected " + amd64("glibc", "2.35-1"),
				exactCVE + " ubuntu fixed " + amd64("glibc", "2.35-2") + " " + amd64("openssl", "1.10") + " " + amd64("openssl", "1.11") +
					" " + arm64("openssl", "1.11") + " " + arm64("openssl", "1.12"),
			}, 4},
		{"glibc@2.35-1 gets affected only",
			statementsRequest{CVEs: []string{exactCVE}, Products: []string{amd64("glibc", "2.35-1")}},
			[]string{exactCVE + " ubuntu affected " + amd64("glibc", "2.35-1")}, 1},
		{"zlib with no version: not_affected for both versions",
			statementsRequest{CVEs: []string{exactCVE}, Products: []string{"pkg:deb/ubuntu/zlib?distro=ubuntu-22.04"}},
			[]string{exactCVE + " ubuntu not_affected " + amd64("zlib", "1.2") + " " + amd64("zlib", "1.3")}, 1},
		{"strict_arch keeps the asked architecture's row only",
			statementsRequest{CVEs: []string{exactCVE}, Products: []string{arm64("openssl", "1.11")}, StrictArch: true},
			[]string{exactCVE + " ubuntu fixed " + arm64("openssl", "1.11")}, 1},
		{"no products: every row expanded",
			statementsRequest{CVEs: []string{epochCVE}},
			[]string{epochCVE + " ubuntu fixed pkg:deb/ubuntu/bind9@1:9.11.3+dfsg-1ubuntu1.17?arch=amd64&distro=ubuntu-18.04"}, 1},
		{"URL-encoded epoch and '+'",
			statementsRequest{CVEs: []string{epochCVE}, Products: []string{"pkg:deb/ubuntu/bind9@1%3A9.11.3%2Bdfsg-1ubuntu1.17?arch=amd64&distro=ubuntu-18.04"}},
			[]string{epochCVE + " ubuntu fixed pkg:deb/ubuntu/bind9@1:9.11.3+dfsg-1ubuntu1.17?arch=amd64&distro=ubuntu-18.04"}, 1},
		{"the epoch qualifier folds into the version",
			statementsRequest{CVEs: []string{epochCVE}, Products: []string{"pkg:deb/ubuntu/bind9@9.11.3%2Bdfsg-1ubuntu1.17?arch=amd64&distro=ubuntu-18.04&epoch=1"}},
			[]string{epochCVE + " ubuntu fixed pkg:deb/ubuntu/bind9@1:9.11.3+dfsg-1ubuntu1.17?arch=amd64&distro=ubuntu-18.04"}, 1},
		{"without its epoch the version is another version",
			statementsRequest{CVEs: []string{epochCVE}, Products: []string{"pkg:deb/ubuntu/bind9@9.11.3+dfsg-1ubuntu1.17?arch=amd64&distro=ubuntu-18.04"}}, nil, 0},
		{"broad mode: a versioned product gets only its own verdicts",
			statementsRequest{Products: []string{amd64("glibc", "2.35-2")}},
			[]string{exactCVE + " ubuntu fixed " + amd64("glibc", "2.35-2")}, 1},
		{"kind '' row with products: the caller's base echoed, version ignored, as before",
			statementsRequest{CVEs: []string{exactCVE}, Products: []string{"pkg:deb/debian/zlib@9.9?arch=amd64&distro=debian-12"}},
			[]string{exactCVE + " debian fixed pkg:deb/debian/zlib?distro=debian-12"}, 1},
		{"Rancher: the scoped verdict for the module version asked",
			statementsRequest{CVEs: []string{rancherCVE}, Products: []string{"pkg:golang/golang.org/x/net@v0.17.0"}, Scopes: []string{rancherImg + "@sha256:abc"}},
			[]string{rancherCVE + " rancher not_affected pkg:golang/golang.org/x/net@v0.17.0"}, 1},
		{"Rancher: a version the image was not assessed at gets nothing",
			statementsRequest{CVEs: []string{rancherCVE}, Products: []string{"pkg:golang/golang.org/x/net@v0.16.0"}, Scopes: []string{rancherImg}}, nil, 0},
		{"Rancher: no version lists both",
			statementsRequest{CVEs: []string{rancherCVE}, Products: []string{"pkg:golang/golang.org/x/net"}, Scopes: []string{rancherImg}},
			[]string{rancherCVE + " rancher not_affected pkg:golang/golang.org/x/net@v0.17.0 pkg:golang/golang.org/x/net@v0.18.0"}, 1},
		{"Rancher: an empty list (no version stated) matches any version, rendered as the vendor's id",
			statementsRequest{CVEs: []string{rancherCVE}, Products: []string{"pkg:deb/ubuntu/inetutils-ping@2.5-3ubuntu4?arch=amd64&distro=ubuntu-24.04&epoch=2"}, Scopes: []string{rancherImg}},
			[]string{rancherCVE + " rancher not_affected pkg:deb/ubuntu/inetutils-ping"}, 1},
		{"a base asked with and without a version keeps its whole list",
			statementsRequest{CVEs: []string{exactCVE}, Products: []string{amd64("glibc", "2.35-1"), "pkg:deb/ubuntu/glibc?distro=ubuntu-22.04"}},
			[]string{exactCVE + " ubuntu affected " + amd64("glibc", "2.35-1"), exactCVE + " ubuntu fixed " + amd64("glibc", "2.35-2")}, 2},
		{"one CVE's listed version never admits another CVE's row",
			statementsRequest{CVEs: []string{exactCVE, otherCVE}, Products: []string{amd64("openssl", "1.10")}},
			[]string{exactCVE + " ubuntu fixed " + amd64("openssl", "1.10")}, 1},
		{"each CVE's own listed version",
			statementsRequest{CVEs: []string{exactCVE, otherCVE}, Products: []string{amd64("openssl", "1.13")}},
			[]string{otherCVE + " ubuntu affected " + amd64("openssl", "1.13")}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w, got := postExact(t, srv, c.req)
			if strings.Join(got, "\n") != strings.Join(c.want, "\n") {
				t.Errorf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(c.want, "\n"))
			}
			if h := w.Header().Get("X-Reel-Statements"); h != strconv.Itoa(c.statements) {
				t.Errorf("X-Reel-Statements = %s, want %d", h, c.statements)
			}
		})
	}

	t.Run("kind '' row with no products: its own product_id, as before", func(t *testing.T) {
		_, got := postExact(t, srv, statementsRequest{CVEs: []string{exactCVE}, Vendors: []string{"debian"}})
		if want := exactCVE + " debian fixed pkg:deb/debian/zlib?distro=debian-12"; strings.Join(got, "\n") != want {
			t.Errorf("got %v, want %s", got, want)
		}
	})

	t.Run("pages over one product's verdicts are stable and complete", func(t *testing.T) {
		req := statementsRequest{CVEs: []string{exactCVE}, Products: []string{"pkg:deb/ubuntu/glibc?distro=ubuntu-22.04"}, Limit: 1}
		w, first := postExact(t, srv, req)
		if w.Header().Get("X-Reel-Truncated") != "true" || w.Header().Get("X-Reel-Next-Offset") != "1" {
			t.Fatalf("first page not flagged as truncated: %v", w.Header())
		}
		req.Offset = 1
		w, second := postExact(t, srv, req)
		if w.Header().Get("X-Reel-Truncated") != "" {
			t.Errorf("second page flagged truncated")
		}
		got := append(first, second...)
		want := []string{exactCVE + " ubuntu affected " + amd64("glibc", "2.35-1"), exactCVE + " ubuntu fixed " + amd64("glibc", "2.35-2")}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("pages:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	})
}

func TestExactLists_Analyze(t *testing.T) {
	srv := exactServer(t)
	post := func(t *testing.T, sbom map[string]any) (*httptest.ResponseRecorder, map[string]any) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"sbom": sbom})
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest("POST", "/v1/analyze", bytes.NewReader(body)))
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		var res map[string]any
		json.NewDecoder(bytes.NewReader(w.Body.Bytes())).Decode(&res)
		return w, res
	}
	sbom := func(vulns []any, purls ...string) map[string]any {
		comps := []any{}
		for i, p := range purls {
			comps = append(comps, map[string]any{"type": "library", "purl": p, "bom-ref": "c" + strconv.Itoa(i)})
		}
		m := map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": "urn:uuid:1", "components": comps}
		if vulns != nil {
			m["vulnerabilities"] = vulns
		}
		return m
	}
	analysisOf := func(t *testing.T, res map[string]any) map[string]any {
		t.Helper()
		vulns, _ := res["vulnerabilities"].([]any)
		if len(vulns) != 1 {
			t.Fatalf("want one vulnerability, got %v", res["vulnerabilities"])
		}
		a, _ := vulns[0].(map[string]any)["analysis"].(map[string]any)
		return a
	}

	t.Run("annotate: each component's own verdict", func(t *testing.T) {
		w, res := post(t, sbom([]any{map[string]any{"id": exactCVE}}, amd64("curl", "7.81"), amd64("glibc", "2.35-1")))
		a := analysisOf(t, res)
		// The fixed glibc@2.35-2 row must not be there to outrank affected.
		if a["state"] != "exploitable" || a["detail"] != "ubuntu: affected; ubuntu: affected" {
			t.Errorf("analysis = %v", a)
		}
		if h := w.Header().Get("X-Reel-Statements"); h != "2" {
			t.Errorf("X-Reel-Statements = %s, want 2", h)
		}
	})
	t.Run("annotate: an unlisted version leaves the vulnerability alone", func(t *testing.T) {
		_, res := post(t, sbom([]any{map[string]any{"id": exactCVE}}, amd64("openssl", "1.09")))
		if a := analysisOf(t, res); a != nil {
			t.Errorf("analysis = %v, want none", a)
		}
	})
	t.Run("annotate: a base asked both with and without a version keeps its whole list", func(t *testing.T) {
		_, res := post(t, sbom([]any{map[string]any{"id": exactCVE}}, amd64("glibc", "2.35-1"), "pkg:deb/ubuntu/glibc?arch=amd64&distro=ubuntu-22.04"))
		if a := analysisOf(t, res); a["state"] != "resolved" || a["detail"] != "ubuntu: affected; ubuntu: fixed" {
			t.Errorf("analysis = %v", a)
		}
	})
	t.Run("synthesise: only the verdict for the version present", func(t *testing.T) {
		_, res := post(t, sbom(nil, amd64("glibc", "2.35-2")))
		if a := analysisOf(t, res); a["state"] != "resolved" || a["detail"] != "ubuntu: fixed" {
			t.Errorf("analysis = %v", a)
		}
	})
}
