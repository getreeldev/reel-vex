package api

import (
	"bytes"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/getreeldev/reel-vex/pkg/csaf"
	"github.com/getreeldev/reel-vex/pkg/db"
	"github.com/getreeldev/reel-vex/pkg/db/dbtest"
)

// srcProps are the properties Trivy writes on a deb component built from a
// source package; empty values are left out, as Trivy leaves them out.
func srcProps(name, version, release, epoch string) map[string]string {
	p := map[string]string{}
	for k, v := range map[string]string{propSrcName: name, propSrcVersion: version, propSrcRelease: release, propSrcEpoch: epoch} {
		if v != "" {
			p[k] = v
		}
	}
	return p
}

// TestSourcePURL: a Debian component built from a source package of another
// name gets that source package's purl, with the binary's distro as written
// and the source version in the form csaf.MatchVersion matches.
func TestSourcePURL(t *testing.T) {
	const zlib1g = "pkg:deb/debian/zlib1g@1.2.13.dfsg-1?arch=amd64&distro=debian-12.15&epoch=1"
	const libc6 = "pkg:deb/debian/libc6@2.36-9%2Bdeb12u14?arch=amd64&distro=debian-12.15"
	for _, c := range []struct {
		name, purl string
		props      map[string]string
		want       string
		version    string // csaf.MatchVersion of want
	}{
		{"no SrcName", zlib1g, srcProps("", "1.2.13.dfsg", "1", "1"), "", ""},
		{"no properties", zlib1g, nil, "", ""},
		{"SrcName equals the name", "pkg:deb/debian/base-files@12.4%2Bdeb12u15?arch=amd64&distro=debian-12.15",
			srcProps("base-files", "12.4+deb12u15", "", ""), "", ""},
		{"different name, epoch", zlib1g, srcProps("zlib", "1.2.13.dfsg", "1", "1"),
			"pkg:deb/debian/zlib@1.2.13.dfsg-1?distro=debian-12.15&epoch=1", "1:1.2.13.dfsg-1"},
		{"different name, no epoch", libc6, srcProps("glibc", "2.36", "9+deb12u14", ""),
			"pkg:deb/debian/glibc@2.36-9+deb12u14?distro=debian-12.15", "2.36-9+deb12u14"},
		{"epoch 0 is no epoch", libc6, srcProps("glibc", "2.36", "9+deb12u14", "0"),
			"pkg:deb/debian/glibc@2.36-9+deb12u14?distro=debian-12.15", "2.36-9+deb12u14"},
		{"native source package: no release", "pkg:deb/debian/libfoo1@3.1?arch=amd64&distro=debian-12.15",
			srcProps("foo", "3.1", "", ""), "pkg:deb/debian/foo@3.1?distro=debian-12.15", "3.1"},
		{"no source version", libc6, srcProps("glibc", "", "", ""), "pkg:deb/debian/glibc?distro=debian-12.15", ""},
		{"no distro", "pkg:deb/debian/libc6@2.36-9?arch=amd64", srcProps("glibc", "2.36", "9", ""), "pkg:deb/debian/glibc@2.36-9", "2.36-9"},
		{"a percent-encoded name equal to its source", "pkg:deb/debian/libsigc%2B%2B-2.0@2.12.0-1?arch=amd64&distro=debian-12.15",
			srcProps("libsigc++-2.0", "2.12.0", "1", ""), "", ""},
		{"Ubuntu names binaries", "pkg:deb/ubuntu/zlib1g@1.2.11.dfsg-2ubuntu9.2?arch=amd64&distro=ubuntu-22.04&epoch=1",
			srcProps("zlib", "1.2.11.dfsg", "2ubuntu9.2", "1"), "", ""},
		{"not a deb", "pkg:rpm/redhat/openssl-libs@3.0.7-27.el9?arch=x86_64&distro=redhat-9.4&epoch=1",
			srcProps("openssl", "3.0.7", "27.el9", "1"), "", ""},
	} {
		got := sourcePURL(c.purl, c.props)
		if got != c.want {
			t.Errorf("%s: sourcePURL = %q, want %q", c.name, got, c.want)
			continue
		}
		if v := csaf.MatchVersion(got); v != c.version {
			t.Errorf("%s: MatchVersion(%q) = %q, want %q", c.name, got, v, c.version)
		}
	}
}

// TestExtractSourcePackages reads the properties off the SBOM's components.
func TestExtractSourcePackages(t *testing.T) {
	var sbom map[string]any
	if err := json.Unmarshal([]byte(`{"components":[
		{"purl":"pkg:deb/debian/zlib1g@1.2.13.dfsg-1?arch=amd64&distro=debian-12.15&epoch=1","properties":[
			{"name":"aquasecurity:trivy:PkgType","value":"debian"},
			{"name":"aquasecurity:trivy:SrcEpoch","value":"1"},
			{"name":"aquasecurity:trivy:SrcName","value":"zlib"},
			{"name":"aquasecurity:trivy:SrcRelease","value":"1"},
			{"name":"aquasecurity:trivy:SrcVersion","value":"1.2.13.dfsg"}]},
		{"purl":"pkg:deb/debian/tzdata@2026b-0%2Bdeb12u1?arch=all&distro=debian-12.15","properties":[
			{"name":"aquasecurity:trivy:SrcName","value":"tzdata"}]},
		{"purl":"pkg:deb/debian/gzip@1.12-1?arch=amd64&distro=debian-12.15"},
		{"cpe":"cpe:2.3:a:example:x:1:*:*:*:*:*:*:*"}]}`), &sbom); err != nil {
		t.Fatal(err)
	}
	got := extractSourcePackages(sbom)
	want := map[string]string{
		"pkg:deb/debian/zlib1g@1.2.13.dfsg-1?arch=amd64&distro=debian-12.15&epoch=1": "pkg:deb/debian/zlib@1.2.13.dfsg-1?distro=debian-12.15&epoch=1",
	}
	if !maps.Equal(got, want) {
		t.Errorf("extractSourcePackages = %v, want %v", got, want)
	}
}

// TestExpandProducts_SourcePackage: the source purl runs through the resolver
// (debian-12.15 normalises to debian-12), every candidate it alone reaches is
// a via_source_package base echoed under the binary, and a base the products
// reach themselves keeps its own reason and is not a source base.
func TestExpandProducts_SourcePackage(t *testing.T) {
	database := dbtest.New()
	t.Cleanup(func() { database.Close() })
	srv := NewServer(database, nil)

	const (
		libc6   = "pkg:deb/debian/libc6@2.36-9%2Bdeb12u14?arch=amd64&distro=debian-12.15"
		libcBin = "pkg:deb/debian/libc-bin@2.36-9%2Bdeb12u14?arch=amd64&distro=debian-12.15"
		libssl3 = "pkg:deb/debian/libssl3@3.0.15-1~deb12u1?arch=amd64&distro=debian-12.15"
		openssl = "pkg:deb/debian/openssl@3.0.15-1~deb12u1?arch=amd64&distro=debian-12.15"
	)
	sources := map[string]string{
		libc6:   "pkg:deb/debian/glibc@2.36-9+deb12u14?distro=debian-12.15",
		libcBin: "pkg:deb/debian/glibc@2.36-9+deb12u14?distro=debian-12.15",
		libssl3: "pkg:deb/debian/openssl@3.0.15-1~deb12u1?distro=debian-12.15",
	}
	reason, inputs, versions, sourceBases := srv.expandProducts([]string{libc6, libcBin, libssl3, openssl}, sources)

	glibc := []string{"pkg:deb/debian/glibc?distro=debian-12.15", "pkg:deb/debian/glibc", "pkg:deb/debian/glibc?distro=debian-12"}
	for _, b := range glibc {
		if reason[b] != matchViaSourcePackage {
			t.Errorf("reason[%s] = %q, want %s", b, reason[b], matchViaSourcePackage)
		}
		if want := []string{"pkg:deb/debian/libc6?distro=debian-12.15", "pkg:deb/debian/libc-bin?distro=debian-12.15"}; !slices.Equal(inputs[b], want) {
			t.Errorf("inputs[%s] = %v, want %v (one echo per binary)", b, inputs[b], want)
		}
	}
	if !slices.Equal(sourceBases, glibc) {
		t.Errorf("sourceBases = %v, want %v", sourceBases, glibc)
	}
	// openssl is a product in its own right: direct, not a source base, and
	// libssl3 is echoed for it too.
	ossl := "pkg:deb/debian/openssl?distro=debian-12"
	if reason[ossl] != "direct" {
		t.Errorf("reason[%s] = %q, want direct", ossl, reason[ossl])
	}
	if want := []string{"pkg:deb/debian/openssl?distro=debian-12.15", "pkg:deb/debian/libssl3?distro=debian-12.15"}; !slices.Equal(inputs[ossl], want) {
		t.Errorf("inputs[%s] = %v, want %v", ossl, inputs[ossl], want)
	}
	// A source candidate pairs no version: only the products' own do.
	for _, v := range versions {
		if slices.Contains(glibc, v.Base) {
			t.Errorf("versions has a source candidate pair %+v", v)
		}
		if v.Base == ossl && v.Version != "3.0.15-1~deb12u1" {
			t.Errorf("versions pairs %s with %q", ossl, v.Version)
		}
	}
}

// TestHandleStatements_SourcePackageAdmitsNoExactRow: a source candidate finds
// the source-keyed row but never an exact-list row stored under the source
// package's name, even at the source version; a product naming that package
// itself still does.
func TestHandleStatements_SourcePackageAdmitsNoExactRow(t *testing.T) {
	database := dbtest.New()
	t.Cleanup(func() { database.Close() })
	const cve = "CVE-2024-0001"
	if err := database.BulkInsert([]db.Statement{
		{Vendor: "debian", CVE: cve, ProductID: "pkg:deb/debian/openssl?distro=debian-12", BaseID: "pkg:deb/debian/openssl?distro=debian-12",
			Versions: []string{"3.0.11-1~deb12u2"}, IDType: "purl", Status: "fixed", Updated: "2026-10-03T00:00:00Z", SourceFormat: "oval"},
		{Vendor: "exactvendor", CVE: cve, ProductID: "pkg:deb/debian/openssl?arch=amd64", BaseID: "pkg:deb/debian/openssl",
			Versions: []string{"3.0.15-1~deb12u1"}, VersionKind: db.VersionKindExact, IDType: "purl", Status: "not_affected",
			Justification: "vulnerable_code_not_present", Updated: "2026-10-03T00:00:00Z", SourceFormat: "openvex"},
	}); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(database, nil)

	post := func(sbom string) []string {
		t.Helper()
		body, _ := json.Marshal(statementsRequest{CVEs: []string{cve}, SBOM: json.RawMessage(sbom)})
		req := httptest.NewRequest("POST", "/v1/statements", bytes.NewReader(body))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		var got []string
		for _, s := range decodeOpenVEX(t, w).Statements {
			for _, p := range s.Products {
				got = append(got, s.Supplier+" "+s.Status+" "+p.ID+" "+s.StatusNotes)
			}
		}
		slices.Sort(got)
		return got
	}

	got := post(`{"components":[{"purl":"pkg:deb/debian/libssl3@3.0.15-1~deb12u1?arch=amd64&distro=debian-12.15","properties":[
		{"name":"aquasecurity:trivy:SrcName","value":"openssl"},
		{"name":"aquasecurity:trivy:SrcVersion","value":"3.0.15"},
		{"name":"aquasecurity:trivy:SrcRelease","value":"1~deb12u1"}]}]}`)
	want := []string{"debian fixed pkg:deb/debian/libssl3?distro=debian-12.15 source_format=oval; match_reason=via_source_package"}
	if !slices.Equal(got, want) {
		t.Errorf("libssl3 (source openssl):\n got %v\nwant %v", got, want)
	}

	got = post(`{"components":[{"purl":"pkg:deb/debian/openssl@3.0.15-1~deb12u1?arch=amd64&distro=debian-12.15","properties":[
		{"name":"aquasecurity:trivy:SrcName","value":"openssl"}]}]}`)
	want = []string{
		"debian fixed pkg:deb/debian/openssl?distro=debian-12.15 source_format=oval; match_reason=direct",
		"exactvendor not_affected pkg:deb/debian/openssl@3.0.15-1~deb12u1?arch=amd64 source_format=openvex; match_reason=direct",
	}
	if !slices.Equal(got, want) {
		t.Errorf("openssl itself:\n got %v\nwant %v", got, want)
	}
}
