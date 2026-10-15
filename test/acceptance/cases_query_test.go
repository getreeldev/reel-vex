//go:build integration

package acceptance

import "strings"

// Filters on /v1/statements, and /v1/analyze with CycloneDX SBOMs shaped the way
// Trivy writes them: every component's bom-ref is its PURL, the root subject is
// metadata.component, and a vulnerability's affects[].ref names a bom-ref, which
// the API rewrites to a BOM-Link (urn:cdx:<serial>/<version>#<bom-ref>).

func filterCases() []Case {
	return []Case{
		{
			Name: "filter/vendors", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2022-37434"), "vendors": ss("debian")}, Status: 200, Rows: 2,
			Want: []Stmt{{CVE: "CVE-2022-37434", Supplier: "debian", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", ""),
				Products: ss("pkg:deb/debian/libz-mingw-w64?distro=debian-12", "pkg:deb/debian/zlib?distro=debian-12"),
				Evidence: "DO definitions ...def:118596735315433746990801407057633161948 (zlib) and ...def:54799239821264313931010316258924094420 (libz-mingw-w64 < 0:1.2.12+dfsg-2)"}},
		},
		{
			Name: "filter/vendors excluding every row", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2023-34034"), "vendors": ss("suse")},
			Status: 204, Rows: 0,
		},
		{
			Name: "filter/statuses", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2023-34034"), "statuses": ss("affected")}, Status: 200, Rows: 2,
			Want: rh34034()[:1],
		},
		{
			Name: "filter/justifications", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2016-9571"), "justifications": ss("vulnerable_code_not_present")}, Status: 200, Rows: 7,
			Want: func() []Stmt {
				for _, c := range ubuntuCases() {
					if strings.HasPrefix(c.Name, "ubuntu/cve-only/affected and not_affected") {
						return c.Want[1:]
					}
				}
				return nil
			}(),
		},
		{
			Name: "filter/source_formats", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2022-37434"), "products": ss("pkg:deb/ubuntu/libklibc@2.0.13-4ubuntu0.2?arch=amd64&distro=ubuntu-24.04"), "source_formats": ss("oval")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2022-37434", Supplier: "ubuntu", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", "direct"),
				Products: ss("pkg:deb/ubuntu/libklibc@2.0.13-4ubuntu0.2?arch=amd64&distro=ubuntu-24.04"),
				Evidence: "UO definition oval:com.ubuntu.noble:def:673620000000 (USN-6736-2): libklibc < 2.0.13-4ubuntu0.1; 2.0.13-4ubuntu0.2 is above it"}},
		},
		{
			Name: "filter/since", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2023-34034", "CVE-2026-94282"), "since": "2026-10-01T00:00:00Z"}, Status: 200, Rows: 7,
			Want: rh34034(),
		},
		{
			Name: "filter/since is inclusive", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2023-34034"), "since": tsRH34034, "statuses": ss("fixed")}, Status: 200, Rows: 1,
			Want: rh34034()[1:2],
		},
		// Paging. The 7 rows of CVE-2023-34034 sort by base_id the same way in
		// every collation (docs/api.md: ordered by base_id, cve, product_id,
		// source_format): camel_quarkus:2, jboss_enterprise_bpms_platform:7,
		// jboss_fuse:6, jboss_fuse:7.12, quarkus:2, red_hat_single_sign_on:7,
		// then the maven PURL.
		{
			Name: "paging/first page", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2023-34034"), "limit": 3}, Status: 200, Rows: 3,
			Headers: map[string]string{"X-Reel-Truncated": "true", "X-Reel-Next-Offset": "3", "X-Reel-Grouped": "2", "X-Reel-Mode": "cve", "X-Reel-CVE": "CVE-2023-34034"},
			Want: []Stmt{
				{CVE: "CVE-2023-34034", Supplier: "redhat", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: tsRH34034, Notes: notes("csaf", ""),
					Products: ss("cpe:/a:redhat:camel_quarkus:2"), Evidence: "RH 2023/cve-2023-34034.json known_not_affected: red_hat_integration_camel_quarkus_2:spring-security (first by base_id)"},
				{CVE: "CVE-2023-34034", Supplier: "redhat", Status: "affected", Timestamp: tsRH34034, Notes: notes("csaf", ""),
					Products: ss("cpe:/a:redhat:jboss_enterprise_bpms_platform:7", "cpe:/a:redhat:jboss_fuse:6"), Evidence: "RH 2023/cve-2023-34034.json known_affected (2nd and 3rd by base_id)"},
			},
		},
		{
			Name: "paging/second page", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2023-34034"), "limit": 3, "offset": 3}, Status: 200, Rows: 3,
			Headers: map[string]string{"X-Reel-Truncated": "true", "X-Reel-Next-Offset": "6", "X-Reel-Grouped": "2"},
			Want: []Stmt{
				{CVE: "CVE-2023-34034", Supplier: "redhat", Status: "fixed", Timestamp: tsRH34034, Notes: notes("csaf", ""),
					Products: ss("cpe:/a:redhat:jboss_fuse:7.12"), Evidence: "RH 2023/cve-2023-34034.json fixed: Red Hat Fuse 7.12.1 (4th by base_id)"},
				{CVE: "CVE-2023-34034", Supplier: "redhat", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: tsRH34034, Notes: notes("csaf", ""),
					Products: ss("cpe:/a:redhat:quarkus:2", "cpe:/a:redhat:red_hat_single_sign_on:7"), Evidence: "RH 2023/cve-2023-34034.json known_not_affected (5th and 6th by base_id)"},
			},
		},
		{
			Name: "paging/last page is not truncated", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2023-34034"), "limit": 3, "offset": 6}, Status: 200, Rows: 1,
			Headers: map[string]string{"X-Reel-Truncated": "", "X-Reel-Next-Offset": "", "X-Reel-Grouped": "1"},
			Want: []Stmt{{CVE: "CVE-2023-34034", Supplier: "redhat", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: tsRH34034, Notes: notes("csaf", ""),
				Products: ss("pkg:maven/io.quarkus/quarkus-spring-security?repository_url=https://maven.repository.redhat.com/ga/&type=jar"),
				Evidence: "RH 2023/cve-2023-34034.json known_not_affected: red_hat_build_of_quarkus:quarkus-spring-security (7th by base_id)"}},
		},
		{
			Name: "errors/statements with no input is 400", Endpoint: epStatements,
			Body: body{"vendors": ss("redhat")}, Status: 400,
			Error: "one of cves, products, or sbom (with components or vulnerabilities) is required",
		},
		{
			Name: "errors/analyze with neither sbom nor user_vex is 400", Endpoint: epAnalyze,
			Body: body{}, Status: 400, Error: "at least one of sbom or user_vex required",
		},
		{
			Name: "errors/user_vex with another @context is 422", Endpoint: epAnalyze,
			Body: body{"user_vex": []any{map[string]any{"@context": "https://openvex.dev/ns/v0.1.0", "statements": []any{}}}}, Status: 422,
			Error: `doc[0]: user_vex doc has invalid @context (must be https://openvex.dev/ns/v0.2.0) (got "https://openvex.dev/ns/v0.1.0")`,
		},
		{
			Name: "filter/several dimensions are ANDed", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2025-1914", "CVE-2017-15535"), "vendors": ss("suse"), "statuses": ss("not_affected")}, Status: 200, Rows: 5,
			Want: func() []Stmt {
				for _, c := range suseCases() {
					if strings.HasPrefix(c.Name, "suse/cve-only/known_not_affected") {
						return c.Want[:1]
					}
				}
				return nil
			}(),
		},
	}
}

const sbomSerial = "urn:uuid:5f0c1d6e-7a2b-4c3d-9e8f-0a1b2c3d4e5f"

// link is the BOM-Link the API writes for a component whose bom-ref is ref.
func link(ref string) string { return "urn:cdx:5f0c1d6e-7a2b-4c3d-9e8f-0a1b2c3d4e5f/1#" + ref }

// withProperties sets CycloneDX properties on the SBOM component whose purl is
// p, the way Trivy records a package's source (aquasecurity:trivy:SrcName...).
func withProperties(sbom map[string]any, p string, props map[string]string) map[string]any {
	for _, c := range sbom["components"].([]any) {
		comp := c.(map[string]any)
		if comp["purl"] != p {
			continue
		}
		var ps []any
		for _, k := range sortedKeys(props) {
			ps = append(ps, map[string]any{"name": k, "value": props[k]})
		}
		comp["properties"] = ps
	}
	return sbom
}

// trivySource is the properties Trivy 0.74.0 writes on a deb component built
// from a source package (debian:12: SrcVersion is the upstream version,
// SrcRelease the Debian revision, SrcEpoch only when non-zero).
func trivySource(name, version, release, epoch string) map[string]string {
	p := map[string]string{"aquasecurity:trivy:PkgType": "debian", "aquasecurity:trivy:SrcName": name, "aquasecurity:trivy:SrcVersion": version}
	if release != "" {
		p["aquasecurity:trivy:SrcRelease"] = release
	}
	if epoch != "" {
		p["aquasecurity:trivy:SrcEpoch"] = epoch
	}
	return p
}

// Components of Trivy 0.74.0's debian:12 SBOM (2026-10-04), verbatim.
const (
	debianImage = "pkg:oci/debian@sha256:f37a335e82bca302e955fa39f9dfe28f1be618f016f8a2b56318e5a5111afc26?arch=amd64&repository_url=index.docker.io%2Flibrary%2Fdebian"
	zlib1gDeb12 = "pkg:deb/debian/zlib1g@1.2.13.dfsg-1?arch=amd64&distro=debian-12.15&epoch=1"
	libc6       = "pkg:deb/debian/libc6@2.36-9%2Bdeb12u14?arch=amd64&distro=debian-12.15"
	libcBin     = "pkg:deb/debian/libc-bin@2.36-9%2Bdeb12u14?arch=amd64&distro=debian-12.15"
)

// libcPair is a components-only SBOM of libc6 and libc-bin, both built from
// glibc.
func libcPair() map[string]any {
	sbom := trivySBOM(debianImage, ss(libc6, libcBin))
	sbom = withProperties(sbom, libc6, trivySource("glibc", "2.36", "9+deb12u14", ""))
	return withProperties(sbom, libcBin, trivySource("glibc", "2.36", "9+deb12u14", ""))
}

// userVEX is one OpenVEX 0.2.0 document with one statement, as a user uploads it.
func userVEX(cve, product, status, justification, supplier, ts string) map[string]any {
	st := map[string]any{
		"vulnerability": map[string]any{"name": cve},
		"products":      []any{map[string]any{"@id": product}},
		"status":        status,
		"supplier":      supplier,
		"timestamp":     ts,
	}
	if justification != "" {
		st["justification"] = justification
	}
	return map[string]any{
		"@context":   "https://openvex.dev/ns/v0.2.0",
		"@id":        "https://example.com/vex/acceptance-1",
		"author":     "Acme Security",
		"timestamp":  ts,
		"version":    1,
		"statements": []any{st},
	}
}

type sbomVuln struct {
	id      string
	affects []string
}

// trivySBOM builds a CycloneDX 1.6 document the way Trivy writes one.
func trivySBOM(root string, components []string, vulns ...sbomVuln) map[string]any {
	comps := make([]any, 0, len(components))
	for _, p := range components {
		name := p[strings.LastIndex(strings.SplitN(p, "@", 2)[0], "/")+1:]
		comps = append(comps, map[string]any{"bom-ref": p, "type": "library", "name": name, "purl": p})
	}
	doc := map[string]any{
		"$schema":      "http://cyclonedx.org/schema/bom-1.6.schema.json",
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.6",
		"serialNumber": sbomSerial,
		"version":      1,
		"metadata": map[string]any{
			"tools":     map[string]any{"components": []any{map[string]any{"type": "application", "group": "aquasecurity", "name": "trivy", "version": "0.70.0"}}},
			"component": map[string]any{"bom-ref": root, "type": "container", "name": "image", "purl": root},
		},
		"components": comps,
	}
	vs := make([]any, 0, len(vulns))
	for _, v := range vulns {
		aff := make([]any, 0, len(v.affects))
		for _, a := range v.affects {
			aff = append(aff, map[string]any{"ref": a})
		}
		vs = append(vs, map[string]any{"id": v.id, "source": map[string]any{"name": "trivy"}, "affects": aff})
	}
	doc["vulnerabilities"] = vs
	return doc
}

func analyzeCases() []Case {
	crun := "pkg:rpm/redhat/crun@1.14.3-1.el9?arch=x86_64&distro=redhat-9.4"
	chromium := "pkg:rpm/suse/chromium@134.0.6998.35-bp156.2.90.1?arch=x86_64&distro=opensuse-leap-15.6"
	zlib1g := "pkg:deb/ubuntu/zlib1g@1.2.11.dfsg-2ubuntu9.2?arch=amd64&distro=ubuntu-22.04&epoch=1"
	ds389 := "pkg:deb/debian/389-ds-base@2.3.1+dfsg1-1+deb12u1?arch=amd64&distro=debian-12"
	socat := "pkg:apk/alpine/socat@1.8.0.3-r0?arch=x86_64&distro=3.22.2"
	libdwarf := "pkg:apk/alpine/libdwarf@0.9.2-r0?arch=x86_64&distro=3.22.2"
	cacerts := "pkg:rpm/amazon/ca-certificates@2021.2.50-1.0.amzn2023.0.6?arch=noarch&distro=amazon-2023.7.20250512"
	squid := "pkg:rpm/alma/squid@5.2-1.el9_0.1?arch=x86_64&distro=alma-9.0&epoch=7"
	sudoPlugin := "pkg:rpm/oracle/sudo-python-plugin@1.9.5p2-10.el9_3?arch=x86_64&distro=oracle-9"
	xnet := "pkg:golang/golang.org/x/net@v0.35.0"
	otel := "pkg:golang/go.opentelemetry.io/otel/sdk@v1.40.0"
	zlibApk := "pkg:apk/alpine/zlib@1.2.12-r3?arch=x86_64&distro=3.16.2"
	opaRoot := "pkg:golang/github.com/open-policy-agent/opa@v1.2.0"
	image := "pkg:oci/app@sha256:1111111111111111111111111111111111111111111111111111111111111111?arch=amd64&repository_url=registry.example.com/app"
	sachetRoot := "pkg:oci/mirrored-messagebird-sachet@sha256:2222222222222222222222222222222222222222222222222222222222222222?arch=amd64&repository_url=index.docker.io/rancher/mirrored-messagebird-sachet"
	kubeOVNRoot := "pkg:oci/kube-ovn@sha256:3333333333333333333333333333333333333333333333333333333333333333?arch=amd64&repository_url=index.docker.io/kubeovn/kube-ovn"
	inetutils := "pkg:deb/ubuntu/inetutils-ping@2.5-3ubuntu4?arch=amd64&distro=ubuntu-24.04&epoch=2"
	libxsmm := "pkg:deb/ubuntu/libxsmm-dev@1.9-1?arch=amd64&distro=ubuntu-20.04"
	libXi := "pkg:rpm/redhat/libXi@1.8.1-9.el10?arch=x86_64&distro=redhat-10.0"
	microcodeAffected := "pkg:deb/ubuntu/intel-microcode@3.20210216.0ubuntu0.16.04.1?arch=amd64&distro=ubuntu-16.04"
	microcodeUnlisted := "pkg:deb/ubuntu/intel-microcode@3.20230214.0ubuntu0.16.04.1?arch=amd64&distro=ubuntu-16.04"
	mongodb := "pkg:rpm/suse/mongodb@3.4.10-5.1?arch=x86_64&distro=sles-12.2"
	microcodeCtl := "pkg:rpm/redhat/microcode_ctl@20250211-1.20250512.1.el9_6?arch=noarch&distro=redhat-9.6&epoch=4"
	zlib1gDebian := "pkg:deb/debian/zlib1g@1.2.13.dfsg-1?arch=amd64&distro=debian-12.11&epoch=1"
	socatUser := "pkg:apk/alpine/socat@1.8.0.3-r0?distro=alpine-3.22"

	return []Case{
		{
			Name: "analyze/rpm/Red Hat known_affected is exploitable", Endpoint: epAnalyze,
			Body:   body{"sbom": trivySBOM(image, ss(crun), sbomVuln{"CVE-2026-88265", ss(crun)})},
			Status: 200, Rows: 4,
			Vulns: []Vuln{{ID: "CVE-2026-88265", State: "exploitable", Affects: ss(link(crun)),
				Evidence: "RH 2026/cve-2026-88265.json product_status.known_affected: crun, crun.src, crun(.src)::container-tools:rhel8"}},
		},
		{
			Name: "analyze/rpm/SUSE recommended is resolved", Endpoint: epAnalyze,
			Body:   body{"sbom": trivySBOM(image, ss(chromium), sbomVuln{"CVE-2025-1914", ss(chromium)})},
			Status: 200, Rows: 2,
			Vulns: []Vuln{{ID: "CVE-2025-1914", State: "resolved", Affects: ss(link(chromium)),
				Evidence: "SUSE cve-2025-1914.json product_status.recommended: chromium-134.0.6998.35-bp156.2.90.1, chromium-134.0.6998.35-1.1"}},
		},
		{
			Name: "analyze/deb/Ubuntu fixed is resolved", Endpoint: epAnalyze,
			Body:   body{"sbom": trivySBOM(image, ss(zlib1g), sbomVuln{"CVE-2022-37434", ss(zlib1g)})},
			Status: 200, Rows: 7,
			Vulns: []Vuln{{ID: "CVE-2022-37434", State: "resolved", Affects: ss(link(zlib1g)),
				Evidence: "UV vex/cve/2022/CVE-2022-37434.json statements[0] fixed: zlib1g@1:1.2.11.dfsg-2ubuntu9.2 distro=jammy (7 arches)"}},
		},
		{
			Name: "analyze/deb/Debian 0:0 is exploitable", Endpoint: epAnalyze,
			Body:   body{"sbom": trivySBOM(image, ss(ds389), sbomVuln{"CVE-2016-5416", ss(ds389)})},
			Status: 200, Rows: 1,
			Vulns: []Vuln{{ID: "CVE-2016-5416", State: "exploitable", Affects: ss(link(ds389)),
				Evidence: "DO definition oval:org.debian:def:308370225544215691963860905694509241784: 389-ds-base evr less than 0:0"}},
		},
		{
			Name: "analyze/apk/Alpine \"0\" and fixed", Endpoint: epAnalyze,
			Body: body{"sbom": trivySBOM(image, ss(socat),
				sbomVuln{"CVE-2024-54661", ss(socat)}, sbomVuln{"CVE-2026-56123", ss(socat)}, sbomVuln{"CVE-2026-99999", ss(socat)})},
			Status: 200, Rows: 1,
			Vulns: []Vuln{
				{ID: "CVE-2024-54661", State: "not_affected", Justification: "code_not_present", Affects: ss(link(socat)), Evidence: "AS v3.22/main.json package socat: secfixes \"0\": [CVE-2024-54661]"},
				{ID: "CVE-2026-56123", Affects: ss(link(socat)), Evidence: "AS v3.22/main.json package socat: secfixes \"1.8.1.2-r0\": [CVE-2026-56123]; the component's 1.8.0.3-r0 is below the fixed-in version, so no analysis"},
				{ID: "CVE-2026-99999", Affects: ss(link(socat)), Evidence: "no fixture names CVE-2026-99999: left without analysis"},
			},
		},
		{
			Name: "analyze/rpm/Amazon fixed is resolved", Endpoint: epAnalyze,
			Body:   body{"sbom": trivySBOM(image, ss(cacerts), sbomVuln{"CVE-2022-23491", ss(cacerts)})},
			Status: 200, Rows: 1,
			Vulns: []Vuln{{ID: "CVE-2022-23491", State: "resolved", Affects: ss(link(cacerts)),
				Evidence: "AL al2023 updateinfo <update> ALAS2023-2023-061: ca-certificates"}},
		},
		{
			Name: "analyze/rpm/AlmaLinux fixed is resolved", Endpoint: epAnalyze,
			Body:   body{"sbom": trivySBOM(image, ss(squid), sbomVuln{"CVE-2021-46784", ss(squid)})},
			Status: 200, Rows: 1,
			Vulns: []Vuln{{ID: "CVE-2021-46784", State: "resolved", Affects: ss(link(squid)),
				Evidence: "AO definition oval:org.almalinux.alsa:def:20225527: squid"}},
		},
		{
			Name: "analyze/rpm/Oracle fixed is resolved", Endpoint: epAnalyze,
			Body:   body{"sbom": trivySBOM(image, ss(sudoPlugin), sbomVuln{"CVE-2023-28487", ss(sudoPlugin)})},
			Status: 200, Rows: 1,
			Vulns: []Vuln{{ID: "CVE-2023-28487", State: "resolved", Affects: ss(link(sudoPlugin)),
				Evidence: "OO definition oval:com.oracle.elsa:def:20240811 (OL9 branch): sudo-python-plugin < 0:1.9.5p2-10.el9_3"}},
		},
		{
			Name: "analyze/golang/Rancher verdicts scoped to the SBOM root", Endpoint: epAnalyze,
			Body: body{"sbom": trivySBOM(opaRoot, ss(xnet, otel),
				sbomVuln{"CVE-2025-22870", ss(xnet)}, sbomVuln{"CVE-2025-22872", ss(xnet)}, sbomVuln{"CVE-2026-39883", ss(otel)})},
			Status: 200, Rows: 3,
			Vulns: []Vuln{
				{ID: "CVE-2025-22870", State: "not_affected", Justification: "code_not_present", Affects: ss(link(xnet)), Evidence: evOPANet},
				{ID: "CVE-2025-22872", State: "not_affected", Justification: "code_not_present", Affects: ss(link(xnet)),
					Evidence: evOPANet22872},
				{ID: "CVE-2026-39883", State: "not_affected", Justification: "code_not_present", Affects: ss(link(otel)),
					Evidence: "RV pkg/golang/github.com/open-policy-agent/opa/scan.openvex.json statements[4]: CVE-2026-39883, otel/sdk@v1.40.0, vulnerable_code_not_present"},
			},
		},
		{
			Name: "analyze/golang/Rancher verdicts withheld under another root", Endpoint: epAnalyze,
			Body:   body{"sbom": trivySBOM(image, ss(xnet), sbomVuln{"CVE-2025-22870", ss(xnet)})},
			Status: 200, Rows: 0,
			Vulns: []Vuln{{ID: "CVE-2025-22870", Affects: ss(link(xnet)), Evidence: evOPANet + " — scoped to the opa module, not to this image: no analysis"}},
		},
		{
			Name: "analyze/apk/an SBOM with no vulnerabilities is filled from broad mode", Endpoint: epAnalyze,
			Body:   body{"sbom": trivySBOM(image, ss(socat, libdwarf))},
			Status: 200, Rows: 3,
			Vulns: []Vuln{
				{ID: "CVE-2015-8538", State: "resolved", Affects: ss(link(libdwarf)), Evidence: "AS v3.22/main.json package libdwarf: secfixes \"0.6.0-r0\"; 0.9.2-r0 is above it"},
				{ID: "CVE-2019-14249", State: "resolved", Affects: ss(link(libdwarf)), Evidence: "AS v3.22/main.json package libdwarf: secfixes \"0.6.0-r0\"; 0.9.2-r0 is above it"},
				{ID: "CVE-2024-54661", State: "not_affected", Justification: "code_not_present", Affects: ss(link(socat)), Evidence: "AS v3.22/main.json package socat: secfixes \"0\""},
				// socat secfixes "1.8.1.2-r0": [CVE-2026-56123]: the SBOM's
				// 1.8.0.3-r0 is below the fixed-in version, so the CVE is not
				// synthesised.
			},
		},
		// CycloneDX analysis vocabulary (pkg/api: under_investigation ->
		// in_triage; component_not_present and vulnerable_code_not_present ->
		// code_not_present; vulnerable_code_not_in_execute_path ->
		// code_not_reachable).
		{
			Name: "analyze/mapping/under_investigation is in_triage", Endpoint: epAnalyze,
			Body:   body{"sbom": trivySBOM(image, ss(libXi), sbomVuln{"CVE-2026-94282", ss(libXi)})},
			Status: 200, Rows: 1,
			Vulns: []Vuln{{ID: "CVE-2026-94282", State: "in_triage", Affects: ss(link(libXi)),
				Evidence: "RH 2026/cve-2026-94282.json product_status.under_investigation: red_hat_enterprise_linux_10:libXi.src"}},
		},
		{
			Name: "analyze/mapping/component_not_present is code_not_present", Endpoint: epAnalyze,
			Body:   body{"sbom": trivySBOM(image, ss(libxsmm), sbomVuln{"CVE-2018-20543", ss(libxsmm)})},
			Status: 200, Rows: 1,
			Vulns: []Vuln{{ID: "CVE-2018-20543", State: "not_affected", Justification: "code_not_present", Affects: ss(link(libxsmm)),
				Evidence: "UV vex/cve/2018/CVE-2018-20543.json statements[0] not_affected/component_not_present: libxsmm-dev@1.9-1 amd64 focal"}},
		},
		{
			// Also the deb distro-stripped candidate on the analyze path: the
			// Rancher subcomponent has no distro.
			Name: "analyze/mapping/vulnerable_code_not_in_execute_path is code_not_reachable", Endpoint: epAnalyze,
			Body:   body{"sbom": trivySBOM(kubeOVNRoot, ss(inetutils), sbomVuln{"CVE-2026-24061", ss(inetutils)})},
			Status: 200, Rows: 1,
			Vulns: []Vuln{{ID: "CVE-2026-24061", State: "not_affected", Justification: "code_not_reachable", Affects: ss(link(inetutils)), Evidence: evKubeOVN}},
		},

		// The rollup when vendor rows disagree: pkg/api annotateSBOM keeps the
		// most actionable state over every matched row of the CVE
		// (not_affected > resolved > in_triage > exploitable).
		{
			Name: "analyze/exact/the version's own verdict", Endpoint: epAnalyze,
			Body:   body{"sbom": trivySBOM(image, ss(microcodeAffected), sbomVuln{"CVE-2022-33972", ss(microcodeAffected)})},
			Status: 200, Rows: 3,
			Vulns: []Vuln{{ID: "CVE-2022-33972", State: "exploitable", Affects: ss(link(microcodeAffected)), Evidence: evMicrocodeAffected}},
		},
		{
			Name: "analyze/exact/an unlisted version leaves no analysis", Endpoint: epAnalyze,
			Body:   body{"sbom": trivySBOM(image, ss(microcodeUnlisted), sbomVuln{"CVE-2022-33972", ss(microcodeUnlisted)})},
			Status: 200, Rows: 0,
			Vulns: []Vuln{{ID: "CVE-2022-33972", Affects: ss(link(microcodeUnlisted)),
				Evidence: "UV vex/cve/2022/CVE-2022-33972.json lists intel-microcode on 16.04 only at 3.20210216.0ubuntu0.16.04.1 and 3.20260210.0ubuntu0.16.04.1+esm1"}},
		},
		{
			Name: "analyze/rollup/SUSE not_affected without justification and fixed", Endpoint: epAnalyze,
			Body:   body{"sbom": trivySBOM(image, ss(mongodb), sbomVuln{"CVE-2017-15535", ss(mongodb)})},
			Status: 200, Rows: 2,
			Vulns: []Vuln{{ID: "CVE-2017-15535", State: "not_affected", Affects: ss(link(mongodb)),
				Evidence: "SUSE cve-2017-15535.json known_not_affected ...:mongodb (no flag, so no justification) and recommended mongodb-3.4.10-5.1"}},
		},
		{
			Name: "analyze/rollup/Red Hat fixed, affected and not_affected streams", Endpoint: epAnalyze,
			Body:   body{"sbom": trivySBOM(image, ss(microcodeCtl), sbomVuln{"CVE-2025-20012", ss(microcodeCtl)})},
			Status: 200, Rows: 26,
			Vulns: []Vuln{{ID: "CVE-2025-20012", State: "not_affected", Justification: "code_not_present", Affects: ss(link(microcodeCtl)),
				Evidence: "RH 2025/cve-2025-20012.json: 22 microcode_ctl PURLs fixed, microcode_ctl(.src) known_affected on RHEL 6 and known_not_affected (vulnerable_code_not_present) on RHEL 10"}},
		},

		// Debian OVAL names source packages; Trivy's components are binary
		// packages with the source in aquasecurity:trivy:SrcName.
		{
			Name: "analyze/deb/a Debian binary package answers for its source package", Endpoint: epAnalyze,
			Body: body{"sbom": withProperties(trivySBOM(image, ss(zlib1gDebian), sbomVuln{"CVE-2022-37434", ss(zlib1gDebian)}), zlib1gDebian, map[string]string{
				"aquasecurity:trivy:PkgType": "debian", "aquasecurity:trivy:SrcName": "zlib", "aquasecurity:trivy:SrcVersion": "1.2.13.dfsg",
				"aquasecurity:trivy:SrcRelease": "1", "aquasecurity:trivy:SrcEpoch": "1"})},
			Status: 200, Rows: 1,
			Vulns: []Vuln{{ID: "CVE-2022-37434", State: "resolved", Affects: ss(link(zlib1gDebian)),
				Evidence: "DO definition oval:org.debian:def:118596735315433746990801407057633161948 (CVE-2022-37434 zlib, the source package zlib1g is built from): evr less than 1:1.2.11.dfsg-4.1"}},
		},
		{
			Name: "statements/sbom/a Debian binary package answers for its source package", Endpoint: epStatements,
			Body: body{"sbom": withProperties(trivySBOM(debianImage, ss(zlib1gDeb12), sbomVuln{"CVE-2022-37434", ss(zlib1gDeb12)}),
				zlib1gDeb12, trivySource("zlib", "1.2.13.dfsg", "1", "1"))},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2022-37434", Supplier: "debian", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", "via_source_package"),
				Products: ss(zlib1gDeb12),
				Evidence: "DO definition oval:org.debian:def:118596735315433746990801407057633161948 (CVE-2022-37434 zlib): evr less than 1:1.2.11.dfsg-4.1; zlib1g is built from zlib 1:1.2.13.dfsg-1 (Trivy 0.74.0 debian:12 SrcName/SrcVersion/SrcRelease/SrcEpoch), above it; answered under the binary as sent, the identifier Trivy applies VEX to"}},
		},
		{
			Name: "statements/sbom/two binaries of one source package are each echoed", Endpoint: epStatements,
			Body:   body{"sbom": libcPair()},
			Status: 200, Rows: 1, Headers: map[string]string{"X-Reel-Mode": "broad"},
			Want: []Stmt{{CVE: "CVE-1999-0199", Supplier: "debian", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", "via_source_package"),
				Products: ss(libcBin, libc6),
				Evidence: "DO definition oval:org.debian:def:302398480618719661759273474285073383836 (CVE-1999-0199 glibc): glibc DPKG is earlier than 2.2-1 (evr 0:2.2-1); libc6 and libc-bin are both built from glibc 2.36-9+deb12u14 (Trivy 0.74.0 debian:12), above it"}},
		},
		{
			Name: "analyze/deb/two binaries of one source package are each affected", Endpoint: epAnalyze,
			Body:   body{"sbom": libcPair()},
			Status: 200, Rows: 1,
			Vulns: []Vuln{{ID: "CVE-1999-0199", State: "resolved", Affects: ss(link(libc6), link(libcBin)),
				Evidence: "DO definition oval:org.debian:def:302398480618719661759273474285073383836 (CVE-1999-0199 glibc): glibc < 2.2-1, synthesised for each binary built from glibc"}},
		},
		{
			// Ubuntu's feeds name binaries (the USN OVAL lists binary packages;
			// Canonical's OpenVEX lists binaries and sources as exact builds), so
			// a source name in an Ubuntu SBOM adds nothing: not the exact
			// zlib@1:1.2.11.dfsg-2ubuntu9.2?arch=source row.
			Name: "statements/sbom/exact: an Ubuntu source package admits nothing", Endpoint: epStatements,
			Body: body{"sbom": withProperties(trivySBOM(image, ss(zlib1g), sbomVuln{"CVE-2022-37434", ss(zlib1g)}),
				zlib1g, trivySource("zlib", "1.2.11.dfsg", "2ubuntu9.2", "1"))},
			Status: 200, Rows: 7,
			Want: []Stmt{{CVE: "CVE-2022-37434", Supplier: "ubuntu", Status: "fixed", Timestamp: tsUV37434, Notes: notes("openvex", "direct"),
				Products: withEpoch(archesAt("pkg:deb/ubuntu/zlib1g@1.2.11.dfsg-2ubuntu9.2", "ubuntu-22.04", "amd64", "arm64", "armhf", "i386", "ppc64el", "riscv64", "s390x"), "1"),
				Evidence: "UV vex/cve/2022/CVE-2022-37434.json statements[0] fixed: zlib1g@1:1.2.11.dfsg-2ubuntu9.2 distro=jammy (7 arches); the same statement's zlib@1:1.2.11.dfsg-2ubuntu9.2?arch=source&distro=jammy is not returned"}},
		},

		// User VEX (docs/api.md, "User-VEX merge semantics").
		{
			Name: "analyze/user_vex/a user statement overrides the vendor's on (cve, base_id)", Endpoint: epAnalyze,
			Body: body{
				"sbom":     trivySBOM(image, ss(socat), sbomVuln{"CVE-2026-56123", ss(socat)}, sbomVuln{"CVE-2024-54661", ss(socat)}),
				"user_vex": []any{userVEX("CVE-2026-56123", socatUser, "affected", "", "acme", "2026-10-01T00:00:00Z")},
			},
			Status: 200, Rows: 2,
			Vulns: []Vuln{
				{ID: "CVE-2026-56123", State: "exploitable", Affects: ss(link(socat)),
					Evidence: "the user's affected (base pkg:apk/alpine/socat?distro=alpine-3.22) collides with AS v3.22/main.json socat secfixes \"1.8.1.2-r0\" and overrides it"},
				{ID: "CVE-2024-54661", State: "not_affected", Justification: "code_not_present", Affects: ss(link(socat)),
					Evidence: "AS v3.22/main.json package socat: secfixes \"0\": [CVE-2024-54661]; no user statement"},
			},
		},
		{
			Name: "analyze/user_vex/user VEX only answers OpenVEX, supplier passed through", Endpoint: epAnalyze,
			Body:   body{"user_vex": []any{userVEX("CVE-2026-56123", socatUser, "not_affected", "inline_mitigations_already_exist", "acme", "2026-10-01T00:00:00Z")}},
			Status: 200, Rows: 1, Headers: map[string]string{"X-Reel-Grouped": "1"},
			Want: []Stmt{{CVE: "CVE-2026-56123", Supplier: "acme", Status: "not_affected", Justification: "inline_mitigations_already_exist", Timestamp: "2026-10-01T00:00:00Z",
				Notes: "match_reason=from_user_vex", Products: ss(socatUser),
				Evidence: "the request's user_vex statement; the vendor row on the same (cve, base_id) (AS socat \"1.8.1.2-r0\") is overridden"}},
		},

		// Trivy-shaped AL2 component (distro "amazon-2 (Karoo)", percent-encoded).
		{
			Name: "analyze/rpm/Trivy AL2 distro", Endpoint: epAnalyze,
			Body: body{"sbom": trivySBOM(image, ss("pkg:rpm/amazon/ca-certificates@2021.2.50-72.amzn2.0.5?arch=noarch&distro=amazon-2%20%28Karoo%29"),
				sbomVuln{"CVE-2022-23491", ss("pkg:rpm/amazon/ca-certificates@2021.2.50-72.amzn2.0.5?arch=noarch&distro=amazon-2%20%28Karoo%29")})},
			Status: 200, Rows: 1,
			Vulns: []Vuln{{ID: "CVE-2022-23491", State: "resolved", Affects: ss(link("pkg:rpm/amazon/ca-certificates@2021.2.50-72.amzn2.0.5?arch=noarch&distro=amazon-2%20%28Karoo%29")),
				Evidence: "AL amzn2 updateinfo <update> ALAS2-2023-1957: ca-certificates"}},
		},
		{
			Name: "statements/sbom/exact: the SBOM root opts in its scoped rows", Endpoint: epStatements,
			Body:   body{"sbom": trivySBOM(sachetRoot, ss(zlibApk), sbomVuln{"CVE-2022-37434", ss(zlibApk)})},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2022-37434", Supplier: "rancher", Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path",
				Timestamp: tsRVSachet, Notes: scoped(notes("openvex", "direct"), scopeSachetDocker), Products: ss("pkg:apk/alpine/zlib"),
				Evidence: evSachetDocker + " (no version: an empty list, rendered as the vendor's product_id: docs/api.md, Versioned queries)"}},
		},
	}
}
