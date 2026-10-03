//go:build integration

package acceptance

// Canonical OpenVEX: entries of security-metadata.canonical.com/vex/vex-all.tar.xz
// ("UV <entry>" below). Every statement carries its own timestamp. Canonical's
// distro qualifier names a release by codename, with or without a support track
// (esm-apps/, esm-infra/, esm-infra-legacy/, fips/, fips-updates/, ...); the hub
// serves it in the scanner convention ubuntu-<version> (CLAUDE.md, config.yaml).
//
// Phase 5 replaces today's version-blind answer to a product query (every row of
// the versionless package, echoed under the caller's base identifier) with the
// verdict Canonical stated for the version asked about, under the vendor's own
// per-version identifiers (PLAN-VEX-SWEEP.md §2, "Version lists per verdict").
// The cases marked Superseded hold today's answer and go when Phase 5 lands.

const (
	tsUV2060  = "2022-06-13T09:15:00Z" // UV vex/cve/2022/CVE-2022-2060.json statements[0].timestamp
	tsUV9571  = "2017-03-07T15:59:00Z" // UV vex/cve/2016/CVE-2016-9571.json statements[*].timestamp
	tsUV20543 = "2018-12-28T16:29:00Z" // UV vex/cve/2018/CVE-2018-20543.json statements[0].timestamp
	tsUV33972 = "2023-02-16T21:15:00Z" // UV vex/cve/2022/CVE-2022-33972.json statements[*].timestamp
	tsUV37434 = "2022-08-05T07:15:00Z" // UV vex/cve/2022/CVE-2022-37434.json statements[*].timestamp
	tsUV41990 = "2026-04-23T05:16:00Z" // UV vex/cve/2026/CVE-2026-41990.json statements[*].timestamp
	tsUV21180 = "2022-06-15T21:15:00Z" // UV vex/cve/2022/CVE-2022-21180.json statements[0].timestamp
)

var (
	uvMicrocode1604Affected = ss(
		"pkg:deb/ubuntu/intel-microcode@3.20210216.0ubuntu0.16.04.1?arch=amd64&distro=ubuntu-16.04",
		"pkg:deb/ubuntu/intel-microcode@3.20210216.0ubuntu0.16.04.1?arch=i386&distro=ubuntu-16.04",
		"pkg:deb/ubuntu/intel-microcode@3.20210216.0ubuntu0.16.04.1?arch=source&distro=ubuntu-16.04")
	uvMicrocode1604Fixed = ss(
		"pkg:deb/ubuntu/intel-microcode@3.20260210.0ubuntu0.16.04.1+esm1?arch=amd64&distro=ubuntu-16.04",
		"pkg:deb/ubuntu/intel-microcode@3.20260210.0ubuntu0.16.04.1+esm1?arch=i386&distro=ubuntu-16.04",
		"pkg:deb/ubuntu/intel-microcode@3.20260210.0ubuntu0.16.04.1+esm1?arch=source&distro=ubuntu-16.04")
)

// archesAt renders a versioned package at each architecture of one release.
func archesAt(pkgAtVersion, distro string, arches ...string) []string {
	out := make([]string, 0, len(arches))
	for _, a := range arches {
		out = append(out, pkgAtVersion+"?arch="+a+"&distro="+distro)
	}
	return out
}

var gcryptArches = ss("amd64", "amd64v3", "arm64", "armhf", "i386", "ppc64el", "riscv64", "s390x", "source")

const (
	evGcryptResolute     = "UV vex/cve/2026/CVE-2026-41990.json statements[0] fixed: libgcrypt20@1.12.0-2ubuntu1.1 distro=resolute (9 arches incl. source)"
	evGcryptQuesting     = "UV vex/cve/2026/CVE-2026-41990.json statements[1] not_affected: libgcrypt20@1.11.0-7ubuntu0.1 distro=questing (9 arches incl. source)"
	evMicrocodeAffected  = "UV vex/cve/2022/CVE-2022-33972.json statements[1] affected: intel-microcode@3.20210216.0ubuntu0.16.04.1 distro=xenial (source, amd64, i386)"
	evMicrocode1804Fixed = "UV vex/cve/2022/CVE-2022-33972.json statements[0] fixed: intel-microcode@3.20230214.0ubuntu0.18.04.1 distro=bionic (source, amd64, i386)"
	ev21180Bionic        = "UV vex/cve/2022/CVE-2022-21180.json statements[0] not_affected: intel-microcode@3.20260210.0ubuntu0.18.04.1+esm1 distro=esm-infra/bionic (source, amd64, i386)"
	evMicrocodeFixed     = "UV vex/cve/2022/CVE-2022-33972.json statements[0] fixed: intel-microcode@3.20260210.0ubuntu0.16.04.1+esm1 distro=esm-infra/xenial (source, amd64, i386)"
)

func uvMicrocode(status, notes, ev string, products []string) Stmt {
	return Stmt{CVE: "CVE-2022-33972", Supplier: "ubuntu", Status: status, Timestamp: tsUV33972, Notes: notes, Products: products, Evidence: ev}
}

func ubuntuCases() []Case {
	echo1604 := ss("pkg:deb/ubuntu/intel-microcode?distro=ubuntu-16.04")
	direct := notes("openvex", "direct")
	return []Case{
		{
			Name: "ubuntu/cve-only/under_investigation on an esm-apps-legacy track", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2022-2060")}, Status: 200, Rows: 7,
			Want: []Stmt{{CVE: "CVE-2022-2060", Supplier: "ubuntu", Status: "under_investigation", Timestamp: tsUV2060, Notes: notes("openvex", ""),
				Products: ss(
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=amd64&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=arm64&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=armhf&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=i386&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=ppc64el&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=s390x&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=source&distro=ubuntu-16.04"),
				Evidence: "UV vex/cve/2022/CVE-2022-2060.json statements[0] under_investigation, 7 products distro=esm-apps-legacy/xenial"}},
		},
		{
			Name: "ubuntu/cve-only/affected and not_affected at two versions of one release", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2016-9571")}, Status: 200, Rows: 15,
			Want: []Stmt{
				{CVE: "CVE-2016-9571", Supplier: "ubuntu", Status: "affected", Timestamp: tsUV9571, Notes: notes("openvex", ""),
					Products: ss(
						"pkg:deb/ubuntu/libresteasy-java@3.0.6-3?arch=amd64&distro=ubuntu-16.04",
						"pkg:deb/ubuntu/libresteasy-java@3.0.6-3?arch=arm64&distro=ubuntu-16.04",
						"pkg:deb/ubuntu/libresteasy-java@3.0.6-3?arch=armhf&distro=ubuntu-16.04",
						"pkg:deb/ubuntu/libresteasy-java@3.0.6-3?arch=i386&distro=ubuntu-16.04",
						"pkg:deb/ubuntu/libresteasy-java@3.0.6-3?arch=powerpc&distro=ubuntu-16.04",
						"pkg:deb/ubuntu/libresteasy-java@3.0.6-3?arch=ppc64el&distro=ubuntu-16.04",
						"pkg:deb/ubuntu/libresteasy-java@3.0.6-3?arch=s390x&distro=ubuntu-16.04",
						"pkg:deb/ubuntu/resteasy@3.0.6-3?arch=source&distro=ubuntu-16.04"),
					Evidence: "UV vex/cve/2016/CVE-2016-9571.json statements[0] affected, 8 products distro=xenial"},
				{CVE: "CVE-2016-9571", Supplier: "ubuntu", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: tsUV9571, Notes: notes("openvex", ""),
					Products: ss(
						"pkg:deb/ubuntu/libresteasy-java@3.0.6-3ubuntu0.1~esm1?arch=amd64&distro=ubuntu-16.04",
						"pkg:deb/ubuntu/libresteasy-java@3.0.6-3ubuntu0.1~esm1?arch=arm64&distro=ubuntu-16.04",
						"pkg:deb/ubuntu/libresteasy-java@3.0.6-3ubuntu0.1~esm1?arch=armhf&distro=ubuntu-16.04",
						"pkg:deb/ubuntu/libresteasy-java@3.0.6-3ubuntu0.1~esm1?arch=i386&distro=ubuntu-16.04",
						"pkg:deb/ubuntu/libresteasy-java@3.0.6-3ubuntu0.1~esm1?arch=ppc64el&distro=ubuntu-16.04",
						"pkg:deb/ubuntu/libresteasy-java@3.0.6-3ubuntu0.1~esm1?arch=s390x&distro=ubuntu-16.04",
						"pkg:deb/ubuntu/resteasy@3.0.6-3ubuntu0.1~esm1?arch=source&distro=ubuntu-16.04"),
					Evidence: "UV vex/cve/2016/CVE-2016-9571.json statements[1] not_affected/vulnerable_code_not_present, 7 products distro=esm-apps/xenial"},
			},
		},
		{
			Name: "ubuntu/cve-only/component_not_present", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2018-20543")}, Status: 200, Rows: 2,
			Want: []Stmt{{CVE: "CVE-2018-20543", Supplier: "ubuntu", Status: "not_affected", Justification: "component_not_present", Timestamp: tsUV20543, Notes: notes("openvex", ""),
				Products: ss("pkg:deb/ubuntu/libxsmm-dev@1.9-1?arch=amd64&distro=ubuntu-20.04", "pkg:deb/ubuntu/libxsmm@1.9-1?arch=source&distro=ubuntu-20.04"),
				Evidence: "UV vex/cve/2018/CVE-2018-20543.json statements[0] not_affected/component_not_present, distro=focal"}},
		},
		{
			Name: "ubuntu/cve-only/fixed and affected across releases and ESM tracks", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2022-33972")}, Status: 200, Rows: 16,
			Want: []Stmt{
				uvMicrocode("fixed", notes("openvex", ""), "UV vex/cve/2022/CVE-2022-33972.json statements[0] fixed: esm-infra/xenial, bionic, focal, jammy", append(ss(
					"pkg:deb/ubuntu/intel-microcode@3.20230214.0ubuntu0.18.04.1?arch=amd64&distro=ubuntu-18.04",
					"pkg:deb/ubuntu/intel-microcode@3.20230214.0ubuntu0.18.04.1?arch=i386&distro=ubuntu-18.04",
					"pkg:deb/ubuntu/intel-microcode@3.20230214.0ubuntu0.18.04.1?arch=source&distro=ubuntu-18.04",
					"pkg:deb/ubuntu/intel-microcode@3.20250512.0ubuntu0.20.04.1?arch=amd64&distro=ubuntu-20.04",
					"pkg:deb/ubuntu/intel-microcode@3.20250512.0ubuntu0.20.04.1?arch=source&distro=ubuntu-20.04",
					"pkg:deb/ubuntu/intel-microcode@3.20260210.0ubuntu0.22.04.1?arch=amd64&distro=ubuntu-22.04",
					"pkg:deb/ubuntu/intel-microcode@3.20260210.0ubuntu0.22.04.1?arch=source&distro=ubuntu-22.04"), uvMicrocode1604Fixed...)),
				uvMicrocode("affected", notes("openvex", ""), "UV vex/cve/2022/CVE-2022-33972.json statements[1] affected: esm-infra-legacy/trusty, xenial", append(ss(
					"pkg:deb/ubuntu/intel-microcode@3.20210608.0ubuntu0.14.04.1+esm1?arch=amd64&distro=ubuntu-14.04",
					"pkg:deb/ubuntu/intel-microcode@3.20210608.0ubuntu0.14.04.1+esm1?arch=i386&distro=ubuntu-14.04",
					"pkg:deb/ubuntu/intel-microcode@3.20210608.0ubuntu0.14.04.1+esm1?arch=source&distro=ubuntu-14.04"), uvMicrocode1604Affected...)),
			},
		},

		// One package, one release, two verdicts at two versions.
		{
			Name: "ubuntu/purl/versioned query is answered version-blind", Superseded: "phase 5", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2022-33972"), "products": ss("pkg:deb/ubuntu/intel-microcode@3.20210216.0ubuntu0.16.04.1?arch=amd64&distro=ubuntu-16.04")},
			Status: 200, Rows: 6,
			Want: []Stmt{uvMicrocode("fixed", direct, evMicrocodeFixed, echo1604), uvMicrocode("affected", direct, evMicrocodeAffected, echo1604)},
		},
		{
			Name: "ubuntu/exact/listed version gets only its own verdict", Pending: "phase 5", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2022-33972"), "products": ss("pkg:deb/ubuntu/intel-microcode@3.20210216.0ubuntu0.16.04.1?arch=amd64&distro=ubuntu-16.04")},
			Status: 200, Rows: 3,
			Want: []Stmt{uvMicrocode("affected", direct, evMicrocodeAffected, uvMicrocode1604Affected)},
		},
		{
			Name: "ubuntu/purl/unlisted version is answered version-blind", Superseded: "phase 5", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2022-33972"), "products": ss("pkg:deb/ubuntu/intel-microcode@3.20230214.0ubuntu0.16.04.1?arch=amd64&distro=ubuntu-16.04")},
			Status: 200, Rows: 6,
			Want: []Stmt{uvMicrocode("fixed", direct, evMicrocodeFixed, echo1604), uvMicrocode("affected", direct, evMicrocodeAffected, echo1604)},
		},
		{
			Name: "ubuntu/exact/unlisted version gets nothing", Pending: "phase 5", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2022-33972"), "products": ss("pkg:deb/ubuntu/intel-microcode@3.20230214.0ubuntu0.16.04.1?arch=amd64&distro=ubuntu-16.04")},
			Status: 204, Rows: 0,
		},
		{
			Name: "ubuntu/purl/versionless query echoes the caller's base", Superseded: "phase 5", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2022-33972"), "products": ss("pkg:deb/ubuntu/intel-microcode?distro=ubuntu-16.04")},
			Status: 200, Rows: 6,
			Want: []Stmt{uvMicrocode("fixed", direct, evMicrocodeFixed, echo1604), uvMicrocode("affected", direct, evMicrocodeAffected, echo1604)},
		},
		{
			Name: "ubuntu/exact/versionless query gets every version under its own verdict", Pending: "phase 5", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2022-33972"), "products": ss("pkg:deb/ubuntu/intel-microcode?distro=ubuntu-16.04")},
			Status: 200, Rows: 6,
			Want: []Stmt{
				uvMicrocode("fixed", direct, evMicrocodeFixed, uvMicrocode1604Fixed),
				uvMicrocode("affected", direct, evMicrocodeAffected, uvMicrocode1604Affected),
			},
		},
		{
			Name: "ubuntu/purl/strict_arch keeps the named arch and source", Superseded: "phase 5", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2022-33972"), "strict_arch": true,
				"products": ss("pkg:deb/ubuntu/intel-microcode@3.20210216.0ubuntu0.16.04.1?arch=amd64&distro=ubuntu-16.04")},
			Status: 200, Rows: 4, Headers: map[string]string{"X-Reel-Arch": "amd64", "X-Reel-Mode": "cve", "X-Reel-CVE": "CVE-2022-33972", "X-Reel-Grouped": "2"},
			Want: []Stmt{uvMicrocode("fixed", direct, evMicrocodeFixed, echo1604), uvMicrocode("affected", direct, evMicrocodeAffected, echo1604)},
		},
		{
			Name: "ubuntu/exact/strict_arch with a version", Pending: "phase 5", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2022-33972"), "strict_arch": true,
				"products": ss("pkg:deb/ubuntu/intel-microcode@3.20210216.0ubuntu0.16.04.1?arch=amd64&distro=ubuntu-16.04")},
			Status: 200, Rows: 2, Headers: map[string]string{"X-Reel-Arch": "amd64"},
			Want: []Stmt{uvMicrocode("affected", direct, evMicrocodeAffected, ss(
				"pkg:deb/ubuntu/intel-microcode@3.20210216.0ubuntu0.16.04.1?arch=amd64&distro=ubuntu-16.04",
				"pkg:deb/ubuntu/intel-microcode@3.20210216.0ubuntu0.16.04.1?arch=source&distro=ubuntu-16.04"))},
		},

		{
			Name: "ubuntu/purl/under_investigation", Superseded: "phase 5", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2022-2060"), "products": ss("pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=amd64&distro=ubuntu-16.04")},
			Status: 200, Rows: 7,
			Want: []Stmt{{CVE: "CVE-2022-2060", Supplier: "ubuntu", Status: "under_investigation", Timestamp: tsUV2060, Notes: direct,
				Products: ss("pkg:deb/ubuntu/dolibarr?distro=ubuntu-16.04"),
				Evidence: "UV vex/cve/2022/CVE-2022-2060.json statements[0] under_investigation: dolibarr@3.5.8+dfsg1-1ubuntu1+esm1 distro=esm-apps-legacy/xenial (7 arches)"}},
		},
		{
			Name: "ubuntu/exact/under_investigation at a listed version", Pending: "phase 5", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2022-2060"), "products": ss("pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=amd64&distro=ubuntu-16.04")},
			Status: 200, Rows: 7,
			Want: []Stmt{{CVE: "CVE-2022-2060", Supplier: "ubuntu", Status: "under_investigation", Timestamp: tsUV2060, Notes: direct,
				Products: ss(
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=amd64&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=arm64&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=armhf&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=i386&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=ppc64el&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=s390x&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=source&distro=ubuntu-16.04"),
				Evidence: "UV vex/cve/2022/CVE-2022-2060.json statements[0] under_investigation: dolibarr@3.5.8+dfsg1-1ubuntu1+esm1 distro=esm-apps-legacy/xenial (7 arches)"}},
		},

		{
			Name: "ubuntu/exact/a base asked with and without a version keeps its whole list", Pending: "phase 5", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2022-33972"), "products": ss(
				"pkg:deb/ubuntu/intel-microcode@3.20210216.0ubuntu0.16.04.1?arch=amd64&distro=ubuntu-16.04",
				"pkg:deb/ubuntu/intel-microcode?distro=ubuntu-16.04")},
			Status: 200, Rows: 6,
			Want: []Stmt{
				uvMicrocode("fixed", direct, evMicrocodeFixed+" (PLAN-VEX-SWEEP.md Phase 5 step 3: a base asked both with and without a version keeps its whole list)", uvMicrocode1604Fixed),
				uvMicrocode("affected", direct, evMicrocodeAffected, uvMicrocode1604Affected),
			},
		},
		{
			// Trivy percent-encodes "+" in a version (packageurl-go escapes
			// every byte outside the unreserved set).
			Name: "ubuntu/exact/a %2B-encoded version matches the vendor's +", Pending: "phase 5", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2022-2060"), "products": ss("pkg:deb/ubuntu/dolibarr@3.5.8%2Bdfsg1-1ubuntu1%2Besm1?arch=amd64&distro=ubuntu-16.04")},
			Status: 200, Rows: 7,
			Want: []Stmt{{CVE: "CVE-2022-2060", Supplier: "ubuntu", Status: "under_investigation", Timestamp: tsUV2060, Notes: direct,
				Products: ss(
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=amd64&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=arm64&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=armhf&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=i386&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=ppc64el&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=s390x&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=source&distro=ubuntu-16.04"),
				Evidence: "UV vex/cve/2022/CVE-2022-2060.json statements[0]: dolibarr@3.5.8+dfsg1-1ubuntu1+esm1 (PLAN-VEX-SWEEP.md Phase 5 step 3: compare after url.PathUnescape on both sides)"}},
		},

		// Two CVEs list intel-microcode on 18.04 at different versions:
		// CVE-2022-33972 fixed at 3.20230214.0ubuntu0.18.04.1, CVE-2022-21180
		// not_affected at 3.20260210.0ubuntu0.18.04.1+esm1.
		{
			Name: "ubuntu/purl/one package in two CVEs is answered version-blind", Superseded: "phase 5", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2022-33972", "CVE-2022-21180"),
				"products": ss("pkg:deb/ubuntu/intel-microcode@3.20230214.0ubuntu0.18.04.1?arch=amd64&distro=ubuntu-18.04")},
			Status: 200, Rows: 6, Headers: map[string]string{"X-Reel-CVE": ""},
			Want: []Stmt{
				uvMicrocode("fixed", direct, evMicrocode1804Fixed, ss("pkg:deb/ubuntu/intel-microcode?distro=ubuntu-18.04")),
				{CVE: "CVE-2022-21180", Supplier: "ubuntu", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: tsUV21180, Notes: direct,
					Products: ss("pkg:deb/ubuntu/intel-microcode?distro=ubuntu-18.04"), Evidence: ev21180Bionic},
			},
		},
		{
			Name: "ubuntu/exact/one CVE's listed version never matches another CVE's row", Pending: "phase 5", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2022-33972", "CVE-2022-21180"),
				"products": ss("pkg:deb/ubuntu/intel-microcode@3.20230214.0ubuntu0.18.04.1?arch=amd64&distro=ubuntu-18.04")},
			Status: 200, Rows: 3,
			Want: []Stmt{uvMicrocode("fixed", direct, evMicrocode1804Fixed+" (PLAN-VEX-SWEEP.md Phase 5 step 3: a caller version matches a row only through that row's own (cve, versionless product, qualifiers))",
				archesAt("pkg:deb/ubuntu/intel-microcode@3.20230214.0ubuntu0.18.04.1", "ubuntu-18.04", "amd64", "i386", "source"))},
		},

		// The two newest codenames in the hub's map.
		{
			Name: "ubuntu/purl/resolute (26.04) and questing (25.10)", Superseded: "phase 5", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2026-41990"), "products": ss(
				"pkg:deb/ubuntu/libgcrypt20@1.12.0-2ubuntu1.1?arch=amd64&distro=ubuntu-26.04",
				"pkg:deb/ubuntu/libgcrypt20@1.11.0-7ubuntu0.1?arch=amd64&distro=ubuntu-25.10")},
			Status: 200, Rows: 18,
			Want: []Stmt{
				{CVE: "CVE-2026-41990", Supplier: "ubuntu", Status: "fixed", Timestamp: tsUV41990, Notes: direct,
					Products: ss("pkg:deb/ubuntu/libgcrypt20?distro=ubuntu-26.04"), Evidence: evGcryptResolute},
				{CVE: "CVE-2026-41990", Supplier: "ubuntu", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: tsUV41990, Notes: direct,
					Products: ss("pkg:deb/ubuntu/libgcrypt20?distro=ubuntu-25.10"), Evidence: evGcryptQuesting},
			},
		},
		{
			Name: "ubuntu/exact/resolute (26.04) and questing (25.10)", Pending: "phase 5", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2026-41990"), "products": ss(
				"pkg:deb/ubuntu/libgcrypt20@1.12.0-2ubuntu1.1?arch=amd64&distro=ubuntu-26.04",
				"pkg:deb/ubuntu/libgcrypt20@1.11.0-7ubuntu0.1?arch=amd64&distro=ubuntu-25.10")},
			Status: 200, Rows: 18,
			Want: []Stmt{
				{CVE: "CVE-2026-41990", Supplier: "ubuntu", Status: "fixed", Timestamp: tsUV41990, Notes: direct,
					Products: archesAt("pkg:deb/ubuntu/libgcrypt20@1.12.0-2ubuntu1.1", "ubuntu-26.04", gcryptArches...), Evidence: evGcryptResolute},
				{CVE: "CVE-2026-41990", Supplier: "ubuntu", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: tsUV41990, Notes: direct,
					Products: archesAt("pkg:deb/ubuntu/libgcrypt20@1.11.0-7ubuntu0.1", "ubuntu-25.10", gcryptArches...), Evidence: evGcryptQuesting},
			},
		},

		// FIPS tracks of one release fold onto ubuntu-20.04.
		{
			Name: "ubuntu/purl/fips and fips-updates tracks normalise to the release", Superseded: "phase 5", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2026-41990"), "products": ss("pkg:deb/ubuntu/libgcrypt20@1.8.5-5ubuntu1.fips.1.7?arch=amd64&distro=ubuntu-20.04")},
			Status: 200, Rows: 6,
			Want: []Stmt{{CVE: "CVE-2026-41990", Supplier: "ubuntu", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: tsUV41990, Notes: direct,
				Products: ss("pkg:deb/ubuntu/libgcrypt20?distro=ubuntu-20.04"),
				Evidence: "UV vex/cve/2026/CVE-2026-41990.json statements[1] not_affected: libgcrypt20@1.8.5-5ubuntu1.fips.1.4 distro=fips/focal and @...fips.1.7 distro=fips-updates/focal (source, amd64, s390x)"}},
		},
		{
			Name: "ubuntu/exact/fips-updates version", Pending: "phase 5", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2026-41990"), "products": ss("pkg:deb/ubuntu/libgcrypt20@1.8.5-5ubuntu1.fips.1.7?arch=amd64&distro=ubuntu-20.04")},
			Status: 200, Rows: 3,
			Want: []Stmt{{CVE: "CVE-2026-41990", Supplier: "ubuntu", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: tsUV41990, Notes: direct,
				Products: ss(
					"pkg:deb/ubuntu/libgcrypt20@1.8.5-5ubuntu1.fips.1.7?arch=amd64&distro=ubuntu-20.04",
					"pkg:deb/ubuntu/libgcrypt20@1.8.5-5ubuntu1.fips.1.7?arch=s390x&distro=ubuntu-20.04",
					"pkg:deb/ubuntu/libgcrypt20@1.8.5-5ubuntu1.fips.1.7?arch=source&distro=ubuntu-20.04"),
				Evidence: "UV vex/cve/2026/CVE-2026-41990.json statements[1] not_affected: libgcrypt20@1.8.5-5ubuntu1.fips.1.7 distro=fips-updates/focal (source, amd64, s390x)"}},
		},

		// Trivy writes the deb epoch as a qualifier; Canonical writes it inline.
		{
			Name: "ubuntu/purl/Trivy epoch qualifier", Superseded: "phase 5", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2022-37434"), "products": ss("pkg:deb/ubuntu/zlib1g@1.2.11.dfsg-2ubuntu9.2?arch=amd64&distro=ubuntu-22.04&epoch=1")},
			Status: 200, Rows: 7,
			Want: []Stmt{{CVE: "CVE-2022-37434", Supplier: "ubuntu", Status: "fixed", Timestamp: tsUV37434, Notes: direct,
				Products: ss("pkg:deb/ubuntu/zlib1g?distro=ubuntu-22.04"),
				Evidence: "UV vex/cve/2022/CVE-2022-37434.json statements[0] fixed: zlib1g@1:1.2.11.dfsg-2ubuntu9.2 distro=jammy (7 arches)"}},
		},
		{
			Name: "ubuntu/exact/Trivy epoch qualifier folds into the version", Pending: "phase 5", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2022-37434"), "products": ss("pkg:deb/ubuntu/zlib1g@1.2.11.dfsg-2ubuntu9.2?arch=amd64&distro=ubuntu-22.04&epoch=1")},
			Status: 200, Rows: 7,
			Want: []Stmt{{CVE: "CVE-2022-37434", Supplier: "ubuntu", Status: "fixed", Timestamp: tsUV37434, Notes: direct,
				Products: ss(
					"pkg:deb/ubuntu/zlib1g@1:1.2.11.dfsg-2ubuntu9.2?arch=amd64&distro=ubuntu-22.04",
					"pkg:deb/ubuntu/zlib1g@1:1.2.11.dfsg-2ubuntu9.2?arch=arm64&distro=ubuntu-22.04",
					"pkg:deb/ubuntu/zlib1g@1:1.2.11.dfsg-2ubuntu9.2?arch=armhf&distro=ubuntu-22.04",
					"pkg:deb/ubuntu/zlib1g@1:1.2.11.dfsg-2ubuntu9.2?arch=i386&distro=ubuntu-22.04",
					"pkg:deb/ubuntu/zlib1g@1:1.2.11.dfsg-2ubuntu9.2?arch=ppc64el&distro=ubuntu-22.04",
					"pkg:deb/ubuntu/zlib1g@1:1.2.11.dfsg-2ubuntu9.2?arch=riscv64&distro=ubuntu-22.04",
					"pkg:deb/ubuntu/zlib1g@1:1.2.11.dfsg-2ubuntu9.2?arch=s390x&distro=ubuntu-22.04"),
				Evidence: "UV vex/cve/2022/CVE-2022-37434.json statements[0] fixed: zlib1g@1:1.2.11.dfsg-2ubuntu9.2 distro=jammy (7 arches)"}},
		},

		// Canonical writes some trusty ESM rows as "trusty/esm": codename first.
		{
			Name: "ubuntu/purl/trusty/esm is Ubuntu 14.04", Superseded: "phase 5", Endpoint: epStatements,
			KnownBug: "ubuntuvex.Normalize takes the last /-segment as the codename; Canonical's distro=trusty/esm (codename first) stays unnormalised, so no ubuntu-14.04 query reaches these rows",
			Body:     body{"cves": ss("CVE-2022-37434"), "products": ss("pkg:deb/ubuntu/klibc-utils@2.0.3-0ubuntu1.14.04.3+esm3?arch=amd64&distro=ubuntu-14.04")},
			Status:   200, Rows: 5,
			Want: []Stmt{{CVE: "CVE-2022-37434", Supplier: "ubuntu", Status: "fixed", Timestamp: tsUV37434, Notes: direct,
				Products: ss("pkg:deb/ubuntu/klibc-utils?distro=ubuntu-14.04"),
				Evidence: "UV vex/cve/2022/CVE-2022-37434.json statements[0] fixed: klibc-utils@2.0.3-0ubuntu1.14.04.3+esm3 distro=trusty/esm (amd64, arm64, armhf, i386, ppc64el)"}},
		},
		{
			Name: "ubuntu/exact/trusty/esm is Ubuntu 14.04", Pending: "phase 5", Endpoint: epStatements,
			KnownBug: "ubuntuvex.Normalize takes the last /-segment as the codename; Canonical's distro=trusty/esm (codename first) stays unnormalised",
			Body:     body{"cves": ss("CVE-2022-37434"), "products": ss("pkg:deb/ubuntu/klibc-utils@2.0.3-0ubuntu1.14.04.3+esm3?arch=amd64&distro=ubuntu-14.04")},
			Status:   200, Rows: 5,
			Want: []Stmt{{CVE: "CVE-2022-37434", Supplier: "ubuntu", Status: "fixed", Timestamp: tsUV37434, Notes: direct,
				Products: ss(
					"pkg:deb/ubuntu/klibc-utils@2.0.3-0ubuntu1.14.04.3+esm3?arch=amd64&distro=ubuntu-14.04",
					"pkg:deb/ubuntu/klibc-utils@2.0.3-0ubuntu1.14.04.3+esm3?arch=arm64&distro=ubuntu-14.04",
					"pkg:deb/ubuntu/klibc-utils@2.0.3-0ubuntu1.14.04.3+esm3?arch=armhf&distro=ubuntu-14.04",
					"pkg:deb/ubuntu/klibc-utils@2.0.3-0ubuntu1.14.04.3+esm3?arch=i386&distro=ubuntu-14.04",
					"pkg:deb/ubuntu/klibc-utils@2.0.3-0ubuntu1.14.04.3+esm3?arch=ppc64el&distro=ubuntu-14.04"),
				Evidence: "UV vex/cve/2022/CVE-2022-37434.json statements[0] fixed: klibc-utils@2.0.3-0ubuntu1.14.04.3+esm3 distro=trusty/esm"}},
		},

		{
			Name: "ubuntu/broad/products only", Superseded: "phase 5", Endpoint: epStatements,
			Body:   body{"products": ss("pkg:deb/ubuntu/libxsmm-dev@1.9-1?arch=amd64&distro=ubuntu-20.04")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2018-20543", Supplier: "ubuntu", Status: "not_affected", Justification: "component_not_present", Timestamp: tsUV20543, Notes: direct,
				Products: ss("pkg:deb/ubuntu/libxsmm-dev?distro=ubuntu-20.04"),
				Evidence: "UV vex/cve/2018/CVE-2018-20543.json statements[0]: libxsmm-dev@1.9-1 arch=amd64 distro=focal (the only document naming libxsmm-dev)"}},
		},
		{
			Name: "ubuntu/exact/broad products only at a listed version", Pending: "phase 5", Endpoint: epStatements,
			Body:   body{"products": ss("pkg:deb/ubuntu/libxsmm-dev@1.9-1?arch=amd64&distro=ubuntu-20.04")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2018-20543", Supplier: "ubuntu", Status: "not_affected", Justification: "component_not_present", Timestamp: tsUV20543, Notes: direct,
				Products: ss("pkg:deb/ubuntu/libxsmm-dev@1.9-1?arch=amd64&distro=ubuntu-20.04"),
				Evidence: "UV vex/cve/2018/CVE-2018-20543.json statements[0]: libxsmm-dev@1.9-1 arch=amd64 distro=focal"}},
		},
		{
			Name: "ubuntu/negative/the same package in a release the vendor did not state", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2018-20543"), "products": ss("pkg:deb/ubuntu/libxsmm-dev@1.9-1?arch=amd64&distro=ubuntu-22.04")},
			Status: 204, Rows: 0,
		},
		{
			Name: "ubuntu/negative/a deb query without distro matches nothing", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2018-20543"), "products": ss("pkg:deb/ubuntu/libxsmm-dev@1.9-1?arch=amd64")},
			Status: 204, Rows: 0,
		},
		{
			Name: "ubuntu/negative/USN-keyed entries are not read (the CVE alias)", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2024-56161")},
			Status: 204, Rows: 0,
		},
		{
			Name: "ubuntu/negative/USN-keyed entries are not read (the USN name)", Endpoint: epStatements,
			Body:   body{"cves": ss("USN-7560-1")},
			Status: 204, Rows: 0,
		},
		{
			// The USN names amd64-microcode with distro=plucky and with no distro;
			// a 25.04 query reaches both shapes (direct and distro-stripped).
			Name: "ubuntu/negative/USN-keyed entries are not read (the package)", Endpoint: epStatements,
			Body:   body{"products": ss("pkg:deb/ubuntu/amd64-microcode@3.20250311.1ubuntu0.25.04.1?arch=amd64&distro=ubuntu-25.04")},
			Status: 204, Rows: 0,
		},
	}
}
