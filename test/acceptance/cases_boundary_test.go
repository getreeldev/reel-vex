//go:build integration

package acceptance

// Boundary rows: Debian, Ubuntu OVAL, Alpine, Amazon, AlmaLinux and
// Oracle state `fixed` with a fixed-in version. A query naming a version gets
// the row only at or above it, in the ecosystem's ordering (dpkg, rpm, apk),
// with an epoch qualifier and an inline epoch read as one and a missing epoch
// as 0, and the row is answered under the identifier the query sent. Below the
// fixed-in version the vendor stated nothing about the version asked about, so
// nothing is answered.

func boundaryCases() []Case {
	fixed := func(cve, supplier, ts, format, product, ev string) []Stmt {
		return []Stmt{{CVE: cve, Supplier: supplier, Status: "fixed", Timestamp: ts, Notes: notes(format, "direct"), Products: ss(product), Evidence: ev}}
	}
	statements := func(name, cve, product string, want []Stmt) Case {
		c := Case{Name: name, Endpoint: epStatements, Body: body{"cves": ss(cve), "products": ss(product)}, Status: 204}
		if want != nil {
			c.Status, c.Rows, c.Want = 200, 1, want
		}
		return c
	}

	// DO definition ...def:118596735315433746990801407057633161948
	// (CVE-2022-37434 zlib): evr less than 1:1.2.11.dfsg-4.1.
	const evZlib = "DO definition oval:org.debian:def:118596735315433746990801407057633161948 (CVE-2022-37434 zlib): evr less than 1:1.2.11.dfsg-4.1"
	zlibAt := "pkg:deb/debian/zlib@1.2.11.dfsg-4.1?arch=source&distro=debian-12&epoch=1"
	zlibAbove := "pkg:deb/debian/zlib@1.2.13.dfsg-1+deb12u1?arch=source&distro=debian-12&epoch=1"
	// UO definition oval:com.ubuntu.noble:def:675610000000 (USN-6756-1):
	// less < 590-2ubuntu2.1.
	const evLess = "UO definition oval:com.ubuntu.noble:def:675610000000 (USN-6756-1): less < 590-2ubuntu2.1"
	lessAt := "pkg:deb/ubuntu/less@590-2ubuntu2.1?arch=amd64&distro=ubuntu-24.04"
	lessAbove := "pkg:deb/ubuntu/less@590-2ubuntu2.3?arch=amd64&distro=ubuntu-24.04"
	lessEpoch0 := "pkg:deb/ubuntu/less@590-2ubuntu2.1?arch=amd64&distro=ubuntu-24.04&epoch=0"
	const evSocat = "AS v3.22/main.json package socat: secfixes \"1.8.1.2-r0\": [CVE-2026-56123]"
	socatAbove := "pkg:apk/alpine/socat@1.8.1.3-r0?arch=x86_64&distro=3.22.2"
	const evCa = "AL al2023 updateinfo <update> ALAS2023-2023-061: CVE-2022-23491, ca-certificates version 2021.2.50 release 1.0.amzn2023.0.6 epoch 0"
	caAbove := "pkg:rpm/amazon/ca-certificates@2023.2.68-1.0.amzn2023.0.1?arch=noarch&distro=amazon-2023"
	caEpoch := "pkg:rpm/amazon/ca-certificates@2021.2.50-1.0.amzn2023.0.5?arch=noarch&distro=amazon-2023&epoch=1"
	const evSquid = "AO definition oval:org.almalinux.alsa:def:20225527 (ALSA-2022:5527 squid): CVE-2021-46784, squid evr less than 7:5.2-1.el9_0.1"
	squidAbove := "pkg:rpm/alma/squid@5.5-6.el9_3.1?arch=x86_64&distro=alma-9.3&epoch=7"
	const evSudo = "OO definition oval:com.oracle.elsa:def:20240811 (ELSA-2024-0811), \"Oracle Linux 8 is installed\" branch: sudo < 0:1.9.5p2-1.el8_9"
	sudoAbove := "pkg:rpm/oracle/sudo@1.9.15p5-1.el8?arch=x86_64&distro=oracle-8"
	sudoEpoch := "pkg:rpm/oracle/sudo@1.9.5p2-1.el8_8?arch=x86_64&distro=oracle-8&epoch=1"

	// A Debian binary built from zlib below the fixed-in version: Trivy's
	// properties for zlib1g 1:1.2.11.dfsg-2.
	zlib1gOld := "pkg:deb/debian/zlib1g@1.2.11.dfsg-2?arch=amd64&distro=debian-12.15&epoch=1"
	oldSBOM := func(vulns ...sbomVuln) map[string]any {
		return withProperties(trivySBOM(debianImage, ss(zlib1gOld), vulns...), zlib1gOld, trivySource("zlib", "1.2.11.dfsg", "2", "1"))
	}

	return []Case{
		statements("boundary/debian/below the fixed-in version", "CVE-2022-37434",
			"pkg:deb/debian/zlib@1.2.11.dfsg-2?arch=source&distro=debian-12&epoch=1", nil),
		statements("boundary/debian/at it", "CVE-2022-37434", zlibAt,
			fixed("CVE-2022-37434", "debian", tsDay1File, "oval", zlibAt, evZlib+"; the query is 1:1.2.11.dfsg-4.1")),
		statements("boundary/debian/above it", "CVE-2022-37434", zlibAbove,
			fixed("CVE-2022-37434", "debian", tsDay1File, "oval", zlibAbove, evZlib+"; the query is 1:1.2.13.dfsg-1+deb12u1")),
		// The fixed-in version's epoch is 1; a version written without one is
		// epoch 0, below every epoch-1 version.
		statements("boundary/debian/no epoch is epoch 0, below an epoch-1 fix", "CVE-2022-37434",
			"pkg:deb/debian/zlib@1.2.13.dfsg-1?arch=source&distro=debian-12", nil),
		{
			Name: "boundary/debian/a binary below its source package's fix: statements", Endpoint: epStatements,
			Body:   body{"sbom": oldSBOM(sbomVuln{"CVE-2022-37434", ss(zlib1gOld)})},
			Status: 204, Rows: 0,
		},
		{
			Name: "boundary/debian/a binary below its source package's fix: analyze", Endpoint: epAnalyze,
			Body:   body{"sbom": oldSBOM(sbomVuln{"CVE-2022-37434", ss(zlib1gOld)})},
			Status: 200, Rows: 0,
			Vulns: []Vuln{{ID: "CVE-2022-37434", Affects: ss(link(zlib1gOld)),
				Evidence: evZlib + "; zlib1g is built from zlib 1:1.2.11.dfsg-2 (SrcName/SrcVersion/SrcRelease/SrcEpoch), below it: no analysis"}},
		},
		{
			Name: "boundary/debian/a binary below its source package's fix: analyze synthesises nothing", Endpoint: epAnalyze,
			Body:   body{"sbom": oldSBOM()},
			Status: 200, Rows: 0,
		},
		// "statements/sbom/a Debian binary package answers for its source
		// package" and "analyze/deb/a Debian binary package answers for its
		// source package" (cases_query_test.go) are the same binary above it.

		statements("boundary/ubuntu-oval/below the fixed-in version", "CVE-2024-32487",
			"pkg:deb/ubuntu/less@590-2ubuntu2?arch=amd64&distro=ubuntu-24.04", nil),
		statements("boundary/ubuntu-oval/at it", "CVE-2024-32487", lessAt,
			fixed("CVE-2024-32487", "ubuntu", tsDay1File, "oval", lessAt, evLess)),
		statements("boundary/ubuntu-oval/above it", "CVE-2024-32487", lessAbove,
			fixed("CVE-2024-32487", "ubuntu", tsDay1File, "oval", lessAbove, evLess)),
		statements("boundary/ubuntu-oval/epoch=0 is no epoch", "CVE-2024-32487", lessEpoch0,
			fixed("CVE-2024-32487", "ubuntu", tsDay1File, "oval", lessEpoch0, evLess+" (no epoch: 0)")),

		statements("boundary/alpine/below the fixed-in version", "CVE-2026-56123",
			"pkg:apk/alpine/socat@1.8.0.3-r0?arch=x86_64&distro=3.22.2", nil),
		// At it: "alpine/purl/fixed, Trivy three-part distro" (cases_rpm_apk_test.go).
		statements("boundary/alpine/above it", "CVE-2026-56123", socatAbove,
			fixed("CVE-2026-56123", "alpine", tsDay1File, "secdb", socatAbove, evSocat)),
		// apk versions have no epoch. A version apk cannot order is withheld.
		statements("boundary/alpine/a version apk cannot read", "CVE-2026-56123",
			"pkg:apk/alpine/socat@latest?arch=x86_64&distro=3.22.2", nil),

		statements("boundary/amazon/below the fixed-in version", "CVE-2022-23491",
			"pkg:rpm/amazon/ca-certificates@2021.2.50-1.0.amzn2023.0.5?arch=noarch&distro=amazon-2023", nil),
		// At it: "amazon/purl/Trivy point-release AL2023 distro".
		statements("boundary/amazon/above it", "CVE-2022-23491", caAbove,
			fixed("CVE-2022-23491", "amazon", tsALCa2023, "updateinfo", caAbove, evCa)),
		statements("boundary/amazon/an epoch outranks the version", "CVE-2022-23491", caEpoch,
			fixed("CVE-2022-23491", "amazon", tsALCa2023, "updateinfo", caEpoch, evCa+"; the query is 1:2021.2.50-1.0.amzn2023.0.5, epoch 1 above 0")),

		statements("boundary/almalinux/below the fixed-in version", "CVE-2021-46784",
			"pkg:rpm/alma/squid@5.2-1.el9_0?arch=x86_64&distro=alma-9.0&epoch=7", nil),
		// At it: "almalinux/purl/Trivy alma namespace and alma-9.x distro".
		statements("boundary/almalinux/above it", "CVE-2021-46784", squidAbove,
			fixed("CVE-2021-46784", "almalinux", tsDay1File, "oval", squidAbove, evSquid+"; the query is 7:5.5-6.el9_3.1")),
		// The fixed-in version's epoch is 7; the same build without the epoch
		// qualifier is epoch 0, below it.
		statements("boundary/almalinux/no epoch is epoch 0, below an epoch-7 fix", "CVE-2021-46784",
			"pkg:rpm/alma/squid@5.5-6.el9_3.1?arch=x86_64&distro=alma-9.3", nil),

		statements("boundary/oracle/below the fixed-in version", "CVE-2023-28486",
			"pkg:rpm/oracle/sudo@1.9.5p2-1.el8_8?arch=x86_64&distro=oracle-8", nil),
		// At it: "oracle/purl/OL8 package".
		statements("boundary/oracle/above it", "CVE-2023-28486", sudoAbove,
			fixed("CVE-2023-28486", "oracle", tsDay1File, "oval", sudoAbove, evSudo)),
		statements("boundary/oracle/an epoch outranks the version", "CVE-2023-28486", sudoEpoch,
			fixed("CVE-2023-28486", "oracle", tsDay1File, "oval", sudoEpoch, evSudo+"; the query is 1:1.9.5p2-1.el8_8, epoch 1 above 0")),
		{
			// One product below and one above in one request: the row is
			// answered, under the product above only.
			Name: "boundary/oracle/only the product at or above is named", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2023-28486"), "products": ss("pkg:rpm/oracle/sudo@1.9.5p2-1.el8_8?arch=x86_64&distro=oracle-8", sudoAbove)},
			Status: 200, Rows: 1,
			Want: fixed("CVE-2023-28486", "oracle", tsDay1File, "oval", sudoAbove, evSudo+"; 1.9.5p2-1.el8_8 is below it and is not named"),
		},
	}
}
