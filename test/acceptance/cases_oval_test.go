//go:build integration

package acceptance

// Ubuntu OVAL (com.ubuntu.noble.usn.oval.xml.bz2, "UO" below) and Debian OVAL
// (oval-definitions-bookworm.xml.bz2, "DO" below). Rows are dated by the feed
// file's Last-Modified (tsDay1File), although the definitions carry their own
// dates (Ubuntu advisory issued/updated, Debian DSA <date>): that is the
// product's current design, an open decision in PLAN-VEX-SWEEP.md §6 Backlog,
// "Found by Phase 3a". A row's product is the versionless package with its
// release (the fixed-in version is stored but is not part of any answer until
// Phase 5b).

func ubuntuOVALCases() []Case {
	return []Case{
		{
			Name: "ubuntu-oval/cve-only/fixed", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2024-32487")}, Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2024-32487", Supplier: "ubuntu", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", ""),
				Products: ss("pkg:deb/ubuntu/less?distro=ubuntu-24.04"),
				Evidence: "UO definition oval:com.ubuntu.noble:def:675610000000 (USN-6756-1, class patch): less < 590-2ubuntu2.1"}},
		},
		{
			Name: "ubuntu-oval/purl/two binary packages of one USN", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2024-28219"), "products": ss("pkg:deb/ubuntu/python3-pil@10.0.0-1?arch=amd64&distro=ubuntu-24.04")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2024-28219", Supplier: "ubuntu", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", "direct"),
				Products: ss("pkg:deb/ubuntu/python3-pil?distro=ubuntu-24.04"),
				Evidence: "UO definition oval:com.ubuntu.noble:def:674430000000 (USN-6744-3): variable python3-pil, python3-pil.imagetk < 10.2.0-1ubuntu1"}},
		},
		{
			Name: "ubuntu-oval/cve-only/one USN, four CVEs, two packages", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2016-9840"), "source_formats": ss("oval")}, Status: 200, Rows: 2,
			Want: []Stmt{{CVE: "CVE-2016-9840", Supplier: "ubuntu", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", ""),
				Products: ss("pkg:deb/ubuntu/klibc-utils?distro=ubuntu-24.04", "pkg:deb/ubuntu/libklibc?distro=ubuntu-24.04"),
				Evidence: "UO definition oval:com.ubuntu.noble:def:673620000000 (USN-6736-2): CVE-2016-9840, -9841, CVE-2018-25032, CVE-2022-37434; klibc-utils, libklibc < 2.0.13-4ubuntu0.1"}},
		},
		{
			Name: "ubuntu-oval/broad/products only", Endpoint: epStatements,
			Body:   body{"products": ss("pkg:deb/ubuntu/less@590-2ubuntu2?arch=amd64&distro=ubuntu-24.04")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2024-32487", Supplier: "ubuntu", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", "direct"),
				Products: ss("pkg:deb/ubuntu/less?distro=ubuntu-24.04"),
				Evidence: "UO definition oval:com.ubuntu.noble:def:675610000000 (USN-6756-1): the only definition naming less"}},
		},
		{
			Name: "ubuntu-oval/negative/a USN with no CVE emits nothing", Endpoint: epStatements,
			Body:   body{"products": ss("pkg:deb/ubuntu/libssl3t64@3.0.13-0ubuntu3.1?arch=amd64&distro=ubuntu-24.04")},
			Status: 204, Rows: 0,
		},
		{
			// The same CVE and package from Canonical's two feeds stay two
			// statements (source_format differs).
			Name: "ubuntu/exact/OpenVEX and OVAL for one package", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2022-37434"), "products": ss("pkg:deb/ubuntu/libklibc@2.0.13-4ubuntu0.2?arch=amd64&distro=ubuntu-24.04")},
			Status: 200, Rows: 8,
			Want: []Stmt{
				{CVE: "CVE-2022-37434", Supplier: "ubuntu", Status: "fixed", Timestamp: tsUV37434, Notes: notes("openvex", "direct"),
					Products: archesAt("pkg:deb/ubuntu/libklibc@2.0.13-4ubuntu0.2", "ubuntu-24.04", "amd64", "arm64", "armhf", "i386", "ppc64el", "riscv64", "s390x"),
					Evidence: "UV vex/cve/2022/CVE-2022-37434.json statements[0] fixed: libklibc@2.0.13-4ubuntu0.2 distro=noble (7 arches)"},
				{CVE: "CVE-2022-37434", Supplier: "ubuntu", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", "direct"),
					Products: ss("pkg:deb/ubuntu/libklibc?distro=ubuntu-24.04"),
					Evidence: "UO definition oval:com.ubuntu.noble:def:673620000000 (USN-6736-2): libklibc < 2.0.13-4ubuntu0.1 (an OVAL row keeps today's rendering, Phase 5 step 4)"},
			},
		},
	}
}

func debianCases() []Case {
	return []Case{
		{
			// The Phase 1 audit fix: "less than 0:0" is how Debian writes "no fix yet".
			Name: "debian/cve-only/0:0 is affected, not fixed", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2016-5416")}, Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2016-5416", Supplier: "debian", Status: "affected", Timestamp: tsDay1File, Notes: notes("oval", ""),
				Products: ss("pkg:deb/debian/389-ds-base?distro=debian-12"),
				Evidence: "DO definition oval:org.debian:def:308370225544215691963860905694509241784 (CVE-2016-5416 389-ds-base): dpkginfo evr less than 0:0"}},
		},
		{
			Name: "debian/cve-only/0:0 on a second package", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2001-1534")}, Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2001-1534", Supplier: "debian", Status: "affected", Timestamp: tsDay1File, Notes: notes("oval", ""),
				Products: ss("pkg:deb/debian/apache2?distro=debian-12"),
				Evidence: "DO definition oval:org.debian:def:71475824035904533640313774911074609996 (CVE-2001-1534 apache2): evr less than 0:0"}},
		},
		{
			Name: "debian/purl/fixed", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2022-37434"), "products": ss("pkg:deb/debian/zlib@1:1.2.13.dfsg-1?arch=source&distro=debian-12")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2022-37434", Supplier: "debian", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", "direct"),
				Products: ss("pkg:deb/debian/zlib?distro=debian-12"),
				Evidence: "DO definition oval:org.debian:def:118596735315433746990801407057633161948 (CVE-2022-37434 zlib): evr less than 1:1.2.11.dfsg-4.1"}},
		},
		{
			Name: "debian/purl/Trivy point-release distro", Endpoint: epStatements,
			KnownBug: "a scanner's deb distro for Debian is the point release (Trivy: debian-12.11); the resolver normalises apk, Amazon and AlmaLinux point releases but not Debian's, so the bookworm rows (distro=debian-12) are never reached",
			Body:     body{"cves": ss("CVE-2022-37434"), "products": ss("pkg:deb/debian/zlib@1:1.2.13.dfsg-1?arch=source&distro=debian-12.11")},
			Status:   200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2022-37434", Supplier: "debian", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", "direct"),
				Products: ss("pkg:deb/debian/zlib?distro=debian-12.11"),
				Evidence: "DO definition oval:org.debian:def:118596735315433746990801407057633161948 (platform Debian GNU/Linux 12): zlib < 1:1.2.11.dfsg-4.1"}},
		},
		{
			Name: "debian/cve-only/a DSA (class patch) naming two CVEs", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2023-2828", "CVE-2023-2911")}, Status: 200, Rows: 2,
			Want: []Stmt{
				{CVE: "CVE-2023-2828", Supplier: "debian", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", ""),
					Products: ss("pkg:deb/debian/bind9?distro=debian-12"),
					Evidence: "DO definition oval:org.debian:def:61325699286411249562200157530598017542 (DSA-5439-1 bind9): references CVE-2023-2828, evr less than 1:9.18.16-1~deb12u1"},
				{CVE: "CVE-2023-2911", Supplier: "debian", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", ""),
					Products: ss("pkg:deb/debian/bind9?distro=debian-12"),
					Evidence: "DO definition oval:org.debian:def:61325699286411249562200157530598017542 (DSA-5439-1 bind9): references CVE-2023-2911"},
			},
		},
		{
			Name: "debian/broad/products only", Endpoint: epStatements,
			Body:   body{"products": ss("pkg:deb/debian/389-ds-base@2.3.1+dfsg1-1+deb12u1?arch=amd64&distro=debian-12")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2016-5416", Supplier: "debian", Status: "affected", Timestamp: tsDay1File, Notes: notes("oval", "direct"),
				Products: ss("pkg:deb/debian/389-ds-base?distro=debian-12"),
				Evidence: "DO definition oval:org.debian:def:308370225544215691963860905694509241784: the only definition naming 389-ds-base (evr 0:0)"}},
		},
		{
			Name: "debian/cve-only/fixed (gzip)", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-1999-1332")}, Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-1999-1332", Supplier: "debian", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", ""),
				Products: ss("pkg:deb/debian/gzip?distro=debian-12"),
				Evidence: "DO definition oval:org.debian:def:166558133375782793613486575811727984470 (CVE-1999-1332 gzip): evr less than 0:1.3.5-6"}},
		},
		{
			Name: "debian/negative/the same package in a release the vendor did not state", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2016-5416"), "products": ss("pkg:deb/debian/389-ds-base@1.4.4.11-2?arch=amd64&distro=debian-11")},
			Status: 204, Rows: 0,
		},
		{
			Name: "debian/negative/another vendor's namespace", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2016-5416"), "products": ss("pkg:deb/ubuntu/389-ds-base@2.3.1?arch=amd64&distro=debian-12")},
			Status: 204, Rows: 0,
		},
	}
}
