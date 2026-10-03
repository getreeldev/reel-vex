//go:build integration

package acceptance

import "strings"

// Day 2: the fixtures change (testdata/feeds/day2 and testdata/src/day2, every
// edit listed in testdata/README.md) and the ingest runs again. These cases
// hold after that second ingest; they need the removal wiring of Phase 4
// (PLAN-VEX-SWEEP.md §2: whole-feed sweep, per-document replace, withdrawal by
// manifest, the 0.2 fraction guard), so until it lands they are pending and the
// day-2 ingest does not run at all.

const phase4 = "phase 4"

// noOpRepublish is why a row the vendor still states unchanged keeps its day-1
// date after the day-2 ingest re-reads it.
const noOpRepublish = " — unchanged, so it keeps its day-1 date: pkg/db/postgres BulkInsert documents that `updated` is not part of the change test, so a timestamp-only republish is a no-op"

func day2Cases() []Case {
	return []Case{
		{
			// Whole-feed sweep: the tarball's Last-Modified moved and
			// statements[1] is gone from CVE-2016-9571.json.
			Name: "day2/ubuntu-vex/a dropped statement is gone", Pending: phase4, Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2016-9571")}, Status: 200, Rows: 8,
			Want: []Stmt{{CVE: "CVE-2016-9571", Supplier: "ubuntu", Status: "affected", Timestamp: tsUV9571, Notes: notes("openvex", ""),
				Products: ss(
					"pkg:deb/ubuntu/libresteasy-java@3.0.6-3?arch=amd64&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/libresteasy-java@3.0.6-3?arch=arm64&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/libresteasy-java@3.0.6-3?arch=armhf&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/libresteasy-java@3.0.6-3?arch=i386&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/libresteasy-java@3.0.6-3?arch=powerpc&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/libresteasy-java@3.0.6-3?arch=ppc64el&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/libresteasy-java@3.0.6-3?arch=s390x&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/resteasy@3.0.6-3?arch=source&distro=ubuntu-16.04"),
				Evidence: "day-2 UV vex/cve/2016/CVE-2016-9571.json: statements[0] affected kept, statements[1] (not_affected, esm-apps/xenial) removed"}},
		},
		{
			Name: "day2/ubuntu-vex/a changed verdict answers only the new one", Pending: phase4, Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2022-2060")}, Status: 200, Rows: 7,
			Want: []Stmt{{CVE: "CVE-2022-2060", Supplier: "ubuntu", Status: "affected", Timestamp: tsUV2060, Notes: notes("openvex", ""),
				Products: ss(
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=amd64&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=arm64&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=armhf&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=i386&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=ppc64el&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=s390x&distro=ubuntu-16.04",
					"pkg:deb/ubuntu/dolibarr@3.5.8+dfsg1-1ubuntu1+esm1?arch=source&distro=ubuntu-16.04"),
				Evidence: "day-2 UV vex/cve/2022/CVE-2022-2060.json statements[0].status under_investigation -> affected"}},
		},
		{
			Name: "day2/alpine/a CVE dropped from secfixes is gone", Pending: phase4, Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2022-29869")},
			Status: 204, Rows: 0,
		},
		{
			Name: "day2/alpine/the rest of the package is kept", Pending: phase4, Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2022-27239")}, Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2022-27239", Supplier: "alpine", Status: "fixed", Timestamp: tsDay1File, Notes: notes("secdb", ""),
				Products: ss("pkg:apk/alpine/cifs-utils?distro=alpine-3.22"),
				Evidence: "AS v3.22/main.json package cifs-utils: secfixes \"6.15-r0\": [CVE-2022-27239] on both days" + noOpRepublish}},
		},
		{
			Name: "day2/debian/a dropped OVAL definition is gone", Pending: phase4, Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-1999-1332")},
			Status: 204, Rows: 0,
		},
		{
			Name: "day2/debian/the other definitions are kept", Pending: phase4, Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2016-5416")}, Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2016-5416", Supplier: "debian", Status: "affected", Timestamp: tsDay1File, Notes: notes("oval", ""),
				Products: ss("pkg:deb/debian/389-ds-base?distro=debian-12"),
				Evidence: "DO definition oval:org.debian:def:308370225544215691963860905694509241784 on both days" + noOpRepublish}},
		},
		{
			Name: "day2/rancher/a file dropped from the snapshot index is gone", Pending: phase4, Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2026-24061"), "scopes": ss(scopeKubeOVN)},
			Status: 204, Rows: 0,
		},
		{
			Name: "day2/rancher/the other files are kept", Pending: phase4, Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2022-37434"), "vendors": ss("rancher"), "scopes": ss(scopeSachetDocker)}, Status: 200, Rows: 1,
			Want: []Stmt{rancherSachet(scopeSachetDocker, evSachetDocker, "pkg:apk/alpine/zlib")},
		},
		{
			// Per-document replace: changes.csv re-publishes the document on
			// day 2 without red_hat_single_sign-on_7:spring-security. The rows
			// the vendor still states are unchanged, so they keep their day-1
			// date (noOpRepublish).
			Name: "day2/redhat/a product removed from a re-published document is gone", Pending: phase4, Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2023-34034")}, Status: 200, Rows: 6,
			Want: func() []Stmt {
				w := rh34034()
				w[2].Products = ss("cpe:/a:redhat:camel_quarkus:2", "cpe:/a:redhat:quarkus:2",
					"pkg:maven/io.quarkus/quarkus-spring-security?repository_url=https://maven.repository.redhat.com/ga/&type=jar")
				w[2].Evidence = "day-2 RH 2023/cve-2023-34034.json (changes.csv 2026-10-04T06:00:00+00:00): known_not_affected without red_hat_single_sign-on_7:spring-security; the rest" + noOpRepublish
				for i := range w[:2] {
					w[i].Evidence += "; day-2 re-publication" + noOpRepublish
				}
				return w
			}(),
		},
		{
			Name: "day2/redhat/a CVE dropped from index.txt is withdrawn", Pending: phase4, Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2026-94282")},
			Status: 204, Rows: 0,
		},
		{
			Name: "day2/redhat/documents still in index.txt are kept", Pending: phase4, KnownBug: archiveDateBug, Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2025-6270")}, Status: 200, Rows: 2,
			Want: []Stmt{{CVE: "CVE-2025-6270", Supplier: "redhat", Status: "affected", Timestamp: tsRH6270, Notes: notes("csaf", ""),
				Products: ss("cpe:/a:redhat:enterprise_linux_ai:1", "pkg:rpm/redhat/hdf5?arch=src"),
				Evidence: "RH 2025/cve-2025-6270.json, listed in the day-2 index.txt, not re-published"}},
		},
		{
			// The day-2 file drops USN-6756-1 but keeps the day-1
			// Last-Modified: the adapter does not fetch it, so nothing is
			// removed.
			Name: "day2/ubuntu-oval/a feed whose Last-Modified did not move removes nothing", Pending: phase4, Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2024-32487")}, Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2024-32487", Supplier: "ubuntu", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", ""),
				Products: ss("pkg:deb/ubuntu/less?distro=ubuntu-24.04"),
				Evidence: "UO definition oval:com.ubuntu.noble:def:675610000000 (day 1); day-2 file served with the day-1 Last-Modified, so the adapter does not fetch it (ubuntuoval: Last-Modified not after the watermark -> skip GET)"}},
		},
		{
			Name: "day2/almalinux/an unchanged feed removes nothing", Pending: phase4, Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2021-46784")}, Status: 200, Rows: 2,
			Want: []Stmt{{CVE: "CVE-2021-46784", Supplier: "almalinux", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", ""),
				Products: ss("pkg:rpm/alma/squid?distro=almalinux-9", "pkg:rpm/almalinux/squid?distro=almalinux-9"),
				Evidence: "AO definition oval:org.almalinux.alsa:def:20225527, file unchanged on day 2"}},
		},
		{
			// The guard: the day-2 community.json drops hermes and netdata, 4 of
			// its 8 rows (> 0.2), so the sweep is refused and every row stays.
			Name: "day2/alpine community/losing more than 20% of a feed is refused", Pending: phase4, Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2020-1914", "CVE-2020-1915", "CVE-2024-32019", "CVE-2023-44487")}, Status: 200, Rows: 4,
			Want: []Stmt{
				{CVE: "CVE-2020-1914", Supplier: "alpine", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: tsDay1File, Notes: notes("secdb", ""),
					Products: ss("pkg:apk/alpine/hermes?distro=alpine-3.22"), Evidence: "AS v3.22/community.json (day 1) package hermes: secfixes \"0\": [CVE-2020-1914, CVE-2020-1915]; the refused sweep deletes nothing" + noOpRepublish},
				{CVE: "CVE-2020-1915", Supplier: "alpine", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: tsDay1File, Notes: notes("secdb", ""),
					Products: ss("pkg:apk/alpine/hermes?distro=alpine-3.22"), Evidence: "AS v3.22/community.json (day 1) package hermes: secfixes \"0\""},
				{CVE: "CVE-2024-32019", Supplier: "alpine", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: tsDay1File, Notes: notes("secdb", ""),
					Products: ss("pkg:apk/alpine/netdata?distro=alpine-3.22"), Evidence: "AS v3.22/community.json (day 1) package netdata: secfixes \"0\": [CVE-2024-32019]"},
				{CVE: "CVE-2023-44487", Supplier: "alpine", Status: "fixed", Timestamp: tsDay1File, Notes: notes("secdb", ""),
					Products: ss("pkg:apk/alpine/netdata?distro=alpine-3.22"), Evidence: "AS v3.22/community.json (day 1) package netdata: secfixes \"1.43.2-r1\": [CVE-2023-44487]"},
			},
		},
		{
			// Ownership: ELSA-2024-0811 is in both release files. The ol9
			// file drops it on day 2 (its Last-Modified moves); the ol8 file
			// keeps it and does not change. Each adapter owns only its own
			// release's rows, so only the OL9 rows go.
			Name: "day2/oracle/an ELSA dropped from one release's file goes from that release only", Pending: phase4, Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2023-42465")}, Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2023-42465", Supplier: "oracle", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", ""),
				Products: ss("pkg:rpm/oracle/sudo?distro=oracle-8"),
				Evidence: "OO com.oracle.elsa-ol8.xml (unchanged) definition oval:com.oracle.elsa:def:20240811, OL8 branch: sudo < 0:1.9.5p2-1.el8_9; day-2 com.oracle.elsa-ol9.xml no longer has the definition"}},
		},
		{
			Name: "day2/oracle/the OL9-only package of the dropped ELSA is gone", Pending: phase4, Endpoint: epStatements,
			Body:   body{"products": ss("pkg:rpm/oracle/sudo-python-plugin@1.9.5p2-10.el9_3?arch=x86_64&distro=oracle-9")},
			Status: 204, Rows: 0,
		},
		{
			Name: "day2/oracle/the rest of the ol9 file is kept", Pending: phase4, Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2026-2447")}, Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2026-2447", Supplier: "oracle", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", ""),
				Products: ss("pkg:rpm/oracle/thunderbird?distro=oracle-9"),
				Evidence: "OO com.oracle.elsa-ol9.xml definition oval:com.oracle.elsa:def:20263516 (ELSA-2026-3516 thunderbird) on both days" + noOpRepublish}},
		},
		{
			// Per-document replace with nothing left: the day-2 document keeps
			// its vulnerability but no product_status.
			Name: "day2/redhat/a re-published document with zero statements removes all its rows", Pending: phase4, Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2026-47699")},
			Status: 204, Rows: 0,
		},
		{
			// SUSE's day-2 run finds no new changes.csv line (nothing is
			// refreshed, nothing swept) and an index.txt without
			// cve-2017-15535.json: 1 of the 4 CVEs it holds, more than 20%, so
			// the withdrawal is refused and every SUSE row stays.
			Name: "day2/suse/an unchanged feed keeps every row, and a withdrawal of more than 20% is refused", Pending: phase4, Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2025-1914", "CVE-2017-15535", "CVE-2025-26791")}, Status: 200, Rows: 26,
			Want: func() []Stmt {
				var w []Stmt
				for _, c := range suseCases() {
					if strings.HasPrefix(c.Name, "suse/cve-only/") {
						w = append(w, c.Want...)
					}
				}
				return w
			}(),
		},
	}
}
