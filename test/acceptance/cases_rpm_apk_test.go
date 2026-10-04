//go:build integration

package acceptance

// Alpine secdb (secdb.alpinelinux.org/v3.22/{main,community}.json, "AS"),
// Amazon ALAS updateinfo ("AL"), AlmaLinux OVAL (org.almalinux.alsa-9.xml.bz2,
// "AO") and Oracle OVAL (com.oracle.elsa-ol{8,9}.xml.bz2, "OO").

func alpineCases() []Case {
	main := func(cve, status, just, ev string, products ...string) Stmt {
		return Stmt{CVE: cve, Supplier: "alpine", Status: status, Justification: just, Timestamp: tsDay1File, Notes: notes("secdb", ""), Products: products, Evidence: ev}
	}
	return []Case{
		{
			// The Phase 1 audit fix: secfixes key "0" means the CVE does not apply.
			Name: "alpine/cve-only/secfixes \"0\" is not_affected", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2020-36325")}, Status: 200, Rows: 1,
			Want: []Stmt{main("CVE-2020-36325", "not_affected", "vulnerable_code_not_present",
				"AS v3.22/main.json package jansson: secfixes \"0\": [CVE-2020-36325]", "pkg:apk/alpine/jansson?distro=alpine-3.22")},
		},
		{
			Name: "alpine/purl/fixed, Trivy three-part distro", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2026-56123"), "products": ss("pkg:apk/alpine/socat@1.8.1.2-r0?arch=x86_64&distro=3.22.2")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2026-56123", Supplier: "alpine", Status: "fixed", Timestamp: tsDay1File, Notes: notes("secdb", "direct"),
				Products: ss("pkg:apk/alpine/socat?distro=3.22.2"), Evidence: "AS v3.22/main.json package socat: secfixes \"1.8.1.2-r0\": [CVE-2026-56123]"}},
		},
		{
			Name: "alpine/purl/\"0\" via a Trivy query", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2024-54661"), "products": ss("pkg:apk/alpine/socat@1.8.0.3-r0?arch=x86_64&distro=3.22.2")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2024-54661", Supplier: "alpine", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: tsDay1File, Notes: notes("secdb", "direct"),
				Products: ss("pkg:apk/alpine/socat?distro=3.22.2"), Evidence: "AS v3.22/main.json package socat: secfixes \"0\": [CVE-2024-54661]"}},
		},
		{
			Name: "alpine/purl/syft alpine-prefixed distro", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2020-35766"), "products": ss("pkg:apk/alpine/opendkim@2.11.0_beta2-r2?arch=x86_64&distro=alpine-3.22.1")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2020-35766", Supplier: "alpine", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: tsDay1File, Notes: notes("secdb", "direct"),
				Products: ss("pkg:apk/alpine/opendkim?distro=alpine-3.22.1"), Evidence: "AS v3.22/community.json package opendkim: secfixes \"0\": [CVE-2020-35766]"}},
		},
		{
			// The version kept (the highest, 1.2.11-r4) is not part of any answer
			// before Phase 5b; one row is what is observable.
			Name: "alpine/cve-only/a CVE under two fixed versions is one row", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2021-20314")}, Status: 200, Rows: 1,
			Want: []Stmt{main("CVE-2021-20314", "fixed", "",
				"AS v3.22/main.json package libspf2: secfixes \"1.2.10-r5\" and \"1.2.11-r4\" both list CVE-2021-20314", "pkg:apk/alpine/libspf2?distro=alpine-3.22")},
		},
		{
			// The Phase 1 rule: a CVE listed under "0" and under a fixed
			// version is the fixed version; "0" applies only when no fixed
			// version lists it.
			Name: "alpine/cve-only/a CVE under \"0\" and a fixed version is fixed", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2026-14681")}, Status: 200, Rows: 1,
			Want: []Stmt{main("CVE-2026-14681", "fixed", "",
				"AS v3.22/main.json package postgresql17: secfixes \"0\": [CVE-2026-14681] and \"17.11-r0\": [..., CVE-2026-14681, ...]", "pkg:apk/alpine/postgresql17?distro=alpine-3.22")},
		},
		{
			Name: "alpine/broad/non-CVE advisory ids are skipped", Endpoint: epStatements,
			Body:   body{"products": ss("pkg:apk/alpine/libdwarf@0.9.2-r0?arch=x86_64&distro=3.22.0")},
			Status: 200, Rows: 2,
			Want: []Stmt{
				{CVE: "CVE-2015-8538", Supplier: "alpine", Status: "fixed", Timestamp: tsDay1File, Notes: notes("secdb", "direct"),
					Products: ss("pkg:apk/alpine/libdwarf?distro=3.22.0"), Evidence: "AS v3.22/main.json package libdwarf: secfixes \"0.6.0-r0\": [CVE-2019-14249, CVE-2015-8538]"},
				{CVE: "CVE-2019-14249", Supplier: "alpine", Status: "fixed", Timestamp: tsDay1File, Notes: notes("secdb", "direct"),
					Products: ss("pkg:apk/alpine/libdwarf?distro=3.22.0"), Evidence: "AS v3.22/main.json package libdwarf: secfixes \"0.6.0-r0\"; \"0.9.2-r0\" lists only DW2024* ids"},
			},
		},
		{
			Name: "alpine/cve-only/community repository", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2023-44487")}, Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2023-44487", Supplier: "alpine", Status: "fixed", Timestamp: tsDay1File, Notes: notes("secdb", ""),
				Products: ss("pkg:apk/alpine/netdata?distro=alpine-3.22"), Evidence: "AS v3.22/community.json package netdata: secfixes \"1.43.2-r1\": [CVE-2023-44487]"}},
		},
		{
			Name: "alpine/negative/a branch the vendor did not state", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2026-56123"), "products": ss("pkg:apk/alpine/socat@1.8.1.2-r0?arch=x86_64&distro=3.21.4")},
			Status: 204, Rows: 0,
		},
		{
			Name: "alpine/negative/a non-CVE id is not a key", Endpoint: epStatements,
			Body:   body{"cves": ss("DW202402-001")},
			Status: 204, Rows: 0,
		},
	}
}

// AL: one row per (CVE reference x package name) of each <update>, dated by
// its <updated date>, keyed pkg:rpm/amazon/<name>?distro=amazon-<major>.
const (
	tsALCa2      = "2023-02-22T01:53:00Z" // ALAS2-2023-1957 <updated>
	tsALCa2023   = "2023-02-22T23:34:00Z" // ALAS2023-2023-061 <updated>
	tsALBottle23 = "2023-02-22T23:30:00Z" // ALAS2023-2023-082 <updated>
)

func amazonCases() []Case {
	return []Case{
		{
			Name: "amazon/purl/Trivy point-release AL2023 distro", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2022-23491"), "products": ss("pkg:rpm/amazon/ca-certificates@2021.2.50-1.0.amzn2023.0.6?arch=noarch&distro=amazon-2023.7.20250512")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2022-23491", Supplier: "amazon", Status: "fixed", Timestamp: tsALCa2023, Notes: notes("updateinfo", "direct"),
				Products: ss("pkg:rpm/amazon/ca-certificates?distro=amazon-2023.7.20250512"),
				Evidence: "AL al2023 updateinfo <update> ALAS2023-2023-061: reference CVE-2022-23491, package ca-certificates 2021.2.50-1.0.amzn2023.0.6"}},
		},
		{
			Name: "amazon/purl/AL2", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2022-23491"), "products": ss("pkg:rpm/amazon/ca-certificates@2021.2.50-72.amzn2.0.5?arch=noarch&distro=amazon-2")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2022-23491", Supplier: "amazon", Status: "fixed", Timestamp: tsALCa2, Notes: notes("updateinfo", "direct"),
				Products: ss("pkg:rpm/amazon/ca-certificates?distro=amazon-2"),
				Evidence: "AL amzn2 updateinfo <update> ALAS2-2023-1957: reference CVE-2022-23491, package ca-certificates 2021.2.50-72.amzn2.0.5"}},
		},
		{
			Name: "amazon/cve-only/one package fixed in both distros", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2022-23491")}, Status: 200, Rows: 2,
			Want: []Stmt{
				{CVE: "CVE-2022-23491", Supplier: "amazon", Status: "fixed", Timestamp: tsALCa2, Notes: notes("updateinfo", ""),
					Products: ss("pkg:rpm/amazon/ca-certificates@2021.2.50-72.amzn2.0.5?distro=amazon-2"),
					Evidence: "AL amzn2 updateinfo <update> ALAS2-2023-1957: ca-certificates version 2021.2.50 release 72.amzn2.0.5 epoch 0"},
				{CVE: "CVE-2022-23491", Supplier: "amazon", Status: "fixed", Timestamp: tsALCa2023, Notes: notes("updateinfo", ""),
					Products: ss("pkg:rpm/amazon/ca-certificates@2021.2.50-1.0.amzn2023.0.6?distro=amazon-2023"),
					Evidence: "AL al2023 updateinfo <update> ALAS2023-2023-061: ca-certificates version 2021.2.50 release 1.0.amzn2023.0.6 epoch 0"},
			},
		},
		{
			Name: "amazon/broad/an advisory naming two CVEs", Endpoint: epStatements,
			Body:   body{"products": ss("pkg:rpm/amazon/python3-bottle@0.12.21-2.amzn2023.0.1?arch=noarch&distro=amazon-2023")},
			Status: 200, Rows: 2,
			Want: []Stmt{
				{CVE: "CVE-2022-3179", Supplier: "amazon", Status: "fixed", Timestamp: tsALBottle23, Notes: notes("updateinfo", "direct"),
					Products: ss("pkg:rpm/amazon/python3-bottle?distro=amazon-2023"), Evidence: "AL al2023 updateinfo <update> ALAS2023-2023-082: references CVE-2022-3179, CVE-2022-31799; package python3-bottle"},
				{CVE: "CVE-2022-31799", Supplier: "amazon", Status: "fixed", Timestamp: tsALBottle23, Notes: notes("updateinfo", "direct"),
					Products: ss("pkg:rpm/amazon/python3-bottle?distro=amazon-2023"), Evidence: "AL al2023 updateinfo <update> ALAS2023-2023-082: reference CVE-2022-31799"},
			},
		},
		{
			// What Trivy writes for Amazon Linux 2: distro "<family>-<name>" with
			// the OS name "2 (Karoo)", percent-encoded by packageurl-go.
			Name: "amazon/purl/Trivy AL2 distro amazon-2 (Karoo), percent-encoded", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2022-23491"), "products": ss("pkg:rpm/amazon/ca-certificates@2021.2.50-72.amzn2.0.5?arch=noarch&distro=amazon-2%20%28Karoo%29")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2022-23491", Supplier: "amazon", Status: "fixed", Timestamp: tsALCa2, Notes: notes("updateinfo", "direct"),
				Products: ss("pkg:rpm/amazon/ca-certificates?distro=amazon-2%20%28Karoo%29"),
				Evidence: "AL amzn2 updateinfo <update> ALAS2-2023-1957: reference CVE-2022-23491, package ca-certificates"}},
		},
		{
			Name: "amazon/negative/an advisory without a CVE", Endpoint: epStatements,
			Body:   body{"products": ss("pkg:rpm/amazon/stunnel@4.56-6.amzn2.0.1?arch=x86_64&distro=amazon-2")},
			Status: 204, Rows: 0,
		},
		{
			Name: "amazon/negative/an AL2023 CVE does not reach AL2", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2022-3179"), "products": ss("pkg:rpm/amazon/python3-bottle@0.12.21-2.amzn2?arch=noarch&distro=amazon-2")},
			Status: 204, Rows: 0,
		},
	}
}

func almalinuxCases() []Case {
	ev := "AO definition oval:org.almalinux.alsa:def:20225527 (ALSA-2022:5527 squid): CVE-2021-46784, squid evr less than 7:5.2-1.el9_0.1"
	return []Case{
		{
			Name: "almalinux/cve-only/fixed under both namespaces", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2021-46784")}, Status: 200, Rows: 2,
			Want: []Stmt{{CVE: "CVE-2021-46784", Supplier: "almalinux", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", ""),
				Products: ss("pkg:rpm/alma/squid?distro=almalinux-9", "pkg:rpm/almalinux/squid?distro=almalinux-9"), Evidence: ev}},
		},
		{
			Name: "almalinux/purl/Trivy alma namespace and alma-9.x distro", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2021-46784"), "products": ss("pkg:rpm/alma/squid@5.2-1.el9_0.1?arch=x86_64&distro=alma-9.0&epoch=7")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2021-46784", Supplier: "almalinux", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", "direct"),
				Products: ss("pkg:rpm/alma/squid?distro=alma-9.0"), Evidence: ev}},
		},
		{
			Name: "almalinux/broad/almalinux namespace and almalinux-9.x distro", Endpoint: epStatements,
			Body:   body{"products": ss("pkg:rpm/almalinux/grafana@7.5.11-5.el9_0?arch=x86_64&distro=almalinux-9.4")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2022-31107", Supplier: "almalinux", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", "direct"),
				Products: ss("pkg:rpm/almalinux/grafana?distro=almalinux-9.4"),
				Evidence: "AO definition oval:org.almalinux.alsa:def:20225716 (ALSA-2022:5716 grafana): CVE-2022-31107, grafana evr less than 0:7.5.11-5.el9_0"}},
		},
		{
			Name: "almalinux/negative/another major", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2021-46784"), "products": ss("pkg:rpm/alma/squid@4.15-1.module_el8?arch=x86_64&distro=alma-8.10")},
			Status: 204, Rows: 0,
		},
	}
}

func oracleCases() []Case {
	ev := "OO definition oval:com.oracle.elsa:def:20240811 (ELSA-2024-0811, in both the ol8 and the ol9 file): the \"Oracle Linux 8 is installed\" branch tests sudo < 0:1.9.5p2-1.el8_9; the \"Oracle Linux 9\" branch tests sudo and sudo-python-plugin < 0:1.9.5p2-10.el9_3"
	return []Case{
		{
			Name: "oracle/cve-only/each release from its own feed", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2023-42465")}, Status: 200, Rows: 3,
			Want: []Stmt{{CVE: "CVE-2023-42465", Supplier: "oracle", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", ""),
				Products: ss("pkg:rpm/oracle/sudo-python-plugin?distro=oracle-9", "pkg:rpm/oracle/sudo?distro=oracle-8", "pkg:rpm/oracle/sudo?distro=oracle-9"), Evidence: ev}},
		},
		{
			// What Trivy writes for Oracle Linux: distro "oracle-<VERSION_ID>".
			Name: "oracle/purl/Trivy point-release distro", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2023-28486"), "products": ss("pkg:rpm/oracle/sudo@1.9.5p2-1.el8_9?arch=x86_64&distro=oracle-8.10")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2023-28486", Supplier: "oracle", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", "direct"), Products: ss("pkg:rpm/oracle/sudo?distro=oracle-8.10"), Evidence: ev}},
		},
		{
			Name: "oracle/cve-only/an OL9-only ELSA", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2026-2447")}, Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2026-2447", Supplier: "oracle", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", ""),
				Products: ss("pkg:rpm/oracle/thunderbird?distro=oracle-9"),
				Evidence: "OO com.oracle.elsa-ol9.xml definition oval:com.oracle.elsa:def:20263516 (ELSA-2026-3516, OL9 gate only): thunderbird < 0:140.8.0-1.0.1.el9_7"}},
		},
		{
			// The Phase 1 audit fix: an OL9-only package of a multi-release ELSA
			// is not stated for OL8.
			Name: "oracle/negative/an OL9-only package under OL8", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2023-42465"), "products": ss("pkg:rpm/oracle/sudo-python-plugin@1.9.5p2-10.el9_3?arch=x86_64&distro=oracle-8")},
			Status: 204, Rows: 0,
		},
		{
			Name: "oracle/broad/OL9 package", Endpoint: epStatements,
			Body:   body{"products": ss("pkg:rpm/oracle/sudo-python-plugin@1.9.5p2-10.el9_3?arch=x86_64&distro=oracle-9")},
			Status: 200, Rows: 3,
			Want: []Stmt{
				{CVE: "CVE-2023-28486", Supplier: "oracle", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", "direct"), Products: ss("pkg:rpm/oracle/sudo-python-plugin?distro=oracle-9"), Evidence: ev},
				{CVE: "CVE-2023-28487", Supplier: "oracle", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", "direct"), Products: ss("pkg:rpm/oracle/sudo-python-plugin?distro=oracle-9"), Evidence: ev},
				{CVE: "CVE-2023-42465", Supplier: "oracle", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", "direct"), Products: ss("pkg:rpm/oracle/sudo-python-plugin?distro=oracle-9"), Evidence: ev},
			},
		},
		{
			Name: "oracle/purl/OL8 package", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2023-28486"), "products": ss("pkg:rpm/oracle/sudo@1.9.5p2-1.el8_9?arch=x86_64&distro=oracle-8")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2023-28486", Supplier: "oracle", Status: "fixed", Timestamp: tsDay1File, Notes: notes("oval", "direct"), Products: ss("pkg:rpm/oracle/sudo?distro=oracle-8"), Evidence: ev}},
		},
	}
}
