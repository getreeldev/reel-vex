//go:build integration

package acceptance

// SUSE CSAF VEX. Documents under ftp.suse.com/pub/projects/security/csaf-vex/
// ("SUSE <file>" below). SUSE publishes no bulk archive, so a cold start crawls
// changes.csv and dates every row by its line.
const (
	tsSUSE1914  = "2025-03-15T04:00:28Z" // changes.csv "cve-2025-1914.json"
	tsSUSE15535 = "2026-05-13T15:56:49Z" // changes.csv "cve-2017-15535.json"
	tsSUSE26791 = "2026-06-06T03:18:08Z" // changes.csv "cve-2025-26791.json"
	tsSUSE22077 = "2026-09-01T01:04:08Z" // changes.csv "cve-2025-22077.json"
)

func suseCases() []Case {
	return []Case{
		{
			// The Phase 1 audit fix: SUSE marks fixes as product_status.recommended.
			Name: "suse/cve-only/recommended is fixed", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2025-1914")}, Status: 200, Rows: 7,
			Want: []Stmt{{CVE: "CVE-2025-1914", Supplier: "suse", Status: "fixed", Timestamp: tsSUSE1914, Notes: notes("csaf", ""),
				Products: ss("cpe:/o:opensuse:leap:15.6", "cpe:/o:opensuse:tumbleweed",
					"cpe:2.3:a:chromium:chromium:134.0.6998.35:*:*:*:*:*:*:*",
					"pkg:rpm/suse/chromedriver@134.0.6998.35-1.1", "pkg:rpm/suse/chromedriver@134.0.6998.35-bp156.2.90.1",
					"pkg:rpm/suse/chromium@134.0.6998.35-1.1", "pkg:rpm/suse/chromium@134.0.6998.35-bp156.2.90.1"),
				Evidence: "SUSE cve-2025-1914.json product_status.recommended (6 products: Package Hub 15 SP6, openSUSE Leap 15.6, Tumbleweed; chromium, chromedriver); no product_status.fixed"}},
		},
		{
			Name: "suse/cve-only/known_not_affected without a flag", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2017-15535")}, Status: 200, Rows: 12,
			Want: []Stmt{
				{CVE: "CVE-2017-15535", Supplier: "suse", Status: "not_affected", Impact: noJustification, Timestamp: tsSUSE15535, Notes: notes("csaf", ""),
					Products: ss("cpe:/o:suse:sle-studioonsite:1.3", "cpe:/o:suse:suse-openstack-cloud:6", "cpe:/o:suse:suse-openstack-cloud:7",
						"cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*", "pkg:rpm/suse/mongodb@?upstream=mongodb.src.rpm"),
					Evidence: "SUSE cve-2017-15535.json product_status.known_not_affected: OpenStack Cloud 6/7, Studio Onsite 1.3 :mongodb (no flags[] in the document)"},
				{CVE: "CVE-2017-15535", Supplier: "suse", Status: "fixed", Timestamp: tsSUSE15535, Notes: notes("csaf", ""),
					Products: ss("cpe:/o:suse:packagehub:12:sp2", "cpe:2.3:a:mongodb:mongodb:3.4.10:*:*:*:*:*:*:*",
						"pkg:rpm/suse/mongodb-mongoperf@3.4.10-5.1", "pkg:rpm/suse/mongodb-mongos@3.4.10-5.1", "pkg:rpm/suse/mongodb-server@3.4.10-5.1",
						"pkg:rpm/suse/mongodb-shell@3.4.10-5.1", "pkg:rpm/suse/mongodb@3.4.10-5.1?upstream=mongodb-3.4.10-5.1.src.rpm"),
					Evidence: "SUSE cve-2017-15535.json product_status.recommended: SUSE Package Hub 12 SP2:mongodb*-3.4.10-5.1 (5 products)"},
			},
		},
		{
			Name: "suse/cve-only/known_affected", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2025-26791")}, Status: 200, Rows: 7,
			Want: []Stmt{
				{CVE: "CVE-2025-26791", Supplier: "suse", Status: "affected", Timestamp: tsSUSE26791, Notes: notes("csaf", ""),
					Products: ss("cpe:/o:suse:sles:16:16.0:server", "cpe:2.3:a:rapid7:velociraptor:*:*:*:*:*:*:*:*", "pkg:rpm/suse/velociraptor@?upstream=velociraptor.src.rpm"),
					Evidence: "SUSE cve-2025-26791.json product_status.known_affected: SUSE Linux Enterprise Server 16.0:velociraptor, openSUSE Leap 16.0:velociraptor"},
				{CVE: "CVE-2025-26791", Supplier: "suse", Status: "fixed", Timestamp: tsSUSE26791, Notes: notes("csaf", ""),
					Products: ss("cpe:/o:opensuse:tumbleweed", "pkg:rpm/suse/argocd-cli-bash-completion@2.14.8-1.1",
						"pkg:rpm/suse/argocd-cli-zsh-completion@2.14.8-1.1", "pkg:rpm/suse/argocd-cli@2.14.8-1.1"),
					Evidence: "SUSE cve-2025-26791.json product_status.recommended: openSUSE Tumbleweed:argocd-cli*-2.14.8-1.1 (3 products)"},
			},
		},
		{
			// The older status the Phase 1 fix also maps: the SL Micro Extras
			// 6.2 platform appears in this document only under first_fixed.
			Name: "suse/cpe/first_fixed is fixed", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2025-22077"), "products": ss("cpe:/o:suse:sl-micro-extras:6.2")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2025-22077", Supplier: "suse", Status: "fixed", Timestamp: tsSUSE22077, Notes: notes("csaf", "direct"),
				Products: ss("cpe:/o:suse:sl-micro-extras:6.2"),
				Evidence: "SUSE cve-2025-22077.json product_status.first_fixed: SUSE Linux Micro Extras 6.2:kernel-obs-build-6.12.0-160000.6.1 and :kernel-syms-6.12.0-160000.6.1 (platform cpe:/o:suse:sl-micro-extras:6.2, in no other status list)"}},
		},
		{
			Name: "suse/purl/recommended answers a scanner rpm query as fixed", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2025-1914"), "products": ss("pkg:rpm/suse/chromium@134.0.6998.35-bp156.2.90.1?arch=x86_64&distro=sles-15.6")},
			Status: 200, Rows: 2,
			Want: []Stmt{{CVE: "CVE-2025-1914", Supplier: "suse", Status: "fixed", Timestamp: tsSUSE1914, Notes: notes("csaf", "direct"),
				Products: ss("pkg:rpm/suse/chromium?distro=sles-15.6"),
				Evidence: "SUSE cve-2025-1914.json product_status.recommended: chromium-134.0.6998.35-bp156.2.90.1 (Package Hub, Leap) and chromium-134.0.6998.35-1.1 (Tumbleweed)"}},
		},
		{
			Name: "suse/purl/known_affected", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2025-26791"), "products": ss("pkg:rpm/suse/velociraptor@0.7.1-1.1?arch=x86_64&distro=sles-16.0")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2025-26791", Supplier: "suse", Status: "affected", Timestamp: tsSUSE26791, Notes: notes("csaf", "direct"),
				Products: ss("pkg:rpm/suse/velociraptor?distro=sles-16.0"),
				Evidence: "SUSE cve-2025-26791.json product_status.known_affected: ...:velociraptor (purl pkg:rpm/suse/velociraptor@?upstream=velociraptor.src.rpm)"}},
		},
		{
			Name: "suse/cpe/direct platform", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2025-1914"), "products": ss("cpe:/o:opensuse:leap:15.6")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2025-1914", Supplier: "suse", Status: "fixed", Timestamp: tsSUSE1914, Notes: notes("csaf", "direct"),
				Products: ss("cpe:/o:opensuse:leap:15.6"),
				Evidence: "SUSE cve-2025-1914.json product_status.recommended: openSUSE Leap 15.6:chromedriver/chromium (platform cpe:/o:opensuse:leap:15.6)"}},
		},
		{
			Name: "suse/purl/not affected on one product, fixed on another, version-blind", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2017-15535"), "products": ss("pkg:rpm/suse/mongodb@3.4.10-5.1?arch=x86_64&distro=sles-12.2")},
			Status: 200, Rows: 2,
			Want: []Stmt{
				{CVE: "CVE-2017-15535", Supplier: "suse", Status: "not_affected", Impact: noJustification, Timestamp: tsSUSE15535, Notes: notes("csaf", "direct"),
					Products: ss("pkg:rpm/suse/mongodb?distro=sles-12.2"),
					Evidence: "SUSE cve-2017-15535.json product_status.known_not_affected: ...:mongodb (purl pkg:rpm/suse/mongodb@?upstream=mongodb.src.rpm)"},
				{CVE: "CVE-2017-15535", Supplier: "suse", Status: "fixed", Timestamp: tsSUSE15535, Notes: notes("csaf", "direct"),
					Products: ss("pkg:rpm/suse/mongodb?distro=sles-12.2"),
					Evidence: "SUSE cve-2017-15535.json product_status.recommended: SUSE Package Hub 12 SP2:mongodb-3.4.10-5.1"},
			},
		},
		{
			Name: "suse/broad/products only", Endpoint: epStatements,
			Body:   body{"products": ss("pkg:rpm/suse/argocd-cli@2.14.8-1.1?arch=x86_64&distro=opensuse-tumbleweed-20250401")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2025-26791", Supplier: "suse", Status: "fixed", Timestamp: tsSUSE26791, Notes: notes("csaf", "direct"),
				Products: ss("pkg:rpm/suse/argocd-cli?distro=opensuse-tumbleweed-20250401"),
				Evidence: "SUSE cve-2025-26791.json product_status.recommended: openSUSE Tumbleweed:argocd-cli-2.14.8-1.1 (the only document naming argocd-cli)"}},
		},
		{
			Name: "suse/negative/another vendor's namespace", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2025-1914"), "products": ss("pkg:rpm/redhat/chromium@134.0.6998.35-1.el9?arch=x86_64")},
			Status: 204, Rows: 0,
		},
	}
}
