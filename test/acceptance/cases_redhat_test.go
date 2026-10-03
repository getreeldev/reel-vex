//go:build integration

package acceptance

// Red Hat CSAF VEX. Documents under security.access.redhat.com/data/csaf/v2/vex/
// (written "RH <path>" below). Every row is dated by when Red Hat last changed
// its document: document.tracking.current_release_date, which is also the date
// changes.csv gives it. Two documents reach the adapter through the bulk archive
// csaf_vex_2026-09-27.tar.zst, the rest through changes.csv lines after that
// date. The archive path stamps its documents with the archive's date instead
// (pkg/source/csafadapter/archive.go: "All archive docs share the archive
// date"), so the cases on those two documents carry a KnownBug until Phase 5c.
// Composite products inherit the identifiers of both sides of their
// relationship (the component's PURL and the platform's CPE).
const (
	tsRH47699  = "2026-09-22T14:54:37Z" // 2026/cve-2026-47699.json document.tracking.current_release_date (archive)
	tsRH6270   = "2026-09-23T03:13:07Z" // 2025/cve-2025-6270.json document.tracking.current_release_date (archive)
	tsRH20012  = "2026-09-29T08:01:18Z" // changes.csv "2025/cve-2025-20012.json"
	tsRH94282  = "2026-09-29T10:04:38Z" // changes.csv "2026/cve-2026-94282.json"
	tsRH88265  = "2026-10-02T13:59:45Z" // changes.csv "2026/cve-2026-88265.json"
	tsRH34034  = "2026-10-03T03:00:07Z" // changes.csv "2023/cve-2023-34034.json"
	tsRH101295 = "2026-09-30T15:14:19Z" // changes.csv "2026/cve-2026-101295.json"

	// archiveDateBug is the KnownBug of every case on an archive-seeded document.
	archiveDateBug = "rows seeded from the bulk archive are dated by the archive (2026-09-27), not by the document's own tracking.current_release_date (Phase 5c)"
)

var rh20012Fixed = []string{
	"cpe:/o:redhat:enterprise_linux:8::baseos",
	"cpe:/o:redhat:enterprise_linux:9::baseos",
	"cpe:/o:redhat:rhel_aus:7.7::server",
	"cpe:/o:redhat:rhel_aus:8.2::baseos",
	"cpe:/o:redhat:rhel_aus:8.4::baseos",
	"cpe:/o:redhat:rhel_aus:8.6::baseos",
	"cpe:/o:redhat:rhel_e4s:8.6::baseos",
	"cpe:/o:redhat:rhel_e4s:8.8::baseos",
	"cpe:/o:redhat:rhel_e4s:9.0::baseos",
	"cpe:/o:redhat:rhel_e4s:9.2::baseos",
	"cpe:/o:redhat:rhel_els:7",
	"cpe:/o:redhat:rhel_eus:9.4::baseos",
	"cpe:/o:redhat:rhel_tus:8.6::baseos",
	"cpe:/o:redhat:rhel_tus:8.8::baseos",
	"pkg:rpm/redhat/microcode_ctl-debuginfo@2.1-53.26.el7_7.1?arch=x86_64&epoch=2",
	"pkg:rpm/redhat/microcode_ctl-debuginfo@2.1-73.24.el7_9?arch=x86_64&epoch=2",
	"pkg:rpm/redhat/microcode_ctl@2.1-53.26.el7_7.1?arch=src&epoch=2",
	"pkg:rpm/redhat/microcode_ctl@2.1-53.26.el7_7.1?arch=x86_64&epoch=2",
	"pkg:rpm/redhat/microcode_ctl@2.1-73.24.el7_9?arch=src&epoch=2",
	"pkg:rpm/redhat/microcode_ctl@2.1-73.24.el7_9?arch=x86_64&epoch=2",
	"pkg:rpm/redhat/microcode_ctl@20191115-4.20250512.1.el8_2?arch=src&epoch=4",
	"pkg:rpm/redhat/microcode_ctl@20191115-4.20250512.1.el8_2?arch=x86_64&epoch=4",
	"pkg:rpm/redhat/microcode_ctl@20210216-1.20250512.1.el8_4?arch=src&epoch=4",
	"pkg:rpm/redhat/microcode_ctl@20210216-1.20250512.1.el8_4?arch=x86_64&epoch=4",
	"pkg:rpm/redhat/microcode_ctl@20220207-1.20250512.1.el8_6?arch=src&epoch=4",
	"pkg:rpm/redhat/microcode_ctl@20220207-1.20250512.1.el8_6?arch=x86_64&epoch=4",
	"pkg:rpm/redhat/microcode_ctl@20220207-1.20250512.1.el9_0?arch=noarch&epoch=4",
	"pkg:rpm/redhat/microcode_ctl@20220207-1.20250512.1.el9_0?arch=src&epoch=4",
	"pkg:rpm/redhat/microcode_ctl@20220809-2.20250512.1.el8_8?arch=src&epoch=4",
	"pkg:rpm/redhat/microcode_ctl@20220809-2.20250512.1.el8_8?arch=x86_64&epoch=4",
	"pkg:rpm/redhat/microcode_ctl@20220809-2.20250512.1.el9_2?arch=noarch&epoch=4",
	"pkg:rpm/redhat/microcode_ctl@20220809-2.20250512.1.el9_2?arch=src&epoch=4",
	"pkg:rpm/redhat/microcode_ctl@20230808-2.20250512.1.el9_4?arch=noarch&epoch=4",
	"pkg:rpm/redhat/microcode_ctl@20230808-2.20250512.1.el9_4?arch=src&epoch=4",
	"pkg:rpm/redhat/microcode_ctl@20250211-1.20250512.1.el9_6?arch=noarch&epoch=4",
	"pkg:rpm/redhat/microcode_ctl@20250211-1.20250512.1.el9_6?arch=src&epoch=4",
	"pkg:rpm/redhat/microcode_ctl@20250512-1.el8_10?arch=src&epoch=4",
	"pkg:rpm/redhat/microcode_ctl@20250512-1.el8_10?arch=x86_64&epoch=4",
}

// rh34034 is CVE-2023-34034's answer to a CVE-only query: every identifier
// the document names, grouped by verdict.
func rh34034() []Stmt {
	return []Stmt{
		{CVE: "CVE-2023-34034", Supplier: "redhat", Status: "affected", Timestamp: tsRH34034, Notes: notes("csaf", ""),
			Products: ss("cpe:/a:redhat:jboss_enterprise_bpms_platform:7", "cpe:/a:redhat:jboss_fuse:6"),
			Evidence: "RH 2023/cve-2023-34034.json product_status.known_affected: red_hat_jboss_fuse_6:spring-security, red_hat_process_automation_7:spring-security (spring-security has no helper; the platforms' CPEs)"},
		{CVE: "CVE-2023-34034", Supplier: "redhat", Status: "fixed", Timestamp: tsRH34034, Notes: notes("csaf", ""),
			Products: ss("cpe:/a:redhat:jboss_fuse:7.12"),
			Evidence: "RH 2023/cve-2023-34034.json product_status.fixed: \"Red Hat Fuse 7.12.1\" (product_name with cpe:/a:redhat:jboss_fuse:7.12)"},
		{CVE: "CVE-2023-34034", Supplier: "redhat", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: tsRH34034, Notes: notes("csaf", ""),
			Products: ss("cpe:/a:redhat:camel_quarkus:2", "cpe:/a:redhat:quarkus:2", "cpe:/a:redhat:red_hat_single_sign_on:7",
				"pkg:maven/io.quarkus/quarkus-spring-security?repository_url=https://maven.repository.redhat.com/ga/&type=jar"),
			Evidence: "RH 2023/cve-2023-34034.json product_status.known_not_affected (3 products) + flags[0] label vulnerable_code_not_present"},
	}
}

func redhatCases() []Case {
	return []Case{
		{
			Name: "redhat/cve-only/fixed, known_affected and known_not_affected with justification", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2023-34034")}, Status: 200, Rows: 7, Want: rh34034(),
		},
		{
			Name: "redhat/cve-only/under_investigation", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2026-94282")}, Status: 200, Rows: 3,
			Want: []Stmt{{CVE: "CVE-2026-94282", Supplier: "redhat", Status: "under_investigation", Timestamp: tsRH94282, Notes: notes("csaf", ""),
				Products: ss("cpe:/o:redhat:enterprise_linux:10", "pkg:rpm/redhat/libXi-devel", "pkg:rpm/redhat/libXi?arch=src"),
				Evidence: "RH 2026/cve-2026-94282.json product_status.under_investigation: red_hat_enterprise_linux_10:libXi-devel, red_hat_enterprise_linux_10:libXi.src"}},
		},
		{
			Name: "redhat/cve-only/known_affected with module streams and Hummingbird fixes", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2026-88265")}, Status: 200, Rows: 19,
			Want: []Stmt{
				{CVE: "CVE-2026-88265", Supplier: "redhat", Status: "affected", Timestamp: tsRH88265, Notes: notes("csaf", ""),
					Products: ss("cpe:/a:redhat:openshift:4", "cpe:/o:redhat:enterprise_linux:10", "cpe:/o:redhat:enterprise_linux:8", "cpe:/o:redhat:enterprise_linux:9",
						"pkg:oci/ose-rhel-coreos-8?repository_url=registry.redhat.io/openshift/ose-rhel-coreos-8",
						"pkg:oci/ose-rhel-coreos-9?repository_url=registry.redhat.io/openshift/ose-rhel-coreos-9",
						"pkg:rpm/redhat/crun", "pkg:rpm/redhat/crun-krun", "pkg:rpm/redhat/crun?arch=src",
						"pkg:rpm/redhat/crun?arch=src&rpmmod=container-tools:rhel8", "pkg:rpm/redhat/crun?rpmmod=container-tools:rhel8"),
					Evidence: "RH 2026/cve-2026-88265.json product_status.known_affected (11 products: RHEL 8 crun(.src) in module container-tools:rhel8, RHEL 9 and RHEL 10 crun, crun.src, crun-krun, OCP 4 crun(.src) and two coreos images)"},
				{CVE: "CVE-2026-88265", Supplier: "redhat", Status: "fixed", Timestamp: tsRH88265, Notes: notes("csaf", ""),
					Products: ss("cpe:/a:redhat:hummingbird:1",
						"pkg:rpm/redhat/crun-krun@1.30-1.hum1?arch=aarch64&distro=hummingbird-20251124&repository_id=public-hummingbird-aarch64-rpms",
						"pkg:rpm/redhat/crun-krun@1.30-1.hum1?arch=x86_64&distro=hummingbird-20251124&repository_id=public-hummingbird-x86_64-rpms",
						"pkg:rpm/redhat/crun-wasm@1.30-1.hum1?arch=aarch64&distro=hummingbird-20251124&repository_id=public-hummingbird-aarch64-rpms",
						"pkg:rpm/redhat/crun-wasm@1.30-1.hum1?arch=x86_64&distro=hummingbird-20251124&repository_id=public-hummingbird-x86_64-rpms",
						"pkg:rpm/redhat/crun@1.30-1.hum1?arch=aarch64&distro=hummingbird-20251124&repository_id=public-hummingbird-aarch64-rpms",
						"pkg:rpm/redhat/crun@1.30-1.hum1?arch=src&distro=hummingbird-20251124&repository_id=public-hummingbird-source-rpms",
						"pkg:rpm/redhat/crun@1.30-1.hum1?arch=x86_64&distro=hummingbird-20251124&repository_id=public-hummingbird-x86_64-rpms"),
					Evidence: "RH 2026/cve-2026-88265.json product_status.fixed (7 Red Hat Hardened Images products)"},
			},
		},
		{
			Name: "redhat/cve-only/archive-seeded document", Endpoint: epStatements, KnownBug: archiveDateBug,
			Body: body{"cves": ss("CVE-2025-6270")}, Status: 200, Rows: 2,
			Want: []Stmt{{CVE: "CVE-2025-6270", Supplier: "redhat", Status: "affected", Timestamp: tsRH6270, Notes: notes("csaf", ""),
				Products: ss("cpe:/a:redhat:enterprise_linux_ai:1", "pkg:rpm/redhat/hdf5?arch=src"),
				Evidence: "RH 2025/cve-2025-6270.json (in csaf_vex_2026-09-27.tar.zst) product_status.known_affected: red_hat_enterprise_linux_ai_(rhel_ai):hdf5.src; document.tracking.current_release_date 2026-09-23T03:13:07+00:00"}},
		},
		{
			Name: "redhat/cve-only/one component, two streams, two verdicts", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2025-20012")}, Status: 200, Rows: 44,
			Want: []Stmt{
				{CVE: "CVE-2025-20012", Supplier: "redhat", Status: "affected", Timestamp: tsRH20012, Notes: notes("csaf", ""),
					Products: ss("cpe:/o:redhat:enterprise_linux:6", "pkg:rpm/redhat/microcode_ctl", "pkg:rpm/redhat/microcode_ctl?arch=src"),
					Evidence: "RH 2025/cve-2025-20012.json product_status.known_affected: red_hat_enterprise_linux_6:microcode_ctl, red_hat_enterprise_linux_6:microcode_ctl.src"},
				{CVE: "CVE-2025-20012", Supplier: "redhat", Status: "fixed", Timestamp: tsRH20012, Notes: notes("csaf", ""), Products: rh20012Fixed,
					Evidence: "RH 2025/cve-2025-20012.json product_status.fixed (30 products — 7Server AUS/ELS, BaseOS 8.x/9.x Z streams — naming 24 PURLs and 14 platform CPEs)"},
				{CVE: "CVE-2025-20012", Supplier: "redhat", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: tsRH20012, Notes: notes("csaf", ""),
					Products: ss("cpe:/o:redhat:enterprise_linux:10", "pkg:rpm/redhat/microcode_ctl", "pkg:rpm/redhat/microcode_ctl?arch=src"),
					Evidence: "RH 2025/cve-2025-20012.json product_status.known_not_affected: red_hat_enterprise_linux_10:microcode_ctl(.src) + flag vulnerable_code_not_present"},
			},
		},
		{
			Name: "redhat/cve-only/archive-seeded, one source package in two streams", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2026-47699")}, Status: 200, Rows: 5,
			KnownBug: archiveDateBug,
			Want: []Stmt{
				{CVE: "CVE-2026-47699", Supplier: "redhat", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: tsRH47699, Notes: notes("csaf", ""),
					Products: ss("cpe:/o:redhat:enterprise_linux:10", "pkg:rpm/redhat/trustee-guest-components?arch=src", "pkg:rpm/redhat/trustee-kbs"),
					Evidence: "RH 2026/cve-2026-47699.json product_status.known_not_affected: red_hat_enterprise_linux_10:trustee-guest-components.src, :trustee-kbs + flag vulnerable_code_not_present"},
				{CVE: "CVE-2026-47699", Supplier: "redhat", Status: "under_investigation", Timestamp: tsRH47699, Notes: notes("csaf", ""),
					Products: ss("cpe:/o:redhat:enterprise_linux:9", "pkg:rpm/redhat/trustee-guest-components?arch=src"),
					Evidence: "RH 2026/cve-2026-47699.json product_status.under_investigation: red_hat_enterprise_linux_9:trustee-guest-components.src"},
			},
		},
		{
			Name: "redhat/purl/Hummingbird distro is identity, distro-stripped candidate reaches RHEL rows", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2026-88265"), "products": ss("pkg:rpm/redhat/crun@1.30-1.hum1?arch=x86_64&distro=hummingbird-20251124")},
			Status: 200, Rows: 7,
			Want: []Stmt{
				{CVE: "CVE-2026-88265", Supplier: "redhat", Status: "fixed", Timestamp: tsRH88265, Notes: notes("csaf", "direct"),
					Products: ss("pkg:rpm/redhat/crun?distro=hummingbird-20251124"),
					Evidence: "RH 2026/cve-2026-88265.json product_status.fixed: Red Hat Hardened Images:crun-0:1.30-1.hum1@{aarch64,src,x86_64} (PURLs carry distro=hummingbird-20251124)"},
				{CVE: "CVE-2026-88265", Supplier: "redhat", Status: "affected", Timestamp: tsRH88265, Notes: notes("csaf", "direct"),
					Products: ss("pkg:rpm/redhat/crun?distro=hummingbird-20251124"),
					Evidence: "RH 2026/cve-2026-88265.json product_status.known_affected: crun, crun.src, crun::container-tools:rhel8, crun.src::container-tools:rhel8 (bare PURLs; docs/api.md: rpm distro is strip-and-also)"},
			},
		},
		{
			Name: "redhat/purl/package in a module stream (rpmmod)", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2026-88265"), "products": ss("pkg:rpm/redhat/crun@1.14.3-2.module+el8.10.0+22000+aaaaaaaa?arch=x86_64&distro=redhat-8.10")},
			Status: 200, Rows: 4,
			Want: []Stmt{{CVE: "CVE-2026-88265", Supplier: "redhat", Status: "affected", Timestamp: tsRH88265, Notes: notes("csaf", "direct"),
				Products: ss("pkg:rpm/redhat/crun?distro=redhat-8.10"),
				Evidence: "RH 2026/cve-2026-88265.json product_status.known_affected: red_hat_enterprise_linux_8:crun::container-tools:rhel8 (pkg:rpm/redhat/crun?rpmmod=container-tools:rhel8) and the .src, RHEL 9/10/OCP crun, crun.src"}},
		},
		{
			Name: "redhat/purl/repository_id reaches the platform CPE via the alias", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2026-88265"), "products": ss("pkg:rpm/redhat/crun@1.30-1.hum1?arch=x86_64&repository_id=public-hummingbird-x86_64-rpms")},
			Status: 200, Rows: 5,
			Want: []Stmt{
				{CVE: "CVE-2026-88265", Supplier: "redhat", Status: "affected", Timestamp: tsRH88265, Notes: notes("csaf", "direct"),
					Products: ss("pkg:rpm/redhat/crun"),
					Evidence: "RH 2026/cve-2026-88265.json product_status.known_affected: crun, crun.src, crun(.src)::container-tools:rhel8"},
				{CVE: "CVE-2026-88265", Supplier: "redhat", Status: "fixed", Timestamp: tsRH88265, Notes: notes("csaf", "via_alias"),
					Products: ss("pkg:rpm/redhat/crun"),
					Evidence: "RH 2026/cve-2026-88265.json product_status.fixed on platform \"Red Hat Hardened Images\" (cpe:/a:redhat:hummingbird:1); repository-to-cpe.json public-hummingbird-x86_64-rpms -> cpe:/a:redhat:hummingbird:1"},
			},
		},
		{
			Name: "redhat/purl/without repository_id the platform CPE is not reached", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2026-88265"), "products": ss("pkg:rpm/redhat/crun@1.30-1.hum1?arch=x86_64")},
			Status: 200, Rows: 4,
			Want: []Stmt{{CVE: "CVE-2026-88265", Supplier: "redhat", Status: "affected", Timestamp: tsRH88265, Notes: notes("csaf", "direct"),
				Products: ss("pkg:rpm/redhat/crun"),
				Evidence: "RH 2026/cve-2026-88265.json product_status.known_affected: crun, crun.src, crun(.src)::container-tools:rhel8"}},
		},
		{
			Name: "redhat/cpe/direct EUS stream", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2025-20012"), "products": ss("cpe:/o:redhat:rhel_eus:9.4::baseos")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2025-20012", Supplier: "redhat", Status: "fixed", Timestamp: tsRH20012, Notes: notes("csaf", "direct"),
				Products: ss("cpe:/o:redhat:rhel_eus:9.4::baseos"),
				Evidence: "RH 2025/cve-2025-20012.json product_status.fixed: BaseOS-9.4.0.Z.EUS:microcode_ctl-4:20230808-2.20250512.1.el9_4.{noarch,src} (platform cpe:/o:redhat:rhel_eus:9.4::baseos)"}},
		},
		{
			Name: "redhat/cpe/prefix reaches the major-release not_affected", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2025-20012"), "products": ss("cpe:/o:redhat:enterprise_linux:10::baseos")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2025-20012", Supplier: "redhat", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: tsRH20012, Notes: notes("csaf", "via_cpe_prefix"),
				Products: ss("cpe:/o:redhat:enterprise_linux:10::baseos"),
				Evidence: "RH 2025/cve-2025-20012.json product_status.known_not_affected: red_hat_enterprise_linux_10:microcode_ctl (platform cpe:/o:redhat:enterprise_linux:10) + flag vulnerable_code_not_present"}},
		},
		{
			Name: "redhat/cpe/prefix reaches under_investigation", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2026-94282"), "products": ss("cpe:/o:redhat:enterprise_linux:10::appstream")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2026-94282", Supplier: "redhat", Status: "under_investigation", Timestamp: tsRH94282, Notes: notes("csaf", "via_cpe_prefix"),
				Products: ss("cpe:/o:redhat:enterprise_linux:10::appstream"),
				Evidence: "RH 2026/cve-2026-94282.json product_status.under_investigation (platform red_hat_enterprise_linux_10, cpe:/o:redhat:enterprise_linux:10)"}},
		},
		{
			Name: "redhat/purl/maven qualifiers are not identity", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2023-34034"), "products": ss("pkg:maven/io.quarkus/quarkus-spring-security@2.16.7.Final-redhat-00001?type=jar")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2023-34034", Supplier: "redhat", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: tsRH34034, Notes: notes("csaf", "direct"),
				Products: ss("pkg:maven/io.quarkus/quarkus-spring-security"),
				Evidence: "RH 2023/cve-2023-34034.json product_status.known_not_affected: red_hat_build_of_quarkus:quarkus-spring-security (purl ...quarkus-spring-security?repository_url=...&type=jar) + flag vulnerable_code_not_present"}},
		},
		{
			Name: "redhat/broad/products only", Endpoint: epStatements,
			Body:   body{"products": ss("pkg:rpm/redhat/libXi-devel@1.8.1-9.el10?arch=x86_64&distro=redhat-10.0")},
			Status: 200, Rows: 1, Headers: map[string]string{"X-Reel-Mode": "broad", "X-Reel-CVE": "", "X-Reel-Grouped": "1", "X-Reel-Truncated": "", "X-Reel-Arch": ""},
			Want: []Stmt{{CVE: "CVE-2026-94282", Supplier: "redhat", Status: "under_investigation", Timestamp: tsRH94282, Notes: notes("csaf", "direct"),
				Products: ss("pkg:rpm/redhat/libXi-devel?distro=redhat-10.0"),
				Evidence: "RH 2026/cve-2026-94282.json product_status.under_investigation: red_hat_enterprise_linux_10:libXi-devel (the only document naming libXi-devel)"}},
		},
		{
			Name: "redhat/purl/under_investigation, Trivy rpm", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2026-94282"), "products": ss("pkg:rpm/redhat/libXi@1.8.1-9.el10?arch=x86_64&distro=redhat-10.0")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2026-94282", Supplier: "redhat", Status: "under_investigation", Timestamp: tsRH94282, Notes: notes("csaf", "direct"),
				Products: ss("pkg:rpm/redhat/libXi?distro=redhat-10.0"),
				Evidence: "RH 2026/cve-2026-94282.json product_status.under_investigation: red_hat_enterprise_linux_10:libXi.src (pkg:rpm/redhat/libXi?arch=src)"}},
		},
		{
			Name: "redhat/purl/known_not_affected, Trivy rpm", Endpoint: epStatements, KnownBug: archiveDateBug,
			Body:   body{"cves": ss("CVE-2026-47699"), "products": ss("pkg:rpm/redhat/trustee-kbs@0.10.0-1.el10?arch=x86_64&distro=redhat-10.0")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2026-47699", Supplier: "redhat", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: tsRH47699, Notes: notes("csaf", "direct"),
				Products: ss("pkg:rpm/redhat/trustee-kbs?distro=redhat-10.0"),
				Evidence: "RH 2026/cve-2026-47699.json product_status.known_not_affected: red_hat_enterprise_linux_10:trustee-kbs + flag vulnerable_code_not_present"}},
		},
		{
			// The vendor last changed both documents before the archive was cut;
			// a since between those dates and the archive date excludes them.
			Name: "redhat/filter/since excludes archive-seeded documents changed before it", Endpoint: epStatements, KnownBug: archiveDateBug,
			Body:   body{"cves": ss("CVE-2025-6270", "CVE-2026-47699"), "since": "2026-09-25T00:00:00Z"},
			Status: 204, Rows: 0,
		},
		{
			Name: "redhat/cve-only/container images under investigation", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2026-101295")}, Status: 200, Rows: 5,
			Want: []Stmt{{CVE: "CVE-2026-101295", Supplier: "redhat", Status: "under_investigation", Timestamp: tsRH101295, Notes: notes("csaf", ""),
				Products: ss("cpe:/a:redhat:assisted_installer:2", "cpe:/a:redhat:openshift:4",
					"pkg:oci/agent-preinstall-image-builder-rhel9?repository_url=registry.redhat.io/assisted/agent-preinstall-image-builder-rhel9",
					"pkg:oci/oc-mirror-plugin-rhel8?repository_url=registry.redhat.io/openshift4/oc-mirror-plugin-rhel8",
					"pkg:oci/oc-mirror-plugin-rhel9?repository_url=registry.redhat.io/openshift4/oc-mirror-plugin-rhel9"),
				Evidence: "RH 2026/cve-2026-101295.json product_status.under_investigation (3 container products)"}},
		},
		{
			Name: "redhat/purl/a Trivy image PURL (digest, tag) reaches its image", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2026-101295"),
				"products": ss("pkg:oci/oc-mirror-plugin-rhel9@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef?arch=amd64&repository_url=registry.redhat.io/openshift4/oc-mirror-plugin-rhel9&tag=v4.18")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2026-101295", Supplier: "redhat", Status: "under_investigation", Timestamp: tsRH101295, Notes: notes("csaf", "direct"),
				Products: ss("pkg:oci/oc-mirror-plugin-rhel9"),
				Evidence: "RH 2026/cve-2026-101295.json product_status.under_investigation: ...:openshift4/oc-mirror-plugin-rhel9 (pkg:oci/oc-mirror-plugin-rhel9?repository_url=...); docs/api.md: repository_url is not part of an rpm/oci base"}},
		},
		{
			// docs/api.md: repository_id is "Required on Red Hat queries that need
			// EUS / AUS / E4S coverage".
			Name: "redhat/purl/EUS repository_id reaches the EUS stream via the alias (fixed)", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2025-20012"), "statuses": ss("fixed"),
				"products": ss("pkg:rpm/redhat/microcode_ctl@20230808-2.20250512.1.el9_4?arch=noarch&distro=redhat-9.4&epoch=4&repository_id=rhel-9-for-x86_64-baseos-eus-rpms")},
			Status: 200, Rows: 23,
			Want: []Stmt{
				{CVE: "CVE-2025-20012", Supplier: "redhat", Status: "fixed", Timestamp: tsRH20012, Notes: notes("csaf", "direct"),
					Products: ss("pkg:rpm/redhat/microcode_ctl?distro=redhat-9.4"),
					Evidence: "RH 2025/cve-2025-20012.json product_status.fixed: 22 microcode_ctl PURLs (the other 2 of the 24 are microcode_ctl-debuginfo)"},
				{CVE: "CVE-2025-20012", Supplier: "redhat", Status: "fixed", Timestamp: tsRH20012, Notes: notes("csaf", "via_alias"),
					Products: ss("pkg:rpm/redhat/microcode_ctl?distro=redhat-9.4"),
					Evidence: "RH 2025/cve-2025-20012.json product_status.fixed: BaseOS-9.4.0.Z.EUS:microcode_ctl (platform cpe:/o:redhat:rhel_eus:9.4::baseos); repository-to-cpe.json rhel-9-for-x86_64-baseos-eus-rpms -> rhel_eus:9.{0,2,4,6,8}::baseos"},
			},
		},
		{
			Name: "redhat/purl/Trivy microcode_ctl: every verdict the vendor states for the package", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2025-20012"), "products": ss("pkg:rpm/redhat/microcode_ctl@20250211-1.20250512.1.el9_6?arch=noarch&distro=redhat-9.6&epoch=4")},
			Status: 200, Rows: 26,
			Want: []Stmt{
				{CVE: "CVE-2025-20012", Supplier: "redhat", Status: "fixed", Timestamp: tsRH20012, Notes: notes("csaf", "direct"),
					Products: ss("pkg:rpm/redhat/microcode_ctl?distro=redhat-9.6"),
					Evidence: "RH 2025/cve-2025-20012.json product_status.fixed: 22 microcode_ctl PURLs across the AUS/E4S/EUS/TUS/ELS and main streams"},
				{CVE: "CVE-2025-20012", Supplier: "redhat", Status: "affected", Timestamp: tsRH20012, Notes: notes("csaf", "direct"),
					Products: ss("pkg:rpm/redhat/microcode_ctl?distro=redhat-9.6"),
					Evidence: "RH 2025/cve-2025-20012.json product_status.known_affected: red_hat_enterprise_linux_6:microcode_ctl(.src)"},
				{CVE: "CVE-2025-20012", Supplier: "redhat", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: tsRH20012, Notes: notes("csaf", "direct"),
					Products: ss("pkg:rpm/redhat/microcode_ctl?distro=redhat-9.6"),
					Evidence: "RH 2025/cve-2025-20012.json product_status.known_not_affected: red_hat_enterprise_linux_10:microcode_ctl(.src) + flag vulnerable_code_not_present"},
			},
		},
		{
			Name: "redhat/purl/RHEL 10 repository_id reaches the major-release CPE via alias and prefix", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2026-94282"), "products": ss("pkg:rpm/redhat/libXi@1.8.1-9.el10?arch=x86_64&distro=redhat-10.0&repository_id=rhel-10-for-x86_64-baseos-rpms")},
			Status: 200, Rows: 2,
			Want: []Stmt{
				{CVE: "CVE-2026-94282", Supplier: "redhat", Status: "under_investigation", Timestamp: tsRH94282, Notes: notes("csaf", "direct"),
					Products: ss("pkg:rpm/redhat/libXi?distro=redhat-10.0"),
					Evidence: "RH 2026/cve-2026-94282.json product_status.under_investigation: red_hat_enterprise_linux_10:libXi.src (pkg:rpm/redhat/libXi?arch=src)"},
				{CVE: "CVE-2026-94282", Supplier: "redhat", Status: "under_investigation", Timestamp: tsRH94282, Notes: notes("csaf", "via_alias"),
					Products: ss("pkg:rpm/redhat/libXi?distro=redhat-10.0"),
					Evidence: "RH 2026/cve-2026-94282.json: platform red_hat_enterprise_linux_10 is cpe:/o:redhat:enterprise_linux:10; repository-to-cpe.json rhel-10-for-x86_64-baseos-rpms -> cpe:/o:redhat:enterprise_linux:10::baseos, whose 5-part prefix is that CPE"},
			},
		},
		{
			Name: "redhat/negative/another vendor's namespace", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2026-94282"), "products": ss("pkg:rpm/suse/libXi-devel@1.8.1-9.1?arch=x86_64")},
			Status: 204, Rows: 0,
		},
		{
			Name: "redhat/negative/a CVE no fixture holds", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2026-94283")},
			Status: 204, Rows: 0,
		},
		{
			Name: "redhat/negative/hummingbird distro does not reach a RHEL query", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2026-88265"), "products": ss("pkg:rpm/redhat/crun-wasm@1.14.4-1.el9?arch=x86_64&distro=redhat-9.6")},
			Status: 204, Rows: 0,
		},
	}
}
