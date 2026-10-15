//go:build integration

package acceptance

// SUSE Rancher VEX hub: per-package OpenVEX files in the repository snapshot
// github.com/rancher/vexhub/archive/refs/heads/main.tar.gz ("RV <path>" below,
// relative to vexhub-main/). A statement's product @id is the image or module
// the verdict is about (the scope, normalised: repository_url kept, version and
// tag dropped); its subcomponent is the package a scanner matches. A scoped row
// is withheld unless the caller names its scope (docs/api.md, "Product-scoped
// statements").

const (
	scopeSachetDocker = "pkg:oci/mirrored-messagebird-sachet?repository_url=index.docker.io/rancher/mirrored-messagebird-sachet"
	scopeSachetSUSE   = "pkg:oci/mirrored-messagebird-sachet?repository_url=registry.suse.com/rancher/mirrored-messagebird-sachet"
	scopeKubeOVN      = "pkg:oci/kube-ovn?repository_url=index.docker.io/kubeovn/kube-ovn"
	scopeNginx        = "pkg:oci/nginx-ingress-controller?repository_url=index.docker.io/rancher/nginx-ingress-controller"
	scopeCalico       = "pkg:golang/github.com/projectcalico/calico/lib/std"
	scopeOPA          = "pkg:golang/github.com/open-policy-agent/opa"

	tsRVSachet = "2026-09-22T18:31:01Z"
	tsRVKube   = "2026-08-04T17:52:52Z"
	tsRVCalico = "2026-08-05T05:12:11Z"
	tsRVOPA    = "2026-06-19T00:00:00Z"

	evSachetDocker = "RV pkg/oci/index.docker.io/rancher/mirrored-messagebird-sachet/scan.openvex.json statements[0]: CVE-2022-37434, subcomponent pkg:apk/alpine/zlib, not_affected/vulnerable_code_not_in_execute_path"
	evSachetSUSE   = "RV pkg/oci/registry.suse.com/rancher/mirrored-messagebird-sachet/scan.openvex.json statements[0]: CVE-2022-37434, subcomponent pkg:apk/alpine/zlib, not_affected/vulnerable_code_not_in_execute_path"
	evKubeOVN      = "RV pkg/oci/index.docker.io/kubeovn/kube-ovn/scan.openvex.json statements[0]: CVE-2026-24061, subcomponent pkg:deb/ubuntu/inetutils-ping, not_affected/vulnerable_code_not_in_execute_path"
	evOPANet22872  = "RV pkg/golang/github.com/open-policy-agent/opa/scan.openvex.json statements[2,3]: CVE-2025-22872, subcomponent pkg:golang/golang.org/x/net@v0.35.0, not_affected/vulnerable_code_not_present"
	evOPANet       = "RV pkg/golang/github.com/open-policy-agent/opa/scan.openvex.json statements[0,1]: CVE-2025-22870, products opa and opa@v1.2.0, subcomponent pkg:golang/golang.org/x/net@v0.35.0, not_affected/vulnerable_code_not_present"
)

func rancherSachet(scope, ev string, products ...string) Stmt {
	return Stmt{CVE: "CVE-2022-37434", Supplier: "rancher", Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path",
		Timestamp: tsRVSachet, Notes: scoped(notes("openvex", ""), scope), Products: products, Evidence: ev}
}

func rancherOPA(notesText string, products ...string) Stmt {
	return Stmt{CVE: "CVE-2025-22870", Supplier: "rancher", Status: "not_affected", Justification: "vulnerable_code_not_present",
		Timestamp: tsRVOPA, Notes: notesText, Products: products, Evidence: evOPANet}
}

func rancherCases() []Case {
	opaDirect := scoped(notes("openvex", "direct"), scopeOPA)
	return []Case{
		{
			Name: "rancher/negative/a scoped row without its scope", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2026-24061")},
			Status: 204, Rows: 0,
		},
		{
			Name: "rancher/cve-only/scoped not_affected with its scope", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2026-24061"), "scopes": ss(scopeKubeOVN)}, Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2026-24061", Supplier: "rancher", Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path",
				Timestamp: tsRVKube, Notes: scoped(notes("openvex", ""), scopeKubeOVN), Products: ss("pkg:deb/ubuntu/inetutils-ping"), Evidence: evKubeOVN}},
		},
		{
			Name: "rancher/cve-only/two scopes, same subcomponent: only the one named", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2022-37434"), "vendors": ss("rancher"), "scopes": ss(scopeSachetSUSE)}, Status: 200, Rows: 1,
			Want: []Stmt{rancherSachet(scopeSachetSUSE, evSachetSUSE, "pkg:apk/alpine/zlib")},
		},
		{
			Name: "rancher/cve-only/two scopes named, two statements", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2022-37434"), "vendors": ss("rancher"), "scopes": ss(scopeSachetSUSE, scopeSachetDocker)}, Status: 200, Rows: 2,
			Want: []Stmt{
				rancherSachet(scopeSachetSUSE, evSachetSUSE, "pkg:apk/alpine/zlib"),
				rancherSachet(scopeSachetDocker, evSachetDocker, "pkg:apk/alpine/zlib"),
			},
		},
		{
			Name: "rancher/cve-only/a scope with digest, tag and an encoded repository_url normalises", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2022-37434"), "vendors": ss("rancher"),
				"scopes": ss("pkg:oci/mirrored-messagebird-sachet@sha256:0f0e0d0c0b0a?repository_url=index.docker.io%2Francher%2Fmirrored-messagebird-sachet&tag=v0.3.0")},
			Status: 200, Rows: 1,
			Want: []Stmt{rancherSachet(scopeSachetDocker, evSachetDocker+" (docs/api.md: scopes keep repository_url, drop tag and digest)", "pkg:apk/alpine/zlib")},
		},
		{
			Name: "rancher/cve-only/one module written with and without its version is one scope", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2026-39822", "CVE-2026-42505"), "scopes": ss(scopeCalico)}, Status: 200, Rows: 2,
			Want: []Stmt{
				{CVE: "CVE-2026-39822", Supplier: "rancher", Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path", Timestamp: tsRVCalico,
					Notes: scoped(notes("openvex", ""), scopeCalico), Products: ss("pkg:golang/stdlib@v1.25.11"),
					Evidence: "RV pkg/golang/github.com/projectcalico/calico/lib/std/scan.openvex.json statements[0,1]: products calico/lib/std and calico/lib/std@v3.32.0, subcomponent stdlib@v1.25.11"},
				{CVE: "CVE-2026-42505", Supplier: "rancher", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: tsRVCalico,
					Notes: scoped(notes("openvex", ""), scopeCalico), Products: ss("pkg:golang/stdlib@v1.25.11"),
					Evidence: "RV pkg/golang/github.com/projectcalico/calico/lib/std/scan.openvex.json statements[2,3]: products calico/lib/std and calico/lib/std@v3.32.0, subcomponent stdlib@v1.25.11"},
			},
		},
		{
			// The resolver also tries a PURL without its distro (docs/api.md,
			// PURL identity rules), and this answer depends on it for deb: the
			// Rancher subcomponent has no distro, a scanner's deb PURL always does.
			Name: "rancher/exact/a scanner's deb PURL reaches a distro-less subcomponent", Endpoint: epStatements,
			Body: body{"cves": ss("CVE-2026-24061"), "scopes": ss(scopeKubeOVN),
				"products": ss("pkg:deb/ubuntu/inetutils-ping@2.5-3ubuntu4?arch=amd64&distro=ubuntu-24.04&epoch=2")},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2026-24061", Supplier: "rancher", Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path",
				Timestamp: tsRVKube, Notes: scoped(notes("openvex", "direct"), scopeKubeOVN), Products: ss("pkg:deb/ubuntu/inetutils-ping"),
				Evidence: evKubeOVN + " (no version: an empty list, rendered as the vendor's product_id: docs/api.md, Versioned queries)"}},
		},
		{
			Name: "rancher/negative/non-CVE statements are skipped", Endpoint: epStatements,
			Body:   body{"cves": ss("SUSE-FU-2026:21213-1"), "scopes": ss(scopeNginx)},
			Status: 204, Rows: 0,
		},
		{
			Name: "rancher/negative/a subcomponent with no package identifier is skipped", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2026-25680", "CVE-2026-25681", "CVE-2026-27136", "CVE-2026-42502", "CVE-2026-42506"), "scopes": ss(scopeNginx)},
			Status: 204, Rows: 0,
		},
		{
			Name: "rancher/negative/a scoped golang row without its scope", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2025-22870"), "products": ss("pkg:golang/golang.org/x/net@v0.35.0")},
			Status: 204, Rows: 0,
		},
		{
			Name: "rancher/negative/a scoped apk row without its scope", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2022-37434"), "products": ss("pkg:apk/alpine/zlib@1.2.12-r3?arch=x86_64&distro=3.16.2")},
			Status: 204, Rows: 0,
		},

		// Exact versions.
		{
			Name: "rancher/exact/listed version", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2025-22870"), "products": ss("pkg:golang/golang.org/x/net@v0.35.0"), "scopes": ss(scopeOPA)},
			Status: 200, Rows: 1,
			Want: []Stmt{rancherOPA(opaDirect, "pkg:golang/golang.org/x/net@v0.35.0")},
		},
		{
			Name: "rancher/exact/unlisted version gets nothing", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2025-22870"), "products": ss("pkg:golang/golang.org/x/net@v0.36.0"), "scopes": ss(scopeOPA)},
			Status: 204, Rows: 0,
		},
		{
			Name: "rancher/exact/versionless query gets the listed version", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2025-22870"), "products": ss("pkg:golang/golang.org/x/net"), "scopes": ss(scopeOPA)},
			Status: 200, Rows: 1,
			Want: []Stmt{rancherOPA(opaDirect, "pkg:golang/golang.org/x/net@v0.35.0")},
		},
		{
			Name: "rancher/exact/broad products only, with the scope", Endpoint: epStatements,
			Body:   body{"products": ss("pkg:golang/golang.org/x/net@v0.35.0"), "scopes": ss(scopeOPA)},
			Status: 200, Rows: 2,
			Want: []Stmt{
				rancherOPA(opaDirect, "pkg:golang/golang.org/x/net@v0.35.0"),
				{CVE: "CVE-2025-22872", Supplier: "rancher", Status: "not_affected", Justification: "vulnerable_code_not_present", Timestamp: tsRVOPA, Notes: opaDirect,
					Products: ss("pkg:golang/golang.org/x/net@v0.35.0"), Evidence: evOPANet22872},
			},
		},
		{
			// An empty list means the vendor stated the verdict with no version:
			// it matches any version, and is rendered as the vendor's
			// versionless product_id, never the caller's identifier
			// (docs/api.md, Versioned queries).
			Name: "rancher/exact/an empty version list matches any version", Endpoint: epStatements,
			Body:   body{"cves": ss("CVE-2022-37434"), "vendors": ss("rancher"), "products": ss("pkg:apk/alpine/zlib@1.2.12-r3?arch=x86_64&distro=3.16.2"), "scopes": ss(scopeSachetDocker)},
			Status: 200, Rows: 1,
			Want: []Stmt{{CVE: "CVE-2022-37434", Supplier: "rancher", Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path",
				Timestamp: tsRVSachet, Notes: scoped(notes("openvex", "direct"), scopeSachetDocker), Products: ss("pkg:apk/alpine/zlib"), Evidence: evSachetDocker}},
		},
	}
}
