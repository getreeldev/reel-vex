// Package resolver expands query identifiers into the set of candidates that
// should match stored VEX statements. Today it implements one rule: Red Hat's
// documented CPE-prefix contract. Future phases add alias-table lookups.
package resolver

import "strings"

// CPEPrefix returns the first 5 parts of a CPE 2.2 URI (part, vendor, product,
// version, update) with any trailing empty fields stripped. Returns the input
// unchanged for non-CPE-2.2-URI identifiers.
//
// Red Hat's SECDATA-1220 resolution documents that their CSAF VEX feed emits
// only the base CPE for unfixed advisories (e.g. cpe:/o:redhat:enterprise_linux:8)
// with no variant suffix, and that scanners should match by comparing the first
// 5 CPE parts. So a query carrying cpe:/o:redhat:enterprise_linux:8::baseos
// needs to be expanded to also consider cpe:/o:redhat:enterprise_linux:8.
//
// Examples:
//
//	cpe:/o:redhat:enterprise_linux:8::baseos    → cpe:/o:redhat:enterprise_linux:8
//	cpe:/a:redhat:rhel_eus:9.6::appstream       → cpe:/a:redhat:rhel_eus:9.6
//	cpe:/o:redhat:enterprise_linux:8            → cpe:/o:redhat:enterprise_linux:8
//	pkg:rpm/redhat/openssl@3.0                  → pkg:rpm/redhat/openssl@3.0  (passthrough)
func CPEPrefix(id string) string {
	if !strings.HasPrefix(id, "cpe:/") {
		return id
	}
	parts := strings.Split(strings.TrimPrefix(id, "cpe:/"), ":")
	if len(parts) > 5 {
		parts = parts[:5]
	}
	// Strip trailing empty fields so cpe:/a:redhat:rhel:8:: canonicalizes to cpe:/a:redhat:rhel:8.
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return "cpe:/" + strings.Join(parts, ":")
}
