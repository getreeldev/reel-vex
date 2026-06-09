package amazonalas

import (
	"encoding/xml"
	"time"

	"github.com/getreeldev/reel-vex/pkg/source"
)

// updatedLayout is how Amazon stamps <updated date="..."/> — a naive
// "YYYY-MM-DD HH:MM:SS" with no zone. We read it as UTC.
const updatedLayout = "2006-01-02 15:04:05"

// RepoMd is the repodata/repomd.xml index. We only care about the <data> entry
// whose type is "updateinfo".
type RepoMd struct {
	RepoList []Repo `xml:"data"`
}

// Repo is one <data> entry in repomd.xml.
type Repo struct {
	Type     string `xml:"type,attr"`
	Location struct {
		Href string `xml:"href,attr"`
	} `xml:"location"`
}

// updateInfoHref returns the href of the updateinfo <data> entry, or "" if the
// repo doesn't advertise one.
func (r RepoMd) updateInfoHref() string {
	for _, d := range r.RepoList {
		if d.Type == "updateinfo" {
			return d.Location.Href
		}
	}
	return ""
}

// UpdateInfo is the decompressed updateinfo.xml: a list of <update> advisories.
type UpdateInfo struct {
	ALASList []ALAS `xml:"update"`
}

// ALAS is one Amazon Linux Security Advisory (<update>). An advisory may
// reference multiple CVEs and ship multiple packages.
type ALAS struct {
	ID      string `xml:"id"`
	Updated struct {
		Date string `xml:"date,attr"`
	} `xml:"updated"`
	Severity   string      `xml:"severity"`
	Packages   []Package   `xml:"pkglist>collection>package"`
	References []Reference `xml:"references>reference"`
}

// Package is one fixed RPM in an advisory's pkglist. Amazon lists every arch
// of a package as a separate entry; we dedupe to one row per name.
type Package struct {
	Name    string `xml:"name,attr"`
	Epoch   string `xml:"epoch,attr"`
	Version string `xml:"version,attr"`
	Release string `xml:"release,attr"`
	Arch    string `xml:"arch,attr"`
}

// Reference is one <reference> in an advisory. Type "cve" carries the CVE id we
// key on; other types (self, bugzilla, ...) are ignored.
type Reference struct {
	ID   string `xml:"id,attr"`
	Type string `xml:"type,attr"`
}

// parseUpdateInfo decodes an updateinfo.xml document.
func parseUpdateInfo(b []byte) (UpdateInfo, error) {
	var ui UpdateInfo
	if err := xml.Unmarshal(b, &ui); err != nil {
		return UpdateInfo{}, err
	}
	return ui, nil
}

// parseRepoMd decodes a repomd.xml document.
func parseRepoMd(b []byte) (RepoMd, error) {
	var rm RepoMd
	if err := xml.Unmarshal(b, &rm); err != nil {
		return RepoMd{}, err
	}
	return rm, nil
}

// emitStatements turns one parsed updateinfo into source.Statements and feeds
// them to emit. The mapping (locked v1):
//   - one statement per (advisory CVE reference) × (deduped package name)
//   - Status "fixed"; the advisory ships the patched RPM
//   - Version is "version-release", prefixed "epoch:" when epoch != "0"
//   - BaseID is the distro-qualified, version-less PURL base (the matchable
//     identity); ProductID appends "@version" so two advisories that fix the
//     same package for the same CVE at different versions stay distinct rows
//     under the (vendor,cve,product_id,...) primary key.
func emitStatements(ui UpdateInfo, distro distroSpec, emit func(source.Statement) error) (counts, error) {
	var c counts
	for _, alas := range ui.ALASList {
		updated, err := time.Parse(updatedLayout, alas.Updated.Date)
		if err != nil {
			// A malformed/absent date shouldn't drop the advisory; fall back to
			// now() so the row still lands (provenance loses precision only).
			updated = time.Now().UTC()
			c.undatedAdvisories++
		} else {
			updated = updated.UTC()
		}

		var cves []string
		for _, ref := range alas.References {
			if ref.Type == "cve" && ref.ID != "" {
				cves = append(cves, ref.ID)
			}
		}
		if len(cves) == 0 {
			c.skippedNoCVE++
			continue
		}

		pkgs := dedupePackages(alas.Packages)
		for _, cve := range cves {
			for _, p := range pkgs {
				baseID := distro.baseID(p.Name)
				version := packageVersion(p)
				if err := emit(source.Statement{
					CVE:       cve,
					ProductID: baseID + "@" + version,
					BaseID:    baseID,
					Version:   version,
					IDType:    "purl",
					Status:    "fixed",
					Updated:   updated,
				}); err != nil {
					return c, err
				}
				c.emitted++
			}
		}
	}
	return c, nil
}

// packageVersion renders a package's version as "version-release", prefixed
// "epoch:" only when the epoch is meaningful (non-empty and not "0"). RPM
// treats a missing epoch as 0, so we elide it in that case to match the
// common scanner-emitted shape.
func packageVersion(p Package) string {
	v := p.Version + "-" + p.Release
	if p.Epoch != "" && p.Epoch != "0" {
		return p.Epoch + ":" + v
	}
	return v
}

// dedupePackages collapses an advisory's package list to one entry per package
// name. Amazon lists every arch (x86_64, i686, aarch64, noarch, ...) as a
// separate <package>; they share name+version+release, so the row we emit is
// arch-independent. First occurrence wins; order is preserved for stable tests.
func dedupePackages(pkgs []Package) []Package {
	seen := make(map[string]struct{}, len(pkgs))
	out := make([]Package, 0, len(pkgs))
	for _, p := range pkgs {
		if p.Name == "" {
			continue
		}
		if _, ok := seen[p.Name]; ok {
			continue
		}
		seen[p.Name] = struct{}{}
		out = append(out, p)
	}
	return out
}

// counts is per-sync bookkeeping for the completion log line.
type counts struct {
	emitted           int
	skippedNoCVE      int
	undatedAdvisories int
}
