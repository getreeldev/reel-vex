// Package ubuntuvex implements source.Adapter for Canonical's OpenVEX 0.2.0
// feed at https://security-metadata.canonical.com/vex/vex-all.tar.xz.
//
// Where the Ubuntu OVAL feed only ships rows for CVEs that have a USN, the
// OpenVEX feed includes pre-USN triage state (`not_affected`,
// `under_investigation`, `affected`) for every CVE Canonical has assessed.
// It is not a superset of OVAL: OVAL covers identifier shapes this feed
// spells differently (versioned binary packages such as golang-1.20-go,
// source vs binary package families), so both adapters run.
//
// The feed is one ~68 MB tar.xz containing 68,845 per-CVE OpenVEX 0.2.0 JSON
// files (2026-10) at vex/cve/<year>/CVE-<id>.json (plus USN-keyed files at vex/usn/
// which this adapter ignores). Each per-CVE document carries one or more
// statements; each statement carries one or more product identifiers in
// PURL form.
//
// Identifier translation: Canonical emits the `?distro=` qualifier in several
// shapes (`ubuntu/<codename>`, `esm-apps/<codename>`, `esm-infra/<codename>`,
// `esm-infra-legacy/<codename>`, and codename first, `trusty/esm`); scanners
// speak `ubuntu-<version>`.
// Normalize() in distro.go rewrites the qualifier, folding the tracks of one
// release onto one identifier.
//
// Version lists: every product carries the binary's current archive version,
// and one CVE can list the same package, arch and release at several versions
// with different verdicts. So each document's rows are grouped by (CVE,
// identifier without its @version — every qualifier and the subpath kept,
// status, justification), and each group is ONE row (version_kind 'exact')
// whose versions are every version Canonical listed for that verdict; a
// product listed without a version gives an empty list. A rebuild changes a
// row's list instead of adding a row. Where normalisation folds two ESM/FIPS
// tracks of one release onto one identifier with different verdicts, the
// verdicts are now two rows; before, they shared a key and the last one
// written won. The store replaces a list on upsert rather than merging it, so
// a key must be emitted once per sync with its complete list: one CVE is one
// document, so grouping per document is grouping per key. Never add an
// incremental path that emits part of a document.
//
// Change detection: the tarball has one Last-Modified for 69K documents and
// no list of what changed, and a publish typically changes about a hundred. So
// each run fingerprints every document and emits only those whose
// fingerprint differs from the last run's, each one whole, for the
// orchestrator to replace that CVE's rows (see SyncChanged). Before this,
// every publish re-upserted ~199M rows; on 2026-10-15 this emits 533K.
package ubuntuvex

import (
	"archive/tar"
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/ulikunitz/xz"

	"github.com/getreeldev/reel-vex/pkg/csaf"
	"github.com/getreeldev/reel-vex/pkg/db"
	"github.com/getreeldev/reel-vex/pkg/openvex"
	"github.com/getreeldev/reel-vex/pkg/source"
	"github.com/getreeldev/reel-vex/pkg/source/httpretry"
)

// Type is the adapter-type string used in config.yaml.
const Type = "ubuntu-vex"

// New constructs an Ubuntu OpenVEX adapter from its config entry.
func New(cfg source.AdapterConfig) (source.Adapter, error) {
	if cfg.ID == "" {
		return nil, fmt.Errorf("ubuntu-vex adapter: id required")
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("ubuntu-vex adapter %q: url required (point at vex-all.tar.xz)", cfg.ID)
	}
	name := cfg.Name
	if name == "" {
		// Distinct from "Ubuntu" used by ubuntu-oval so operators can tell
		// the two apart in stats / dashboards.
		name = "Ubuntu (OpenVEX)"
	}
	return &Adapter{
		id:   cfg.ID,
		name: name,
		url:  cfg.URL,
		http: &http.Client{Timeout: 15 * time.Minute, Transport: httpretry.New(nil)}, // tarball is ~68 MB; allow time for slow links
	}, nil
}

// Adapter streams statements from Canonical's OpenVEX tarball.
type Adapter struct {
	id   string
	name string
	url  string

	http *http.Client
}

func (a *Adapter) ID() string { return a.id }

// Vendor returns "ubuntu" — shared with the ubuntu-oval adapter. Statements
// from the two are distinguished by SourceFormat (`oval` vs `openvex`), and
// the statements PK includes source_format so they coexist without collision.
func (a *Adapter) Vendor() string       { return "ubuntu" }
func (a *Adapter) Name() string         { return a.name }
func (a *Adapter) SourceFormat() string { return "openvex" }

// Discover confirms the configured URL is reachable.
func (a *Adapter) Discover(ctx context.Context) (*source.FeedInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, a.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HEAD %s: %w", a.url, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HEAD %s: HTTP %d", a.url, resp.StatusCode)
	}
	return &source.FeedInfo{FeedURL: a.url}, nil
}

// fingerprintVersion is part of every document fingerprint. Bump it whenever
// emitDoc or Normalize changes what a document emits: the next run then finds
// every fingerprint changed and reads every document, as a cold start does.
const fingerprintVersion = "1"

// wholeReadAbove is how many changed documents a publish may replace without
// the whole-feed sweep's guard (with a fifth of the documents); a publish
// typically changes about a hundred. A var so tests can lower it.
var wholeReadAbove = 1000

// maxDocumentBytes bounds one tar entry read into memory. Canonical's largest
// is 16 MB (CVE-2023-4039, 2026-10); a larger entry is skipped as malformed.
// A var so tests can lower it.
var maxDocumentBytes int64 = 256 << 20

// fingerprint is what SyncChanged compares to tell a document unchanged.
func fingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return fingerprintVersion + ":" + hex.EncodeToString(sum[:])
}

// Sync reads every document in the tarball; see SyncChanged.
func (a *Adapter) Sync(ctx context.Context, since time.Time, emit func(source.Statement) error) (source.SyncResult, error) {
	return a.SyncChanged(ctx, since, nil, emit)
}

// SyncChanged streams VEX statements from the configured tarball. Incremental
// via Last-Modified: when the server's value is ≤ since, skip the GET
// entirely.
//
// On full fetch, the tarball is decoded streaming (xz → tar) one entry at a
// time; we never buffer the multi-GB decompressed contents. Each entry whose
// path matches `vex/cve/*/CVE-*.json` is one CVE's OpenVEX document;
// USN-keyed entries (`vex/usn/...`), directory entries, and any other paths
// are skipped silently. Malformed entries are logged and skipped — a single
// bad file should not abort the whole sync.
//
// A document whose fingerprint equals its entry in last emits nothing: one
// file is one CVE, so leaving the file out leaves out exactly that CVE's rows,
// which are still what it states. Every other document is emitted whole and
// listed in RefreshedCVEs, so the orchestrator replaces that CVE's rows. A
// run that left anything out is not Complete and lists every CVE in the
// tarball in LiveCVEs. That holds only while each file is one CVE's own —
// Canonical's are (69,923 checked, 2026-10-15) — so a tarball with two files
// of one name, or a document naming another CVE, is read whole instead, and
// keeps no fingerprints. The watermark is the tarball's Last-Modified.
func (a *Adapter) SyncChanged(ctx context.Context, since time.Time, last map[string]string, emit func(source.Statement) error) (source.SyncResult, error) {
	headReq, err := http.NewRequestWithContext(ctx, http.MethodHead, a.url, nil)
	if err != nil {
		return source.SyncResult{}, err
	}
	headResp, err := a.http.Do(headReq)
	if err != nil {
		return source.SyncResult{}, fmt.Errorf("HEAD %s: %w", a.url, err)
	}
	headResp.Body.Close()
	if headResp.StatusCode != http.StatusOK {
		return source.SyncResult{}, fmt.Errorf("HEAD %s: HTTP %d", a.url, headResp.StatusCode)
	}

	lastModified, _ := http.ParseTime(headResp.Header.Get("Last-Modified"))
	if lastModified.IsZero() {
		slog.Warn("no Last-Modified header on Canonical OpenVEX feed", "adapter", a.id)
	} else if !since.IsZero() && !lastModified.After(since) {
		slog.Info("ubuntu-vex up to date, skipping GET", "adapter", a.id, "last_modified", lastModified, "since", since)
		return source.SyncResult{}, nil
	}

	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, a.url, nil)
	if err != nil {
		return source.SyncResult{}, err
	}
	getResp, err := a.http.Do(getReq)
	if err != nil {
		return source.SyncResult{}, fmt.Errorf("GET %s: %w", a.url, err)
	}
	if getResp.StatusCode != http.StatusOK {
		getResp.Body.Close()
		return source.SyncResult{}, fmt.Errorf("GET %s: HTTP %d", a.url, getResp.StatusCode)
	}

	// Buffer the tarball fully into memory before walking. The xz+tar walk
	// can take 30-60+ minutes on a real Canonical feed (~69K JSON entries
	// to decode + insert), but the body read needs to complete inside the
	// HTTP client's Timeout — streaming the body through xz/tar/JSON keeps
	// the connection open for the full walk and trips the deadline. The
	// tarball is small enough (~68 MB compressed) to buffer; processing
	// then happens entirely on local memory with no HTTP coupling.
	body, err := io.ReadAll(getResp.Body)
	getResp.Body.Close()
	if err != nil {
		return source.SyncResult{}, fmt.Errorf("read body: %w", err)
	}
	// The body's own date is the publish this run read, should a cache have
	// answered the HEAD with a newer one.
	if lm, _ := http.ParseTime(getResp.Header.Get("Last-Modified")); !lm.IsZero() {
		lastModified = lm
	}

	fallbackTime := lastModified
	if fallbackTime.IsZero() {
		fallbackTime = time.Now().UTC()
	}
	res, odd, err := a.walk(ctx, body, last, fallbackTime, emit)
	if err != nil {
		return source.SyncResult{}, err
	}
	// A run that found every document changed (fingerprints of another
	// fingerprintVersion, say) has read the whole feed already.
	whole := len(last) == 0 || res.Complete
	if !whole {
		// Replacing a document's rows has no fraction guard; the whole-feed
		// sweep does. A publish that changed more than a fifth of the
		// documents and more than wholeReadAbove of them (a new format the
		// parser reads as empty, say) is read whole, from the buffered
		// tarball, so that guard judges it. So is one
		// holding a document that is not one CVE's own, since leaving a
		// document out is only leaving that CVE's rows when every document is.
		var why string
		switch {
		case odd:
			why = "a document is not one CVE's own"
		case len(res.RefreshedCVEs) > wholeReadAbove && len(res.RefreshedCVEs)*5 > len(res.LiveCVEs):
			why = "more than a fifth of the documents changed"
		}
		if why != "" {
			slog.Warn("ubuntu-vex reading every document", "adapter", a.id, "reason", why,
				"refreshed", len(res.RefreshedCVEs), "entries", len(res.LiveCVEs))
			if res, odd, err = a.walk(ctx, body, nil, fallbackTime, emit); err != nil {
				return source.SyncResult{}, err
			}
			whole = true
		}
	}
	if whole && !res.Complete {
		// A whole read that skipped a document removes nothing, as before
		// documents were left out, and stores no fingerprints: the next run
		// reads whole again.
		res = source.SyncResult{Fingerprints: map[string]string{}}
	}
	if odd {
		res.Fingerprints = map[string]string{}
	}
	res.Watermark = lastModified
	return res, nil
}

// walk reads the tarball, leaving out each document whose fingerprint equals
// its entry in last. odd reports a document that is not one CVE's own — two
// files with one name, or a document naming another CVE — which makes
// leaving documents out unsafe.
func (a *Adapter) walk(ctx context.Context, body []byte, last map[string]string, fallbackTime time.Time, emit func(source.Statement) error) (source.SyncResult, bool, error) {
	xzReader, err := xz.NewReader(bytes.NewReader(body))
	if err != nil {
		return source.SyncResult{}, false, fmt.Errorf("xz reader: %w", err)
	}
	tarReader := tar.NewReader(xzReader)

	var (
		entries   int
		emitted   int
		skipped   int
		unchanged int
		odd       bool
		live      []string
		refreshed []string
		fps       = map[string]string{}
		seen      = map[string]bool{}
	)
	for {
		if err := ctx.Err(); err != nil {
			return source.SyncResult{}, false, err
		}
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return source.SyncResult{}, false, fmt.Errorf("tar next: %w", err)
		}
		if !isCVEEntry(hdr.Name, hdr.Typeflag) {
			continue
		}
		entries++
		cve := strings.TrimSuffix(path.Base(hdr.Name), ".json")
		if seen[cve] {
			odd = true
		}
		seen[cve] = true
		live = append(live, cve)

		if hdr.Size > maxDocumentBytes {
			slog.Warn("ubuntu-vex skip oversized entry", "adapter", a.id, "name", hdr.Name, "bytes", hdr.Size)
			skipped++
			continue
		}
		raw, err := io.ReadAll(tarReader)
		if err != nil {
			return source.SyncResult{}, false, fmt.Errorf("read %s: %w", hdr.Name, err)
		}
		fp := fingerprint(raw)
		if prev, ok := last[cve]; ok && prev == fp {
			fps[cve] = fp
			unchanged++
			continue
		}

		var doc openvex.Document
		if err := json.Unmarshal(raw, &doc); err != nil {
			slog.Warn("ubuntu-vex skip malformed entry", "adapter", a.id, "name", hdr.Name, "error", err)
			skipped++
			continue
		}
		for _, st := range doc.Statements {
			if n := st.Vulnerability.Name; n != "" && n != cve {
				odd = true
			}
		}
		n, err := emitDoc(doc, fallbackTime, emit)
		if err != nil {
			return source.SyncResult{}, false, err
		}
		emitted += n
		fps[cve] = fp
		refreshed = append(refreshed, cve)
	}
	slog.Info("ubuntu-vex sync complete", "adapter", a.id, "entries", entries, "unchanged", unchanged,
		"refreshed", entries-unchanged-skipped, "statements", emitted, "skipped", skipped)
	if skipped == 0 && unchanged == 0 {
		return source.SyncResult{Complete: true, Fingerprints: fps}, odd, nil
	}
	return source.SyncResult{RefreshedCVEs: refreshed, LiveCVEs: live, Fingerprints: fps}, odd, nil
}

// isCVEEntry returns true for tar headers that point at one of Canonical's
// per-CVE OpenVEX files. Path shape: vex/cve/<year>/CVE-<rest>.json.
// Filters out: vex/usn/*, directory entries, anything else.
func isCVEEntry(name string, typeflag byte) bool {
	if typeflag != tar.TypeReg { // tar.Reader already maps legacy TypeRegA to TypeReg
		return false
	}
	// Strip a leading "./" if present.
	name = strings.TrimPrefix(name, "./")
	if !strings.HasPrefix(name, "vex/cve/") {
		return false
	}
	if !strings.HasSuffix(name, ".json") {
		return false
	}
	return strings.HasPrefix(path.Base(name), "CVE-")
}

// emitDoc walks one OpenVEX document and emits one source.Statement per
// verdict: the document's (statement × normalized identifier) pairs are
// grouped by (CVE, identifier without its @version, status, justification),
// and each group is one exact-list row carrying every version Canonical
// listed for that verdict, dated by the latest timestamp in the group (see
// the package doc). The output does not depend on the order of the
// document's statements or products. Returns the number of rows emitted.
// fallback is used when the document carries no per-statement and no
// doc-level timestamp.
func emitDoc(doc openvex.Document, fallback time.Time, emit func(source.Statement) error) (int, error) {
	type key struct{ cve, product, status, justification string }
	type group struct {
		versions []string
		updated  time.Time
	}
	groups := make(map[key]*group)
	docTime := parseRFC3339(doc.Timestamp, fallback)
	for _, stmt := range doc.Statements {
		if stmt.Vulnerability.Name == "" {
			continue
		}
		ts := parseRFC3339(stmt.Timestamp, docTime)
		// Normalize ESM/distro qualifiers before grouping: Canonical often
		// lists one product under three ESM tracks of one release, and
		// normalisation folds them onto one identifier.
		for _, id := range openvex.CollectIdentifiers(stmt.Products) {
			product, version := csaf.StripPURLVersion(Normalize(id))
			k := key{stmt.Vulnerability.Name, product, stmt.Status, stmt.Justification}
			g := groups[k]
			if g == nil {
				g = &group{}
				groups[k] = g
			}
			if version != "" {
				// Stored percent-decoded, as a caller's version is compared.
				g.versions = append(g.versions, csaf.UnescapeVersion(version))
			}
			if ts.After(g.updated) {
				g.updated = ts
			}
		}
	}

	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b key) int {
		return cmp.Or(cmp.Compare(a.cve, b.cve), cmp.Compare(a.product, b.product),
			cmp.Compare(a.status, b.status), cmp.Compare(a.justification, b.justification))
	})
	count := 0
	for _, k := range keys {
		g := groups[k]
		slices.Sort(g.versions)
		base, _ := csaf.SplitPURL(k.product)
		idType := "purl"
		if !strings.HasPrefix(k.product, "pkg:") {
			idType = "cpe"
		}
		out := source.Statement{
			CVE:           k.cve,
			ProductID:     k.product,
			BaseID:        base,
			Versions:      slices.Compact(g.versions),
			VersionKind:   db.VersionKindExact,
			IDType:        idType,
			Status:        k.status,
			Justification: k.justification,
			Updated:       g.updated,
		}
		if err := emit(out); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

// parseRFC3339 returns the RFC3339-parsed override, or the fallback when the
// override is empty or unparseable. Mirrors the helper in pkg/uservex/parse.go
// — we don't share it across packages because that one returns time.Time and
// is a few lines. Duplication is cheaper than a tiny shared helper.
func parseRFC3339(override string, fallback time.Time) time.Time {
	if override != "" {
		if t, err := time.Parse(time.RFC3339, override); err == nil {
			return t
		}
		if t, err := time.Parse(time.RFC3339Nano, override); err == nil {
			return t
		}
	}
	return fallback
}
