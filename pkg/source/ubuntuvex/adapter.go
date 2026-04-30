// Package ubuntuvex implements source.Adapter for Canonical's OpenVEX 0.2.0
// feed at https://security-metadata.canonical.com/vex/vex-all.tar.xz.
//
// Coverage is a strict superset of the existing Ubuntu OVAL adapter: where
// the OVAL feed only ships rows for CVEs that have a USN, the OpenVEX feed
// includes pre-USN triage state (`not_affected`, `under_investigation`,
// `affected`) for every CVE Canonical has assessed.
//
// The feed is one ~59MB tar.xz containing ~54K per-CVE OpenVEX 0.2.0 JSON
// files at vex/cve/<year>/CVE-<id>.json (plus USN-keyed files at vex/usn/
// which this adapter ignores). Each per-CVE document carries one or more
// statements; each statement carries one or more product identifiers in
// PURL form.
//
// Identifier translation: Canonical emits the `?distro=` qualifier in four
// shapes (`ubuntu/<codename>`, `esm-apps/<codename>`, `esm-infra/<codename>`,
// `esm-infra-legacy/<codename>`); scanners speak `ubuntu-<version>`.
// Normalize() in distro.go rewrites the qualifier; the loop below dedupes
// the resulting many-to-one collisions before emit.
package ubuntuvex

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/ulikunitz/xz"

	"github.com/getreeldev/reel-vex/pkg/csaf"
	"github.com/getreeldev/reel-vex/pkg/openvex"
	"github.com/getreeldev/reel-vex/pkg/source"
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
		// the two apart in stats / dashboards during the soak window.
		name = "Ubuntu (OpenVEX)"
	}
	return &Adapter{
		id:   cfg.ID,
		name: name,
		url:  cfg.URL,
		http: &http.Client{Timeout: 15 * time.Minute}, // tarball is ~59MB; allow time for slow links
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

// Sync streams VEX statements from the configured tarball. Incremental via
// Last-Modified: when the server's value is ≤ since, skip the GET entirely.
//
// On full fetch, the tarball is decoded streaming (xz → tar) one entry at a
// time; we never buffer the multi-GB decompressed contents. Each entry whose
// path matches `vex/cve/*/CVE-*.json` is parsed as one OpenVEX document;
// USN-keyed entries (`vex/usn/...`), directory entries, and any other paths
// are skipped silently. Malformed entries are logged and skipped — a single
// bad file should not abort the whole sync.
func (a *Adapter) Sync(ctx context.Context, since time.Time, emit func(source.Statement) error) error {
	headReq, err := http.NewRequestWithContext(ctx, http.MethodHead, a.url, nil)
	if err != nil {
		return err
	}
	headResp, err := a.http.Do(headReq)
	if err != nil {
		return fmt.Errorf("HEAD %s: %w", a.url, err)
	}
	headResp.Body.Close()
	if headResp.StatusCode != http.StatusOK {
		return fmt.Errorf("HEAD %s: HTTP %d", a.url, headResp.StatusCode)
	}

	lastModified, _ := http.ParseTime(headResp.Header.Get("Last-Modified"))
	if lastModified.IsZero() {
		slog.Warn("no Last-Modified header on Canonical OpenVEX feed", "adapter", a.id)
	} else if !since.IsZero() && !lastModified.After(since) {
		slog.Info("ubuntu-vex up to date, skipping GET", "adapter", a.id, "last_modified", lastModified, "since", since)
		return nil
	}

	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, a.url, nil)
	if err != nil {
		return err
	}
	getResp, err := a.http.Do(getReq)
	if err != nil {
		return fmt.Errorf("GET %s: %w", a.url, err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", a.url, getResp.StatusCode)
	}

	xzReader, err := xz.NewReader(getResp.Body)
	if err != nil {
		return fmt.Errorf("xz reader: %w", err)
	}
	tarReader := tar.NewReader(xzReader)

	fallbackTime := lastModified
	if fallbackTime.IsZero() {
		fallbackTime = time.Now().UTC()
	}

	var (
		entries int
		emitted int
		skipped int
	)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar next: %w", err)
		}
		if !isCVEEntry(hdr.Name, hdr.Typeflag) {
			continue
		}
		entries++

		var doc openvex.Document
		if err := json.NewDecoder(tarReader).Decode(&doc); err != nil {
			slog.Warn("ubuntu-vex skip malformed entry", "adapter", a.id, "name", hdr.Name, "error", err)
			skipped++
			continue
		}
		n, err := emitDoc(doc, fallbackTime, emit)
		if err != nil {
			return err
		}
		emitted += n
	}
	slog.Info("ubuntu-vex sync complete", "adapter", a.id, "entries", entries, "statements", emitted, "skipped", skipped)
	return nil
}

// isCVEEntry returns true for tar headers that point at one of Canonical's
// per-CVE OpenVEX files. Path shape: vex/cve/<year>/CVE-<rest>.json.
// Filters out: vex/usn/*, directory entries, anything else.
func isCVEEntry(name string, typeflag byte) bool {
	if typeflag != tar.TypeReg && typeflag != tar.TypeRegA {
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
// (statement × unique normalized identifier). Returns the number of rows
// emitted. fallback is used when the document carries no per-statement and
// no doc-level timestamp.
func emitDoc(doc openvex.Document, fallback time.Time, emit func(source.Statement) error) (int, error) {
	docTime := parseRFC3339(doc.Timestamp, fallback)
	count := 0
	for _, stmt := range doc.Statements {
		if stmt.Vulnerability.Name == "" {
			continue
		}
		ts := parseRFC3339(stmt.Timestamp, docTime)

		ids := openvex.CollectIdentifiers(stmt.Products)
		if len(ids) == 0 {
			continue
		}
		// Normalize ESM/distro qualifiers, then re-dedup. Canonical
		// often emits the same product under three ESM tracks for one
		// release; normalisation collapses them to one entry.
		seen := make(map[string]bool, len(ids))
		normalized := make([]string, 0, len(ids))
		for _, id := range ids {
			n := Normalize(id)
			if seen[n] {
				continue
			}
			seen[n] = true
			normalized = append(normalized, n)
		}

		for _, id := range normalized {
			base, version := csaf.SplitPURL(id)
			idType := "purl"
			if !strings.HasPrefix(id, "pkg:") {
				idType = "cpe"
			}
			out := source.Statement{
				CVE:           stmt.Vulnerability.Name,
				ProductID:     id,
				BaseID:        base,
				Version:       version,
				IDType:        idType,
				Status:        stmt.Status,
				Justification: stmt.Justification,
				Updated:       ts,
			}
			if err := emit(out); err != nil {
				return count, err
			}
			count++
		}
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
