// Package ranchervex implements source.Adapter for SUSE's Rancher VEX Hub
// (https://github.com/rancher/vexhub), contributed via reel-vex issue #1.
//
// The hub is a VEX Repository (per the VEX Repository Specification): its
// vex-repository.json names one snapshot of the whole repository, the GitHub
// archive tarball of the main branch (~8 MB gzipped, one commit). The adapter
// downloads that tarball on every sync, reads the repository's index.json
// manifest from it, and parses each per-package OpenVEX 0.2.0 document the
// manifest lists (~1,250 today, ~320K statements) covering SUSE cloud-native
// product *images* (Rancher, RKE2, K3s, Harvester, Longhorn). Every statement
// is `not_affected`: the hub is a pure suppression feed.
//
// Statements are subcomponent-scoped, which is new to reel-vex. Each statement
// looks like:
//
//	{ "vulnerability": { "name": "CVE-2024-1234" },
//	  "products": [ { "@id": "pkg:oci/longhorn-engine?repository_url=...",
//	                  "subcomponents": [ { "@id": "pkg:golang/golang.org/x/net@v0.17.0" } ] } ],
//	  "status": "not_affected", "justification": "vulnerable_code_not_present" }
//
// The product @id is the image/module the verdict is *about* — stored as the
// statement's scope. The subcomponent is the package a scanner matches against
// an SBOM component — stored as product_id/base_id. The query layer only
// surfaces a scoped row when the caller names a matching scope, so a verdict
// scoped to one image never suppresses the same package in an unrelated image
// (see pkg/csaf.NormalizeScope and pkg/db.QueryFilters.Scopes).
//
// Three classes of statement are skipped, by design:
//   - Non-CVE-named (~3%: mostly SUSE-SU advisories, a few GHSA). They carry no
//     CVE alias, and reel-vex keys and serves by CVE, so they would be dead
//     rows. Deferred to a future advisory→CVE resolution pass.
//   - No subcomponent. We refuse to emit a product-level (unscoped) row from
//     this feed: it would assert a global not_affected and risk over-suppression.
//     Empirically every statement carries exactly one subcomponent, so this is
//     a defensive guard, not a live path.
//   - A subcomponent that is neither a PURL nor a CPE. Rancher's generator
//     writes its own error text as the @id when it fails to map a package
//     (observed live: "[ERROR] CVE type  not mapped"); storing that as a
//     product identifier makes a row nothing can ever match.
package ranchervex

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/getreeldev/reel-vex/pkg/csaf"
	"github.com/getreeldev/reel-vex/pkg/openvex"
	"github.com/getreeldev/reel-vex/pkg/source"
	"github.com/getreeldev/reel-vex/pkg/source/httpretry"
)

// Type is the adapter-type string used in config.yaml.
const Type = "rancher-vex"

// New constructs a Rancher VEX adapter from its config entry.
func New(cfg source.AdapterConfig) (source.Adapter, error) {
	if cfg.ID == "" {
		return nil, fmt.Errorf("rancher-vex adapter: id required")
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("rancher-vex adapter %q: url required (point at the repository snapshot .tar.gz)", cfg.ID)
	}
	name := cfg.Name
	if name == "" {
		name = "SUSE Rancher (OpenVEX)"
	}
	return &Adapter{
		id:   cfg.ID,
		name: name,
		url:  cfg.URL,
		http: &http.Client{Timeout: 15 * time.Minute, Transport: httpretry.New(nil)}, // one ~8 MB download; allow slow links
	}, nil
}

// Adapter streams statements from a Rancher VEX Hub repository snapshot.
type Adapter struct {
	id   string
	name string
	url  string

	http *http.Client
}

func (a *Adapter) ID() string { return a.id }

// Vendor returns "rancher" — a distinct vendor from SUSE's CSAF feed ("suse").
// These are product-level suppressions for the Rancher/SUSE cloud-native image
// line, semantically separate from SUSE Linux OS-package CSAF, and a separate
// /v1/stats line keeps that visible.
func (a *Adapter) Vendor() string       { return "rancher" }
func (a *Adapter) Name() string         { return a.name }
func (a *Adapter) SourceFormat() string { return "openvex" }

// Discover confirms the configured URL is reachable. GitHub answers the
// archive URL with a redirect to codeload.github.com, which the client follows.
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

// Sync downloads the repository snapshot and emits every statement in every
// per-package document its index.json lists, in tar order. `since` is
// ignored: the snapshot is one request and one consistent commit, so every
// sync reads the whole current set and the conditional upsert makes the
// unchanged rows cheap.
//
// The result is Complete when index.json was found and every file it lists
// was present in the snapshot and parsed. An index.json that is missing, a
// Git LFS pointer, or lists no packages is an error, and so is a snapshot in
// which no listed file parses: an empty Complete run would claim the vendor
// withdrew every Rancher statement.
func (a *Adapter) Sync(ctx context.Context, _ time.Time, emit func(source.Statement) error) (source.SyncResult, error) {
	body, err := a.download(ctx)
	if err != nil {
		return source.SyncResult{}, err
	}

	idx, commit, err := readIndex(body)
	if err != nil {
		return source.SyncResult{}, err
	}
	listed := idx.locations()
	if len(listed) == 0 {
		return source.SyncResult{}, errors.New("index.json lists no packages")
	}
	slog.Info("rancher-vex snapshot", "adapter", a.id, "commit", commit,
		"compressed_bytes", len(body), "packages", len(listed))

	pending := make(map[string]bool, len(listed))
	for _, loc := range listed {
		pending[loc] = true
	}
	var (
		counts      syncCounts
		parsed      int
		filesFailed int
		emitErr     error
	)
	// emit's own error is recorded so a failure from the orchestrator stops
	// the sync instead of reading as one unparseable file.
	emitRecorded := func(s source.Statement) error {
		if err := emit(s); err != nil {
			emitErr = err
			return err
		}
		return nil
	}
	err = walkSnapshot(body, func(name string, r io.Reader) (bool, error) {
		if !pending[name] {
			return true, nil
		}
		delete(pending, name)
		if err := ctx.Err(); err != nil {
			return false, err
		}
		b, err := io.ReadAll(r)
		if err != nil {
			return false, fmt.Errorf("read %s: %w", name, err)
		}
		c, err := a.parseFile(ctx, b, emitRecorded)
		counts.emitted += c.emitted
		counts.skippedNonCVE += c.skippedNonCVE
		counts.skippedNoSub += c.skippedNoSub
		counts.skippedBadSub += c.skippedBadSub
		if err != nil {
			if emitErr != nil {
				return false, emitErr
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				return false, ctxErr
			}
			filesFailed++
			slog.Warn("rancher-vex: per-package file failed; skipping", "adapter", a.id, "file", name, "error", err)
			return true, nil
		}
		parsed++
		return true, nil
	})
	if err != nil {
		return source.SyncResult{}, err
	}
	for loc := range pending {
		slog.Warn("rancher-vex: index.json lists a file the snapshot lacks", "adapter", a.id, "file", loc)
	}
	if parsed == 0 {
		return source.SyncResult{}, fmt.Errorf("none of the %d files index.json lists parsed (%d failed, %d missing)",
			len(listed), filesFailed, len(pending))
	}

	slog.Info("rancher-vex sync complete", "adapter", a.id,
		"statements", counts.emitted, "skipped_non_cve", counts.skippedNonCVE,
		"skipped_no_subcomponent", counts.skippedNoSub, "skipped_bad_subcomponent", counts.skippedBadSub,
		"files_failed", filesFailed, "files_missing", len(pending))
	return source.SyncResult{Complete: filesFailed == 0 && len(pending) == 0}, nil
}

// download GETs the snapshot tarball whole. Buffering keeps the two local
// walks below off the HTTP connection.
func (a *Adapter) download(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", a.url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", a.url, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", a.url, err)
	}
	return b, nil
}

// walkSnapshot calls fn for each regular file in the gzipped tarball, in tar
// order, with its path relative to the archive's single top-level directory
// (GitHub names it <repo>-<ref>/). fn returns false to stop the walk early.
func walkSnapshot(body []byte, fn func(name string, r io.Reader) (bool, error)) error {
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("tar walk: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		_, rel, ok := strings.Cut(hdr.Name, "/")
		if !ok || rel == "" {
			continue
		}
		more, err := fn(rel, tr)
		if err != nil {
			return err
		}
		if !more {
			return nil
		}
	}
}

// readIndex finds index.json in the snapshot and decodes it. It also returns
// the commit GitHub records in the archive's global header, for the log.
func readIndex(body []byte) (indexManifest, string, error) {
	var (
		idx    indexManifest
		raw    []byte
		found  bool
		commit string
	)
	// GitHub writes the commit as the "comment" record of a leading pax
	// global header, which tar.Reader returns as the first entry.
	if zr, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
		if hdr, err := tar.NewReader(zr).Next(); err == nil {
			commit = hdr.PAXRecords["comment"]
		}
		zr.Close()
	}
	err := walkSnapshot(body, func(name string, r io.Reader) (bool, error) {
		if name != "index.json" {
			return true, nil
		}
		b, err := io.ReadAll(r)
		if err != nil {
			return false, fmt.Errorf("read index.json: %w", err)
		}
		raw, found = b, true
		return false, nil
	})
	if err != nil {
		return idx, "", err
	}
	if !found {
		return idx, "", errors.New("snapshot has no index.json")
	}
	if bytes.HasPrefix(raw, lfsPointerPrefix) {
		return idx, "", errors.New("index.json in the snapshot is a Git LFS pointer, not the manifest")
	}
	if err := json.Unmarshal(raw, &idx); err != nil {
		return idx, "", fmt.Errorf("decode index.json: %w", err)
	}
	return idx, commit, nil
}

// lfsPointerPrefix opens a Git LFS pointer file, which an archive carries in
// place of an LFS-tracked file's content.
var lfsPointerPrefix = []byte("version https://git-lfs.github.com/spec")

// indexManifest is the top-level index.json: each package points at its
// per-package OpenVEX document (a repo-relative path).
type indexManifest struct {
	Packages []struct {
		ID       string `json:"id"`
		Location string `json:"location"`
	} `json:"packages"`
}

func (m indexManifest) locations() []string {
	locs := make([]string, 0, len(m.Packages))
	for _, p := range m.Packages {
		if p.Location != "" {
			locs = append(locs, p.Location)
		}
	}
	return locs
}

// parseFile parses one per-package document and emits its statements.
func (a *Adapter) parseFile(ctx context.Context, b []byte, emit func(source.Statement) error) (syncCounts, error) {
	if bytes.HasPrefix(b, lfsPointerPrefix) {
		return syncCounts{}, errors.New("file is a Git LFS pointer, not the document")
	}
	// OpenVEX statements inherit the document-level timestamp when they carry
	// none — and Rancher's per-package docs only set it at the document level.
	// Use it as the per-statement fallback so rows keep the vendor's assertion
	// time (provenance + ?since= filtering), not ingest time.
	fallback := time.Now().UTC()
	var meta struct {
		Timestamp string `json:"timestamp"`
	}
	if json.Unmarshal(b, &meta) == nil {
		fallback = parseRFC3339(meta.Timestamp, fallback)
	}
	return a.streamStatements(ctx, bytes.NewReader(b), fallback, emit)
}

type syncCounts struct {
	emitted       int
	skippedNonCVE int
	skippedNoSub  int
	skippedBadSub int
}

// streamStatements walks the top-level JSON object, decodes the `statements`
// array element-by-element, and emits a row per (product-scope × subcomponent).
// Other top-level fields (@context, author, timestamp, …) are skipped.
func (a *Adapter) streamStatements(ctx context.Context, r io.Reader, fallback time.Time, emit func(source.Statement) error) (syncCounts, error) {
	var counts syncCounts
	dec := json.NewDecoder(r)

	tok, err := dec.Token()
	if err != nil {
		return counts, fmt.Errorf("read opening token: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return counts, fmt.Errorf("expected JSON object, got %v", tok)
	}

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return counts, fmt.Errorf("read key: %w", err)
		}
		key, _ := keyTok.(string)
		if key != "statements" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return counts, fmt.Errorf("skip field %q: %w", key, err)
			}
			continue
		}

		// statements: [ ... ]
		arrTok, err := dec.Token()
		if err != nil {
			return counts, fmt.Errorf("read statements array start: %w", err)
		}
		if d, ok := arrTok.(json.Delim); !ok || d != '[' {
			return counts, fmt.Errorf("statements is not an array")
		}
		for dec.More() {
			if err := ctx.Err(); err != nil {
				return counts, err
			}
			var st openvex.Statement
			if err := dec.Decode(&st); err != nil {
				return counts, fmt.Errorf("decode statement: %w", err)
			}
			if err := a.emitStatement(st, fallback, emit, &counts); err != nil {
				return counts, err
			}
		}
		if _, err := dec.Token(); err != nil { // closing ']'
			return counts, fmt.Errorf("read statements array end: %w", err)
		}
	}
	return counts, nil
}

// emitStatement turns one OpenVEX statement into zero or more source.Statements
// — one per (product, subcomponent) pair — and updates counters. CVE-only and
// subcomponent-bearing statements are emitted; everything else is skipped.
func (a *Adapter) emitStatement(st openvex.Statement, fallback time.Time, emit func(source.Statement) error, counts *syncCounts) error {
	cve := st.Vulnerability.Name
	if !strings.HasPrefix(cve, "CVE-") {
		counts.skippedNonCVE++
		return nil
	}
	ts := parseRFC3339(st.Timestamp, fallback)

	rows, bad := 0, 0
	for _, product := range st.Products {
		scopeIDs := openvex.CollectIdentifiers([]openvex.Component{product})
		if len(scopeIDs) == 0 {
			continue
		}
		scope := csaf.NormalizeScope(scopeIDs[0])
		if scope == "" {
			continue
		}
		for _, sub := range openvex.CollectIdentifiers(product.Subcomponents) {
			idType := "purl"
			switch {
			case strings.HasPrefix(sub, "pkg:"):
			case strings.HasPrefix(sub, "cpe:"):
				idType = "cpe"
			default:
				bad++
				continue
			}
			base, version := csaf.SplitPURL(sub)
			if err := emit(source.Statement{
				CVE:           cve,
				ProductID:     sub,
				BaseID:        base,
				Version:       version,
				IDType:        idType,
				Status:        st.Status,
				Justification: st.Justification,
				Scope:         scope,
				Updated:       ts,
			}); err != nil {
				return err
			}
			counts.emitted++
			rows++
		}
	}
	counts.skippedBadSub += bad
	if rows == 0 && bad == 0 {
		counts.skippedNoSub++
	}
	return nil
}

// parseRFC3339 returns the RFC3339-parsed override, or the fallback when the
// override is empty or unparseable. (Mirrors the helper in pkg/source/ubuntuvex
// — too small to share across packages.)
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
