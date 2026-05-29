// Package ranchervex implements source.Adapter for SUSE's Rancher VEX Hub
// (https://github.com/rancher/vexhub), contributed via reel-vex issue #1.
//
// The feed is one consolidated OpenVEX 0.2.0 document — `rancher.openvex.json`
// (~80 MB, ~140K statements) — covering SUSE cloud-native product *images*
// (Rancher, RKE2, K3s, Harvester, Longhorn). Every statement is `not_affected`:
// the hub is a pure suppression feed.
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
// Two classes of statement are skipped, by design:
//   - Non-CVE-named (~3%: mostly SUSE-SU advisories, a few GHSA). They carry no
//     CVE alias, and reel-vex keys and serves by CVE, so they would be dead
//     rows. Deferred to a future advisory→CVE resolution pass.
//   - No subcomponent. We refuse to emit a product-level (unscoped) row from
//     this feed: it would assert a global not_affected and risk over-suppression.
//     Empirically every statement carries exactly one subcomponent, so this is
//     a defensive guard, not a live path.
package ranchervex

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
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
		return nil, fmt.Errorf("rancher-vex adapter %q: url required (point at index.json)", cfg.ID)
	}
	name := cfg.Name
	if name == "" {
		name = "SUSE Rancher (OpenVEX)"
	}
	return &Adapter{
		id:      cfg.ID,
		name:    name,
		url:     cfg.URL,
		apiBase: "https://api.github.com",
		http:    &http.Client{Timeout: 15 * time.Minute, Transport: httpretry.New(nil)}, // many small non-LFS files; allow slow links
	}, nil
}

// Adapter streams statements from the Rancher VEX Hub consolidated document.
type Adapter struct {
	id      string
	name    string
	url     string
	apiBase string // GitHub API base; overridable in tests

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

// Sync ingests the Rancher VEX hub via its repo index (index.json) — a small,
// non-LFS manifest mapping each package to a per-package scan.openvex.json. The
// consolidated reports/rancher.openvex.json is deliberately NOT used: it is
// Git-LFS-backed, so fetching it draws down the upstream repo's LFS bandwidth
// quota and breaks (serves the LFS pointer) once that's exhausted. The
// per-package files are non-LFS and tiny.
//
// First sync (zero watermark): walk the whole index. Incremental: ask the
// GitHub commits API what changed since the watermark and fetch only those
// files — most cycles touch nothing. Both paths emit identical rows (the
// monolith was just the aggregation of these files), so the DB is self-
// consistent regardless of which path produced a given statement.
func (a *Adapter) Sync(ctx context.Context, since time.Time, emit func(source.Statement) error) error {
	coords, err := repoCoords(a.url)
	if err != nil {
		return err
	}

	var locations []string
	switch {
	case since.IsZero():
		idx, err := a.fetchIndex(ctx)
		if err != nil {
			return err
		}
		locations = idx.locations()
		slog.Info("rancher-vex full index seed", "adapter", a.id, "packages", len(locations))
	default:
		changed, err := a.changedSince(ctx, coords, since)
		if err != nil {
			// A commits-API hiccup shouldn't stall the feed; fall back to a full
			// index walk (conditional upsert makes the redundant pass cheap).
			slog.Warn("rancher-vex incremental check failed; falling back to full index",
				"adapter", a.id, "error", err)
			idx, ferr := a.fetchIndex(ctx)
			if ferr != nil {
				return ferr
			}
			locations = idx.locations()
		} else if len(changed) == 0 {
			slog.Info("rancher-vex up to date, no changes since watermark", "adapter", a.id, "since", since)
			return nil
		} else {
			locations = changed
			slog.Info("rancher-vex incremental sync", "adapter", a.id,
				"changed_files", len(locations), "since", since)
		}
	}

	counts, err := a.fetchAndEmit(ctx, coords.rawBase, locations, emit)
	if err != nil {
		return err
	}
	slog.Info("rancher-vex sync complete", "adapter", a.id,
		"statements", counts.emitted, "skipped_non_cve", counts.skippedNonCVE,
		"skipped_no_subcomponent", counts.skippedNoSub, "files_failed", counts.filesFailed)
	return nil
}

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

// repoSpec holds the GitHub coordinates derived from the configured index URL.
type repoSpec struct {
	owner, repo, ref, rawBase string
}

// repoCoords parses a raw.githubusercontent.com index URL into the pieces we
// need for raw per-file fetches and GitHub API calls, e.g.
//
//	https://raw.githubusercontent.com/rancher/vexhub/refs/heads/main/index.json
//	  -> owner=rancher repo=vexhub ref=main
//	     rawBase=https://raw.githubusercontent.com/rancher/vexhub/refs/heads/main/
func repoCoords(indexURL string) (repoSpec, error) {
	u, err := url.Parse(indexURL)
	if err != nil {
		return repoSpec{}, fmt.Errorf("parse index url: %w", err)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 4 {
		return repoSpec{}, fmt.Errorf("index url %q: want /owner/repo/.../index.json", indexURL)
	}
	slash := strings.LastIndex(indexURL, "/")
	return repoSpec{
		owner:   parts[0],
		repo:    parts[1],
		ref:     parts[len(parts)-2], // the directory that holds index.json
		rawBase: indexURL[:slash+1],
	}, nil
}

// fetchIndex downloads and decodes index.json.
func (a *Adapter) fetchIndex(ctx context.Context) (indexManifest, error) {
	var idx indexManifest
	b, err := a.getBytes(ctx, a.url)
	if err != nil {
		return idx, fmt.Errorf("index.json: %w", err)
	}
	if err := json.Unmarshal(b, &idx); err != nil {
		return idx, fmt.Errorf("decode index.json: %w", err)
	}
	return idx, nil
}

// changedSince asks the GitHub commits API which per-package files changed since
// the watermark, via a single commits listing plus one compare call. Returns
// nil,nil when nothing changed. Removed files are ignored — the ingest never
// deletes (a withdrawn suppression lingering is a separate, known follow-up).
func (a *Adapter) changedSince(ctx context.Context, coords repoSpec, since time.Time) ([]string, error) {
	api := a.apiBase + "/repos/" + coords.owner + "/" + coords.repo
	commitsURL := fmt.Sprintf("%s/commits?sha=%s&since=%s&per_page=100",
		api, url.QueryEscape(coords.ref), url.QueryEscape(since.UTC().Format(time.RFC3339)))

	var commits []struct {
		SHA     string `json:"sha"`
		Parents []struct {
			SHA string `json:"sha"`
		} `json:"parents"`
	}
	if err := a.getAPIJSON(ctx, commitsURL, &commits); err != nil {
		return nil, err
	}
	if len(commits) == 0 {
		return nil, nil
	}
	if len(commits) >= 100 {
		return nil, fmt.Errorf("≥100 commits since watermark — full reseed is cheaper")
	}
	oldest := commits[len(commits)-1]
	if len(oldest.Parents) == 0 {
		return nil, fmt.Errorf("oldest commit %.7s has no parent", oldest.SHA)
	}
	cmpURL := fmt.Sprintf("%s/compare/%s...%s", api, oldest.Parents[0].SHA, commits[0].SHA)

	var cmp struct {
		Files []struct {
			Filename string `json:"filename"`
			Status   string `json:"status"`
		} `json:"files"`
	}
	if err := a.getAPIJSON(ctx, cmpURL, &cmp); err != nil {
		return nil, err
	}
	// GitHub's compare endpoint caps `files` at 300 and truncates beyond that
	// (no pagination in this response). A truncated list would silently drop
	// changed files; fall back to a full index walk instead, same as the
	// ≥100-commits guard above. Conditional upsert makes the full pass cheap.
	if len(cmp.Files) >= 300 {
		return nil, fmt.Errorf("compare returned ≥300 files (truncated) — full reseed is safer")
	}
	var changed []string
	for _, f := range cmp.Files {
		if f.Status != "removed" && strings.HasSuffix(f.Filename, "scan.openvex.json") {
			changed = append(changed, f.Filename)
		}
	}
	return changed, nil
}

// fetchAndEmit downloads each per-package document concurrently, parses it, and
// emits its statements. emit is serialised (the orchestrator's emit is not
// concurrency-safe). A single file failing is logged and skipped; only an
// all-failed batch is fatal.
func (a *Adapter) fetchAndEmit(ctx context.Context, rawBase string, locations []string, emit func(source.Statement) error) (syncCounts, error) {
	var (
		mu       sync.Mutex
		counts   syncCounts
		firstErr error
	)
	safeEmit := func(s source.Statement) error {
		mu.Lock()
		defer mu.Unlock()
		return emit(s)
	}

	workers := 16
	if len(locations) < workers {
		workers = len(locations)
	}
	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for loc := range jobs {
				if ctx.Err() != nil {
					return
				}
				c, err := a.fetchFile(ctx, rawBase+loc, safeEmit)
				mu.Lock()
				counts.emitted += c.emitted
				counts.skippedNonCVE += c.skippedNonCVE
				counts.skippedNoSub += c.skippedNoSub
				if err != nil {
					counts.filesFailed++
					if firstErr == nil {
						firstErr = err
					}
				}
				mu.Unlock()
				if err != nil {
					slog.Warn("rancher-vex: per-package file failed; skipping",
						"adapter", a.id, "file", loc, "error", err)
				}
			}
		}()
	}
	for _, loc := range locations {
		if ctx.Err() != nil {
			break
		}
		jobs <- loc
	}
	close(jobs)
	wg.Wait()

	if ctx.Err() != nil {
		return counts, ctx.Err()
	}
	if len(locations) > 0 && counts.filesFailed == len(locations) {
		return counts, fmt.Errorf("all %d per-package fetches failed: %w", len(locations), firstErr)
	}
	return counts, nil
}

// fetchFile downloads + parses one per-package document.
func (a *Adapter) fetchFile(ctx context.Context, rawURL string, emit func(source.Statement) error) (syncCounts, error) {
	b, err := a.getBytes(ctx, rawURL)
	if err != nil {
		return syncCounts{}, err
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

// getBytes GETs a raw file, guards against a Git LFS pointer (served when the
// upstream LFS quota is exhausted), and returns the body. Files are small, so
// reading fully is fine.
func (a *Adapter) getBytes(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", rawURL, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", rawURL, err)
	}
	if bytes.HasPrefix(b, []byte("version https://git-lfs.github.com/spec")) {
		return nil, fmt.Errorf("%s returned a Git LFS pointer, not the document (upstream LFS bandwidth likely exhausted)", rawURL)
	}
	return b, nil
}

// getAPIJSON GETs a GitHub API URL (which requires a User-Agent) and decodes it.
func (a *Adapter) getAPIJSON(ctx context.Context, apiURL string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "reel-vex")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", apiURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", apiURL, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(into)
}

type syncCounts struct {
	emitted       int
	skippedNonCVE int
	skippedNoSub  int
	filesFailed   int
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

	rows := 0
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
			base, version := csaf.SplitPURL(sub)
			idType := "purl"
			if !strings.HasPrefix(sub, "pkg:") {
				idType = "cpe"
			}
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
	if rows == 0 {
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
