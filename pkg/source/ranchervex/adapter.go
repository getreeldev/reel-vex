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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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
		return nil, fmt.Errorf("rancher-vex adapter %q: url required (point at rancher.openvex.json)", cfg.ID)
	}
	name := cfg.Name
	if name == "" {
		name = "SUSE Rancher (OpenVEX)"
	}
	return &Adapter{
		id:   cfg.ID,
		name: name,
		url:  cfg.URL,
		http: &http.Client{Timeout: 15 * time.Minute, Transport: httpretry.New(nil)}, // ~80 MB document; allow slow links
	}, nil
}

// Adapter streams statements from the Rancher VEX Hub consolidated document.
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

// Sync streams VEX statements from the consolidated document. Incremental via
// Last-Modified: when the server's value is ≤ since, skip the GET entirely.
//
// The document is one JSON object with a large `statements` array; we walk it
// with a streaming decoder so we never hold all ~140K statements in memory at
// once. The feed carries no per-statement timestamp, so every emitted row is
// stamped with the feed's Last-Modified (or now() if absent) — that becomes the
// adapter watermark for the next incremental cycle.
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
		slog.Warn("no Last-Modified header on Rancher VEX feed; full re-ingest each cycle", "adapter", a.id)
	} else if !since.IsZero() && !lastModified.After(since) {
		slog.Info("rancher-vex up to date, skipping GET", "adapter", a.id, "last_modified", lastModified, "since", since)
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

	// rancher.openvex.json (~100 MB) is stored in Git LFS. When the upstream
	// repo's LFS bandwidth quota is exhausted, raw.githubusercontent.com serves
	// the LFS *pointer* (a tiny text file starting with
	// "version https://git-lfs.github.com/spec/...") instead of the document.
	// Detect it and fail clearly rather than feeding the pointer to the JSON
	// decoder, which only reports a cryptic "invalid character 'v'".
	br := bufio.NewReader(getResp.Body)
	if head, _ := br.Peek(40); bytes.HasPrefix(head, []byte("version https://git-lfs.github.com/spec")) {
		return fmt.Errorf("rancher feed returned a Git LFS pointer, not the document: the upstream repo's LFS bandwidth is likely exhausted (GitHub serves the pointer when the quota is hit). Retry after the quota resets, or fetch via an LFS-aware path")
	}

	fallback := lastModified
	if fallback.IsZero() {
		fallback = time.Now().UTC()
	}

	counts, err := a.streamStatements(ctx, br, fallback, emit)
	if err != nil {
		return err
	}
	slog.Info("rancher-vex sync complete", "adapter", a.id,
		"statements", counts.emitted, "skipped_non_cve", counts.skippedNonCVE, "skipped_no_subcomponent", counts.skippedNoSub)
	return nil
}

type syncCounts struct {
	emitted       int
	skippedNonCVE int
	skippedNoSub  int
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
