// Package alpinesecdb implements source.Adapter for the Alpine Linux security
// database (secdb) feeds at https://secdb.alpinelinux.org. This package owns
// the HTTP fetch, Last-Modified-based incremental sync, JSON parse, and the
// source.Adapter contract.
//
// One adapter instance per (branch × repository) feed file — e.g.
// https://secdb.alpinelinux.org/v3.21/main.json and .../community.json.
// Branches are named explicitly (v3.19 .. v3.24); there is no latest-stable
// alias. The body is small, uncompressed JSON, so there is no decompression
// step (unlike the OVAL adapters).
//
// Schema (per feed file):
//
//	{ "distroversion": "v3.21", "reponame": "main",
//	  "packages": [ { "pkg": { "name": "busybox",
//	    "secfixes": { "1.34.0-r0": ["CVE-2021-42374", ...],
//	                  "0":         ["CVE-2021-42373", ...] } } } ] }
//
// secfixes maps a fixed apk version to the list of advisory ids fixed in it.
// The version key "0" means the CVE does not apply to the package (Alpine's
// security-rejections README; Wolfi and Anchore's vunnel read it the same
// way) — those ids become `not_affected` statements (vulnerable_code_not_present)
// with an empty Version. Any other key is a real fixed version and yields a
// `fixed` statement with that version verbatim.
//
// product_id carries no version, so a (package, CVE) is one row. When a CVE is
// listed under several keys the adapter picks one deterministically (secfixes
// is a Go map): the highest fixed version by apk version ordering wins, and
// "0" is used only when no fixed version lists the CVE.
//
// Only `CVE-`-prefixed ids are emitted; Alpine also files non-CVE advisories
// (XSA-, ALPINE-, DW-, ...) which reel-vex does not key on. The skipped count is
// logged (mirrors the Rancher VEX adapter).
package alpinesecdb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	apkversion "github.com/knqyf263/go-apk-version"

	"github.com/getreeldev/reel-vex/pkg/source"
	"github.com/getreeldev/reel-vex/pkg/source/httpretry"
)

// Type is the adapter-type string used in config.yaml.
const Type = "alpine-secdb"

// notApplicableKey is the secfixes version key Alpine uses for ids that do not
// apply to the package. It maps to a `not_affected` statement with an empty
// version (the rest are `fixed` with the key as the fixed version).
const notApplicableKey = "0"

// New constructs an Alpine secdb adapter from its config entry.
func New(cfg source.AdapterConfig) (source.Adapter, error) {
	if cfg.ID == "" {
		return nil, fmt.Errorf("alpine-secdb adapter: id required")
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("alpine-secdb adapter %q: url required (point at a <branch>/{main,community}.json)", cfg.ID)
	}
	name := cfg.Name
	if name == "" {
		name = "Alpine Linux"
	}
	return &Adapter{
		id:   cfg.ID,
		name: name,
		url:  cfg.URL,
		http: &http.Client{Timeout: 5 * time.Minute, Transport: httpretry.New(nil)}, // tiny uncompressed JSON
	}, nil
}

// Adapter streams statements from a single Alpine secdb feed file. Each adapter
// instance targets one URL; multiple branch×repo feeds (v3.21/main,
// v3.21/community, ...) need distinct adapter entries with distinct IDs.
type Adapter struct {
	id   string
	name string
	url  string

	http *http.Client
}

func (a *Adapter) ID() string { return a.id }

// Vendor returns "alpine" regardless of which secdb file this adapter points at.
func (a *Adapter) Vendor() string { return "alpine" }
func (a *Adapter) Name() string   { return a.name }

// SourceFormat returns "secdb" — Alpine's own advisory format, distinct from
// the "oval"/"csaf"/"openvex" feeds.
func (a *Adapter) SourceFormat() string { return "secdb" }

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

// secdb is the on-the-wire shape of an Alpine secdb feed file. Only the fields
// reel-vex consumes are decoded; apkurl/archs/urlprefix/reponame are ignored.
// distroversion is read from the body (authoritative) rather than parsed from
// the URL.
type secdb struct {
	DistroVersion string `json:"distroversion"`
	Packages      []struct {
		Pkg struct {
			Name     string              `json:"name"`
			Secfixes map[string][]string `json:"secfixes"`
		} `json:"pkg"`
	} `json:"packages"`
}

// Sync fetches the secdb JSON, parses it, and emits one statement per
// (package × CVE id), in sorted order. Incremental via Last-Modified.
func (a *Adapter) Sync(ctx context.Context, since time.Time, emit func(source.Statement) error) (source.SyncResult, error) {
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
		slog.Warn("no Last-Modified header on Alpine secdb feed", "adapter", a.id)
	} else if !since.IsZero() && !lastModified.After(since) {
		slog.Info("alpine-secdb up to date, skipping GET", "adapter", a.id, "last_modified", lastModified, "since", since)
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
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		return source.SyncResult{}, fmt.Errorf("GET %s: HTTP %d", a.url, getResp.StatusCode)
	}

	body, err := io.ReadAll(getResp.Body)
	if err != nil {
		return source.SyncResult{}, fmt.Errorf("read %s: %w", a.url, err)
	}
	var feed secdb
	if err := json.Unmarshal(body, &feed); err != nil {
		return source.SyncResult{}, fmt.Errorf("parse secdb %s: %w", a.url, err)
	}

	updated := lastModified
	if updated.IsZero() {
		updated = time.Now().UTC()
	}

	// Branch-scoped identity: store ?distro=alpine-<major.minor> so the same
	// (package, CVE) on different branches (v3.20 vs v3.21) stays a distinct row
	// — the statements PK includes product_id, so without the qualifier the
	// fixed-versions would collide and only one branch would survive. The
	// resolver normalizes a scanner's apk distro qualifier (Trivy "3.21.3", syft
	// "alpine-3.21.2") to this form so queries still match. distroversion is the
	// branch label, e.g. "v3.21".
	distroQual := ""
	if dv := strings.TrimPrefix(feed.DistroVersion, "v"); dv != "" {
		if parts := strings.SplitN(dv, ".", 3); len(parts) >= 2 {
			distroQual = "?distro=alpine-" + parts[0] + "." + parts[1]
		} else {
			distroQual = "?distro=alpine-" + dv
		}
	}

	var emitted, skippedNonCVE int
	for _, p := range feed.Packages {
		name := p.Pkg.Name
		if name == "" {
			continue
		}
		base := "pkg:apk/alpine/" + name + distroQual
		fixes := map[string]string{} // CVE → highest fixed version
		notApplicable := map[string]bool{}
		for key, ids := range p.Pkg.Secfixes {
			for _, id := range ids {
				// A secfixes value can glue a CVE to non-CVE advisory refs with
				// whitespace, e.g. "CVE-2021-27219 GHSL-2021-045" (324 such in
				// v3.21/main alone). Split and keep only the CVE token(s) so the
				// stored CVE is a bare id a scanner query can match.
				matched := false
				for _, tok := range strings.Fields(id) {
					if !strings.HasPrefix(tok, "CVE-") {
						continue
					}
					matched = true
					if key == notApplicableKey {
						notApplicable[tok] = true
					} else if cur, ok := fixes[tok]; !ok || laterFix(key, cur) {
						fixes[tok] = key
					}
				}
				if !matched {
					skippedNonCVE++
				}
			}
		}

		cves := make([]string, 0, len(fixes)+len(notApplicable))
		for cve := range fixes {
			cves = append(cves, cve)
		}
		for cve := range notApplicable {
			if _, ok := fixes[cve]; !ok {
				cves = append(cves, cve)
			}
		}
		sort.Strings(cves)
		for _, cve := range cves {
			if err := ctx.Err(); err != nil {
				return source.SyncResult{}, err
			}
			status, justification := "fixed", ""
			version, isFixed := fixes[cve]
			if !isFixed {
				status, justification = "not_affected", "vulnerable_code_not_present"
			}
			if err := emit(source.Statement{
				CVE:           cve,
				ProductID:     base,
				BaseID:        base,
				Version:       version,
				IDType:        "purl",
				Status:        status,
				Justification: justification,
				Scope:         "",
				Updated:       updated,
			}); err != nil {
				return source.SyncResult{}, err
			}
			emitted++
		}
	}

	slog.Info("alpine-secdb sync complete", "adapter", a.id,
		"distroversion", feed.DistroVersion, "statements", emitted, "skipped_non_cve", skippedNonCVE)
	return source.SyncResult{Complete: true}, nil
}

// laterFix reports whether fixed version a outranks b: higher by apk version
// ordering; a key apk cannot parse loses to any valid one; ties (including two
// unparseable keys) go to the greater string.
func laterFix(a, b string) bool {
	av, aErr := apkversion.NewVersion(a)
	bv, bErr := apkversion.NewVersion(b)
	switch {
	case aErr == nil && bErr != nil:
		return true
	case aErr != nil && bErr == nil:
		return false
	case aErr == nil:
		if c := av.Compare(bv); c != 0 {
			return c > 0
		}
	}
	return a > b
}
