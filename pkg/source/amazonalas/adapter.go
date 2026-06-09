// Package amazonalas implements source.Adapter for Amazon Linux Security
// Advisories (ALAS). Amazon publishes NO OVAL or CSAF feed; the advisory data
// lives in each yum repo's repodata/updateinfo.xml. Reaching it is a three-hop
// crawl, re-resolved every run:
//
//  1. GET the repo's mirror.list — a newline-separated list of mirror base URLs.
//     The first usable base wins; the rest are fallbacks. The base path embeds
//     a content GUID that rotates as Amazon republishes, so we never cache it.
//  2. For a base, GET <base>repodata/repomd.xml and find the <data
//     type="updateinfo"> entry's <location href="repodata/updateinfo.xml.gz"/>.
//  3. GET <base><href>, gunzip, parse <updates><update>… into fixed-version
//     VEX statements.
//
// One adapter instance per distro: amzn2 (Amazon Linux 2) and al2023 (Amazon
// Linux 2023). The distro is derived from the configured mirror.list URL, so a
// config entry is just {type, id, url}. Each emits package-level "fixed"
// statements keyed on a distro-qualified RPM PURL
// (pkg:rpm/amazon/<name>?distro=amazon-<major>), mirroring the deb feeds'
// distro-as-identity model; the resolver normalizes a scanner's full
// point-release distro (amazon-2023.7.x) down to amazon-<major> so a query
// matches this major precisely (no cross-major leakage).
//
// SCOPE (v1, locked): core repos only, distros amzn2 + al2023. We deliberately
// do NOT crawl the AL2 "Extras" repos (amzn2extra-*): each topic is a separate
// repo with its own mirror.list/GUID, so covering them means enumerating the
// extras catalog — a meaningfully larger crawl deferred until there's demand.
// AL1 (amzn1) is EOL and skipped entirely.
package amazonalas

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/getreeldev/reel-vex/pkg/source"
	"github.com/getreeldev/reel-vex/pkg/source/httpretry"
)

// Type is the adapter-type string used in config.yaml.
const Type = "amazon-alas"

// syncTimeout bounds a whole crawl (mirror.list + repomd + the multi-MB gzip).
// Generous because the gzipped updateinfo is ~1.3 MB and a mirror can be slow;
// the httpretry transport retries transient blips within this budget.
const syncTimeout = 5 * time.Minute

// New constructs an Amazon Linux ALAS adapter from its config entry. The distro
// (amzn2 vs al2023) is inferred from the mirror.list URL path; an unrecognised
// URL is a hard config error rather than a silent miss.
func New(cfg source.AdapterConfig) (source.Adapter, error) {
	if cfg.ID == "" {
		return nil, fmt.Errorf("amazon-alas adapter: id required")
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("amazon-alas adapter %q: url required (point at a core repo mirror.list)", cfg.ID)
	}
	distro, err := distroFromMirrorURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("amazon-alas adapter %q: %w", cfg.ID, err)
	}
	name := cfg.Name
	if name == "" {
		name = distro.displayName
	}
	return &Adapter{
		id:        cfg.ID,
		name:      name,
		mirrorURL: cfg.URL,
		distro:    distro,
		http:      &http.Client{Timeout: syncTimeout, Transport: httpretry.New(nil)},
	}, nil
}

// Adapter streams ALAS statements for one Amazon Linux distro.
type Adapter struct {
	id        string
	name      string
	mirrorURL string
	distro    distroSpec

	http *http.Client
}

func (a *Adapter) ID() string { return a.id }

// Vendor returns "amazon" for both distros; they're distinguished by the
// ?distro= qualifier on each statement's identifier, not by vendor.
func (a *Adapter) Vendor() string { return "amazon" }
func (a *Adapter) Name() string   { return a.name }

// SourceFormat returns "updateinfo" — the yum repo metadata format ALAS rides
// in. Distinct from "oval"/"csaf"/"openvex" so provenance stays attributable.
func (a *Adapter) SourceFormat() string { return "updateinfo" }

// Discover confirms the mirror.list is reachable. It does not resolve the
// mirror base (Sync re-resolves it every run, since the GUID rotates).
func (a *Adapter) Discover(ctx context.Context) (*source.FeedInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.mirrorURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", a.mirrorURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", a.mirrorURL, resp.StatusCode)
	}
	return &source.FeedInfo{FeedURL: a.mirrorURL}, nil
}

// Sync crawls mirror.list -> repomd.xml -> updateinfo.xml.gz and emits every
// fixed-version statement. The `since` watermark is ignored: Amazon's
// updateinfo carries no document-level Last-Modified we can cheaply HEAD, so we
// re-parse the (small) feed each cycle and let the conditional upsert make the
// redundant rows cheap. Per-statement Updated still reflects each advisory's
// own <updated> date, so ?since= filtering on the API stays correct.
func (a *Adapter) Sync(ctx context.Context, _ time.Time, emit func(source.Statement) error) error {
	bases, err := a.fetchMirrorBases(ctx)
	if err != nil {
		return err
	}
	if len(bases) == 0 {
		return fmt.Errorf("mirror.list %s returned no usable mirror bases", a.mirrorURL)
	}

	data, base, err := a.fetchUpdateInfo(ctx, bases)
	if err != nil {
		return err
	}

	ui, err := parseUpdateInfo(data)
	if err != nil {
		return fmt.Errorf("parse updateinfo from %s: %w", base, err)
	}

	c, err := emitStatements(ui, a.distro, emit)
	if err != nil {
		return err
	}
	slog.Info("amazon-alas sync complete", "adapter", a.id, "mirror", base,
		"advisories", len(ui.ALASList), "statements", c.emitted,
		"skipped_no_cve", c.skippedNoCVE, "undated_advisories", c.undatedAdvisories)
	return nil
}

// fetchMirrorBases GETs mirror.list and returns the base URLs, each normalised
// to a trailing slash so href joining is uniform.
func (a *Adapter) fetchMirrorBases(ctx context.Context) ([]string, error) {
	body, err := a.get(ctx, a.mirrorURL)
	if err != nil {
		return nil, fmt.Errorf("fetch mirror.list %s: %w", a.mirrorURL, err)
	}
	var bases []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasSuffix(line, "/") {
			line += "/"
		}
		bases = append(bases, line)
	}
	return bases, nil
}

// fetchUpdateInfo walks the mirror bases in order: for each, read repomd.xml,
// find the updateinfo href, fetch + gunzip it. The first mirror that yields a
// decompressed body wins; any failure falls through to the next. Returns the
// raw updateinfo XML and the base it came from.
func (a *Adapter) fetchUpdateInfo(ctx context.Context, bases []string) ([]byte, string, error) {
	var lastErr error
	for _, base := range bases {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		data, err := a.fetchUpdateInfoFrom(ctx, base)
		if err != nil {
			slog.Warn("amazon-alas: mirror failed, trying next", "adapter", a.id, "mirror", base, "error", err)
			lastErr = err
			continue
		}
		return data, base, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no mirror bases to try")
	}
	return nil, "", fmt.Errorf("all %d mirror(s) failed for %s: %w", len(bases), a.mirrorURL, lastErr)
}

// fetchUpdateInfoFrom resolves and downloads the updateinfo for one mirror base.
func (a *Adapter) fetchUpdateInfoFrom(ctx context.Context, base string) ([]byte, error) {
	repomdURL := base + "repodata/repomd.xml"
	repomdBytes, err := a.get(ctx, repomdURL)
	if err != nil {
		return nil, fmt.Errorf("repomd.xml: %w", err)
	}
	rm, err := parseRepoMd(repomdBytes)
	if err != nil {
		return nil, fmt.Errorf("parse repomd.xml: %w", err)
	}
	href := rm.updateInfoHref()
	if href == "" {
		return nil, fmt.Errorf("repomd.xml advertises no updateinfo data entry")
	}

	gzURL, err := joinHref(base, href)
	if err != nil {
		return nil, err
	}
	gzBytes, err := a.get(ctx, gzURL)
	if err != nil {
		return nil, fmt.Errorf("updateinfo.xml.gz: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(gzBytes))
	if err != nil {
		return nil, fmt.Errorf("gunzip updateinfo from %s: %w", gzURL, err)
	}
	defer zr.Close()
	data, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("read updateinfo from %s: %w", gzURL, err)
	}
	return data, nil
}

// get GETs a URL fully into memory. Both repomd.xml and the gzipped updateinfo
// are small (KBs to ~1.5 MB), so buffering is fine and keeps the multi-step
// crawl simple.
func (a *Adapter) get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", u, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// joinHref resolves a repomd href (which Amazon writes relative, e.g.
// "repodata/updateinfo.xml.gz") against the mirror base. Resolving via net/url
// tolerates an absolute href too, should a mirror ever emit one.
func joinHref(base, href string) (string, error) {
	bu, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse mirror base %q: %w", base, err)
	}
	ref, err := url.Parse(href)
	if err != nil {
		return "", fmt.Errorf("parse updateinfo href %q: %w", href, err)
	}
	return bu.ResolveReference(ref).String(), nil
}
