// Package oracleoval implements source.Adapter for Oracle Linux errata OVAL
// feeds. Delegates parsing + VEX-statement emission to
// github.com/getreeldev/oval-to-vex (FromOracleOVAL); this package owns the
// HTTP fetch, bz2 decompression, Last-Modified-based incremental sync, and the
// source.Adapter contract.
//
// One adapter instance per Oracle Linux release feed file. Configure against
// https://linux.oracle.com/security/oval/com.oracle.elsa-ol<N>.xml.bz2 — the
// per-release files (one watermark each) rather than the ~11 MB elsa-all bundle.
//
// An ELSA in one release's file can also cover other releases, and the
// translator emits each package under its own release, so the ol9 file yields
// some distro=oracle-8 rows that the ol8 adapter writes too. The adapter keeps
// only rows of its own release, N from the configured file name; New refuses a
// URL it cannot read N from.
//
// The own-release file is authoritative for its release, and that has a known
// gap: an ELSA's copy in another release's file can list packages of this
// release that this file's copy does not, and those are dropped.
// ELSA-2026-500137 (a UEK update) in the ol8 file lists 19 OL9 packages that
// its copy in the ol9 file lacks (2026-10); they reach no row.
package oracleoval

import (
	"compress/bzip2"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/getreeldev/oval-to-vex/translator"
	"github.com/getreeldev/reel-vex/pkg/source"
	"github.com/getreeldev/reel-vex/pkg/source/httpretry"
)

// Type is the adapter-type string used in config.yaml.
const Type = "oracle-oval"

// releaseFile matches the per-release feed file name and captures the release.
var releaseFile = regexp.MustCompile(`^com\.oracle\.elsa-ol(\d+)\.xml\.bz2$`)

// New constructs an Oracle Linux OVAL adapter from its config entry.
func New(cfg source.AdapterConfig) (source.Adapter, error) {
	if cfg.ID == "" {
		return nil, fmt.Errorf("oracle-oval adapter: id required")
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("oracle-oval adapter %q: url required (point at a com.oracle.elsa-ol<N>.xml.bz2)", cfg.ID)
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("oracle-oval adapter %q: parse url: %w", cfg.ID, err)
	}
	m := releaseFile.FindStringSubmatch(path.Base(u.Path))
	if m == nil {
		return nil, fmt.Errorf("oracle-oval adapter %q: cannot read the release from url %q (want .../com.oracle.elsa-ol<N>.xml.bz2)", cfg.ID, cfg.URL)
	}
	name := cfg.Name
	if name == "" {
		name = "Oracle Linux"
	}
	return &Adapter{
		id:      cfg.ID,
		name:    name,
		url:     cfg.URL,
		release: m[1],
		http:    &http.Client{Timeout: 10 * time.Minute, Transport: httpretry.New(nil)}, // per-release OVAL is a few MB compressed, tens uncompressed
	}, nil
}

// Adapter streams statements from a single Oracle Linux OVAL feed file. Each
// adapter instance targets one URL; multiple releases (ol8, ol9, ol10) need
// distinct adapter entries with distinct IDs.
type Adapter struct {
	id      string
	name    string
	url     string
	release string // "9" for com.oracle.elsa-ol9.xml.bz2

	http *http.Client
}

func (a *Adapter) ID() string { return a.id }

// Vendor returns "oracle" regardless of which OVAL file this adapter points at.
func (a *Adapter) Vendor() string       { return "oracle" }
func (a *Adapter) Name() string         { return a.name }
func (a *Adapter) SourceFormat() string { return "oval" }

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

// Sync fetches the OVAL file, decompresses bz2, translates to VEX statements,
// and emits each one. Incremental via Last-Modified.
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
		slog.Warn("no Last-Modified header on Oracle OVAL feed", "adapter", a.id)
	} else if !since.IsZero() && !lastModified.After(since) {
		slog.Info("oracle-oval up to date, skipping GET", "adapter", a.id, "last_modified", lastModified, "since", since)
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

	stmts, err := translator.FromOracleOVAL(bzip2.NewReader(getResp.Body))
	if err != nil {
		return source.SyncResult{}, fmt.Errorf("translate OVAL: %w", err)
	}

	updated := lastModified
	if updated.IsZero() {
		updated = time.Now().UTC()
	}
	own := "?distro=oracle-" + a.release
	var emitted, otherRelease int
	for _, s := range stmts {
		if err := ctx.Err(); err != nil {
			return source.SyncResult{}, err
		}
		if !strings.HasSuffix(s.BaseID, own) {
			otherRelease++
			continue
		}
		if err := emit(source.Statement{
			CVE:           s.CVE,
			ProductID:     s.ProductID,
			BaseID:        s.BaseID,
			Version:       s.Version,
			VersionKind:   source.FixedInKind(s.Status, s.Version),
			IDType:        s.IDType,
			Status:        s.Status,
			Justification: s.Justification,
			Updated:       updated,
		}); err != nil {
			return source.SyncResult{}, err
		}
		emitted++
	}
	slog.Info("oracle-oval sync complete", "adapter", a.id, "release", a.release,
		"statements", emitted, "skipped_other_release", otherRelease)
	return source.SyncResult{Complete: true}, nil
}
