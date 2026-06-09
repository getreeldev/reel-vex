// Package almalinuxoval implements source.Adapter for AlmaLinux errata OVAL
// feeds. Delegates parsing + VEX-statement emission to
// github.com/getreeldev/oval-to-vex (FromAlmaLinuxOVAL); this package owns the
// HTTP fetch, bz2 decompression, Last-Modified-based incremental sync, and the
// source.Adapter contract.
//
// One adapter instance per AlmaLinux major release. Configure against
// https://security.almalinux.org/oval/org.almalinux.alsa-<N>.xml.bz2. The
// release major (8, 9, 10) is parsed from the URL filename and passed to the
// parser — AlmaLinux's OVAL IDs don't encode it, and it becomes the
// ?distro=almalinux-<N> qualifier on every emitted PURL.
package almalinuxoval

import (
	"compress/bzip2"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/getreeldev/oval-to-vex/translator"
	"github.com/getreeldev/reel-vex/pkg/source"
	"github.com/getreeldev/reel-vex/pkg/source/httpretry"
)

// Type is the adapter-type string used in config.yaml.
const Type = "almalinux-oval"

// releaseRe pulls the major release out of an AlmaLinux OVAL filename, e.g.
// org.almalinux.alsa-9.xml.bz2 -> "9".
var releaseRe = regexp.MustCompile(`alsa-(\d+)`)

// New constructs an AlmaLinux OVAL adapter from its config entry. The release
// major is derived from the URL; an unrecognised URL is a hard config error
// (the parser needs the major for the ?distro= qualifier — without it the rows
// have no stable identity).
func New(cfg source.AdapterConfig) (source.Adapter, error) {
	if cfg.ID == "" {
		return nil, fmt.Errorf("almalinux-oval adapter: id required")
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("almalinux-oval adapter %q: url required (point at an org.almalinux.alsa-<N>.xml.bz2)", cfg.ID)
	}
	m := releaseRe.FindStringSubmatch(cfg.URL)
	if len(m) < 2 {
		return nil, fmt.Errorf("almalinux-oval adapter %q: cannot derive release major from url %q (expected .../org.almalinux.alsa-<N>.xml.bz2)", cfg.ID, cfg.URL)
	}
	release := m[1]
	name := cfg.Name
	if name == "" {
		name = "AlmaLinux " + release
	}
	return &Adapter{
		id:      cfg.ID,
		name:    name,
		url:     cfg.URL,
		release: release,
		http:    &http.Client{Timeout: 10 * time.Minute, Transport: httpretry.New(nil)}, // alsa-8 is ~1.4MB compressed, ~38MB uncompressed
	}, nil
}

// Adapter streams statements from a single AlmaLinux OVAL feed file.
type Adapter struct {
	id      string
	name    string
	url     string
	release string // major, e.g. "9" — the ?distro=almalinux-<release> qualifier

	http *http.Client
}

func (a *Adapter) ID() string { return a.id }

// Vendor returns "almalinux" regardless of which OVAL file this adapter points at.
func (a *Adapter) Vendor() string       { return "almalinux" }
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

// Sync fetches the OVAL file, decompresses bz2, translates to VEX statements
// (one per CVE × package × namespace), and emits each. Incremental via Last-Modified.
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
		slog.Warn("no Last-Modified header on AlmaLinux OVAL feed", "adapter", a.id)
	} else if !since.IsZero() && !lastModified.After(since) {
		slog.Info("almalinux-oval up to date, skipping GET", "adapter", a.id, "last_modified", lastModified, "since", since)
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

	stmts, err := translator.FromAlmaLinuxOVAL(bzip2.NewReader(getResp.Body), a.release)
	if err != nil {
		return fmt.Errorf("translate OVAL: %w", err)
	}

	updated := lastModified
	if updated.IsZero() {
		updated = time.Now().UTC()
	}
	for _, s := range stmts {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := emit(source.Statement{
			CVE:           s.CVE,
			ProductID:     s.ProductID,
			BaseID:        s.BaseID,
			Version:       s.Version,
			IDType:        s.IDType,
			Status:        s.Status,
			Justification: s.Justification,
			Updated:       updated,
		}); err != nil {
			return err
		}
	}
	slog.Info("almalinux-oval sync complete", "adapter", a.id, "release", a.release, "statements", len(stmts))
	return nil
}
