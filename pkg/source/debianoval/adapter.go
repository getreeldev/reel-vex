// Package debianoval implements source.Adapter for Debian Security
// Tracker OVAL feeds. Delegates parsing + VEX-statement emission to
// github.com/getreeldev/oval-to-vex; this package owns the HTTP fetch,
// bz2 decompression, Last-Modified-based incremental sync, and the
// source.Adapter contract.
//
// One adapter instance per Debian release feed file (bullseye, bookworm,
// trixie, ...). Configure against
// https://www.debian.org/security/oval/oval-definitions-<codename>.xml.bz2.
package debianoval

import (
	"compress/bzip2"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/getreeldev/oval-to-vex/translator"
	"github.com/getreeldev/reel-vex/pkg/source"
)

// Type is the adapter-type string used in config.yaml.
const Type = "debian-oval"

// New constructs a Debian OVAL adapter from its config entry.
func New(cfg source.AdapterConfig) (source.Adapter, error) {
	if cfg.ID == "" {
		return nil, fmt.Errorf("debian-oval adapter: id required")
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("debian-oval adapter %q: url required (point at an oval-definitions-<release>.xml.bz2)", cfg.ID)
	}
	name := cfg.Name
	if name == "" {
		name = "Debian"
	}
	return &Adapter{
		id:   cfg.ID,
		name: name,
		url:  cfg.URL,
		http: &http.Client{Timeout: 10 * time.Minute}, // bookworm OVAL is ~6MB compressed, ~40MB uncompressed
	}, nil
}

// Adapter streams statements from a single Debian OVAL feed file. Each
// adapter instance targets one URL; multiple releases (bullseye, bookworm,
// trixie) need distinct adapter entries with distinct IDs.
type Adapter struct {
	id   string
	name string
	url  string

	http *http.Client
}

func (a *Adapter) ID() string { return a.id }

// Vendor returns "debian" regardless of which OVAL file this adapter
// points at.
func (a *Adapter) Vendor() string       { return "debian" }
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

// Sync fetches the OVAL file, decompresses bz2, translates to VEX
// statements, and emits each one. Incremental via Last-Modified.
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
		slog.Warn("no Last-Modified header on Debian OVAL feed", "adapter", a.id)
	} else if !since.IsZero() && !lastModified.After(since) {
		slog.Info("debian-oval up to date, skipping GET", "adapter", a.id, "last_modified", lastModified, "since", since)
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

	stmts, err := translator.FromDebianOVAL(bzip2.NewReader(getResp.Body))
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
	slog.Info("debian-oval sync complete", "adapter", a.id, "statements", len(stmts))
	return nil
}
