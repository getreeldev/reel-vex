// Package oracleoval implements source.Adapter for Oracle Linux errata OVAL
// feeds. Delegates parsing + VEX-statement emission to
// github.com/getreeldev/oval-to-vex (FromOracleOVAL); this package owns the
// HTTP fetch, bz2 decompression, Last-Modified-based incremental sync, and the
// source.Adapter contract.
//
// One adapter instance per Oracle Linux release feed file. Configure against
// https://linux.oracle.com/security/oval/com.oracle.elsa-ol<N>.xml.bz2 — the
// per-release files (one watermark each) rather than the ~11 MB elsa-all bundle.
package oracleoval

import (
	"compress/bzip2"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/getreeldev/oval-to-vex/translator"
	"github.com/getreeldev/reel-vex/pkg/source"
	"github.com/getreeldev/reel-vex/pkg/source/httpretry"
)

// Type is the adapter-type string used in config.yaml.
const Type = "oracle-oval"

// New constructs an Oracle Linux OVAL adapter from its config entry.
func New(cfg source.AdapterConfig) (source.Adapter, error) {
	if cfg.ID == "" {
		return nil, fmt.Errorf("oracle-oval adapter: id required")
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("oracle-oval adapter %q: url required (point at a com.oracle.elsa-ol<N>.xml.bz2)", cfg.ID)
	}
	name := cfg.Name
	if name == "" {
		name = "Oracle Linux"
	}
	return &Adapter{
		id:   cfg.ID,
		name: name,
		url:  cfg.URL,
		http: &http.Client{Timeout: 10 * time.Minute, Transport: httpretry.New(nil)}, // per-release OVAL is a few MB compressed, tens uncompressed
	}, nil
}

// Adapter streams statements from a single Oracle Linux OVAL feed file. Each
// adapter instance targets one URL; multiple releases (ol8, ol9, ol10) need
// distinct adapter entries with distinct IDs.
type Adapter struct {
	id   string
	name string
	url  string

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
		slog.Warn("no Last-Modified header on Oracle OVAL feed", "adapter", a.id)
	} else if !since.IsZero() && !lastModified.After(since) {
		slog.Info("oracle-oval up to date, skipping GET", "adapter", a.id, "last_modified", lastModified, "since", since)
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

	stmts, err := translator.FromOracleOVAL(bzip2.NewReader(getResp.Body))
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
	slog.Info("oracle-oval sync complete", "adapter", a.id, "statements", len(stmts))
	return nil
}
