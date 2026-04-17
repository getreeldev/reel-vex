// Package redhatoval implements source.Adapter for Red Hat OVAL feeds.
// Delegates parsing + VEX-statement emission to
// github.com/getreeldev/oval-to-vex; this package owns the HTTP fetch,
// bz2 decompression, Last-Modified-based incremental sync, and the
// source.Adapter contract.
package redhatoval

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
const Type = "redhat-oval"

// New constructs a RH OVAL adapter from its config entry.
func New(cfg source.AdapterConfig) (source.Adapter, error) {
	if cfg.ID == "" {
		return nil, fmt.Errorf("redhat-oval adapter: id required")
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("redhat-oval adapter %q: url required (point at a .oval.xml.bz2)", cfg.ID)
	}
	name := cfg.Name
	if name == "" {
		name = "Red Hat"
	}
	return &Adapter{
		id:   cfg.ID,
		name: name,
		url:  cfg.URL,
		http: &http.Client{Timeout: 5 * time.Minute}, // OVAL files can be ~20MB uncompressed
	}, nil
}

// Adapter streams statements from a single Red Hat OVAL feed file. Each
// adapter instance targets one URL; to cover multiple OVAL files (EUS,
// AUS, E4S, unfixed, earlier versions, ...) configure multiple adapter
// entries with distinct IDs.
type Adapter struct {
	id   string
	name string
	url  string

	http *http.Client
}

func (a *Adapter) ID() string { return a.id }

// Vendor returns "redhat" regardless of which OVAL file this adapter
// points at. All Red Hat OVAL files, CSAF feeds, and future RH sources
// share one vendor domain; their provenance differs only in SourceFormat.
func (a *Adapter) Vendor() string       { return "redhat" }
func (a *Adapter) Name() string         { return a.name }
func (a *Adapter) SourceFormat() string { return "oval" }

// Discover resolves the feed URL (for RH OVAL that's just the configured
// URL, no metadata file to parse) and confirms it's reachable.
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
// statements, and emits each one. Incremental via Last-Modified: if the
// server's header is <= since, skip the GET entirely and return without
// emitting anything — the orchestrator's watermark logic leaves the
// existing last_synced in place.
func (a *Adapter) Sync(ctx context.Context, since time.Time, emit func(source.Statement) error) error {
	// HEAD first to check Last-Modified. Saves a 1MB+ download when
	// upstream hasn't regenerated the file.
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
		// Server didn't give us Last-Modified; proceed with the GET to be
		// safe. All RH OVAL mirror hosts we've tested do send it.
		slog.Warn("no Last-Modified header on RH OVAL feed", "adapter", a.id)
	} else if !since.IsZero() && !lastModified.After(since) {
		slog.Info("redhat-oval up to date, skipping GET", "adapter", a.id, "last_modified", lastModified, "since", since)
		return nil
	}

	// GET + decompress + translate.
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

	stmts, err := translator.FromRedHatOVAL(bzip2.NewReader(getResp.Body))
	if err != nil {
		return fmt.Errorf("translate OVAL: %w", err)
	}

	// All statements from one OVAL file share the same Updated timestamp
	// (the file's Last-Modified). Without this, Statement.Updated would be
	// zero and the orchestrator would never bump the watermark.
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
	slog.Info("redhat-oval sync complete", "adapter", a.id, "statements", len(stmts))
	return nil
}
