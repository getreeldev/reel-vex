// Package csafadapter implements source.Adapter for CSAF 2.0 VEX feeds.
// It delegates CSAF parsing to pkg/csaf; this package only owns the
// orchestration glue (discover, walk changes.csv, fetch, emit).
package csafadapter

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/getreeldev/reel-vex/pkg/csaf"
	"github.com/getreeldev/reel-vex/pkg/source"
)

// Type is the adapter-type string used in config.yaml.
const Type = "csaf"

// New constructs a CSAF adapter from its config entry.
func New(cfg source.AdapterConfig) (source.Adapter, error) {
	if cfg.ID == "" {
		return nil, fmt.Errorf("csaf adapter: id required")
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("csaf adapter %q: url required (should point to provider-metadata.json)", cfg.ID)
	}
	return &Adapter{
		id:          cfg.ID,
		name:        cfg.Name,
		metadataURL: cfg.URL,
		http:        &http.Client{Timeout: 60 * time.Second},
	}, nil
}

// Adapter streams statements from a CSAF 2.0 provider-metadata.json feed.
type Adapter struct {
	id          string
	name        string
	metadataURL string

	// Cached after Discover. Empty until then.
	feedURL string

	http *http.Client
}

func (a *Adapter) ID() string           { return a.id }
func (a *Adapter) Name() string         { return a.name }
func (a *Adapter) SourceFormat() string { return "csaf" }

// Discover resolves the provider-metadata.json, records the VEX feed URL,
// and — if the config left Name empty — picks up the publisher name from
// the metadata.
func (a *Adapter) Discover(ctx context.Context) (*source.FeedInfo, error) {
	p, err := csaf.DiscoverProvider(a.metadataURL)
	if err != nil {
		return nil, fmt.Errorf("discover %s: %w", a.id, err)
	}
	if a.name == "" {
		a.name = p.Name
	}
	a.feedURL = p.VEXFeedURL
	return &source.FeedInfo{FeedURL: p.VEXFeedURL}, nil
}

// Sync walks the feed's changes.csv and fetches each referenced CSAF
// document, extracting VEX statements. Per-document fetch and parse errors
// are logged and skipped so that one broken advisory doesn't abort the
// whole run.
func (a *Adapter) Sync(ctx context.Context, since time.Time, emit func(source.Statement) error) error {
	if a.feedURL == "" {
		if _, err := a.Discover(ctx); err != nil {
			return err
		}
	}
	entries, err := csaf.FetchFeedEntries(a.feedURL, since)
	if err != nil {
		return fmt.Errorf("fetch changes.csv: %w", err)
	}

	for i, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		docURL := csaf.DocumentURL(a.feedURL, entry)
		data, err := a.fetchDocument(ctx, docURL)
		if err != nil {
			slog.Warn("csaf fetch failed", "adapter", a.id, "url", docURL, "error", err)
			continue
		}
		stmts, err := csaf.Extract(data)
		if err != nil {
			slog.Warn("csaf extract failed", "adapter", a.id, "url", docURL, "error", err)
			continue
		}
		for _, s := range stmts {
			if err := emit(source.Statement{
				CVE:           s.CVE,
				ProductID:     s.ProductID,
				BaseID:        s.BaseID,
				Version:       s.Version,
				IDType:        s.IDType,
				Status:        s.Status,
				Justification: s.Justification,
				Updated:       entry.Updated,
			}); err != nil {
				return err
			}
		}
		if i > 0 && i%100 == 0 {
			slog.Info("csaf progress", "adapter", a.id, "processed", i, "of", len(entries))
		}
	}
	return nil
}

func (a *Adapter) fetchDocument(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
