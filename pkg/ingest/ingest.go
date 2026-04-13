package ingest

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/getreeldev/reel-vex/pkg/csaf"
	"github.com/getreeldev/reel-vex/pkg/db"
)

var httpClient = &http.Client{
	Timeout: 60 * time.Second,
}

// ProviderConfig is the configuration for a single CSAF provider.
type ProviderConfig struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	MetadataURL string `yaml:"url"`
}

// Config is the top-level ingest configuration.
type Config struct {
	Providers []ProviderConfig `yaml:"providers"`
}

// Options controls ingest behavior.
type Options struct {
	Limit int // max documents to process per provider (0 = unlimited)
}

// Run executes ingestion for all configured providers.
func Run(cfg Config, database *db.DB, opts Options) error {
	for _, pc := range cfg.Providers {
		if err := ingestProvider(pc, database, opts); err != nil {
			slog.Error("provider ingest failed", "provider", pc.ID, "error", err)
			continue
		}
	}
	return nil
}

func ingestProvider(pc ProviderConfig, database *db.DB, opts Options) error {
	slog.Info("discovering provider", "id", pc.ID, "url", pc.MetadataURL)

	provider, err := csaf.DiscoverProvider(pc.MetadataURL)
	if err != nil {
		return fmt.Errorf("discover provider %s: %w", pc.ID, err)
	}
	slog.Info("found VEX feed", "provider", pc.ID, "feed_url", provider.VEXFeedURL)

	if err := database.UpsertVendor(pc.ID, provider.Name, provider.VEXFeedURL); err != nil {
		return fmt.Errorf("upsert vendor: %w", err)
	}

	var since time.Time
	lastSynced, err := database.VendorLastSynced(pc.ID)
	if err != nil {
		return fmt.Errorf("get last synced: %w", err)
	}
	if lastSynced != "" {
		since, _ = time.Parse(time.RFC3339, lastSynced)
		slog.Info("incremental sync", "provider", pc.ID, "since", since)
	} else {
		slog.Info("full sync", "provider", pc.ID)
	}

	entries, err := csaf.FetchFeedEntries(provider.VEXFeedURL, since)
	if err != nil {
		return fmt.Errorf("fetch feed: %w", err)
	}
	slog.Info("feed entries", "provider", pc.ID, "count", len(entries))

	if opts.Limit > 0 && len(entries) > opts.Limit {
		entries = entries[:opts.Limit]
		slog.Info("limiting to", "count", opts.Limit)
	}

	var (
		processed int
		failed    int
		newest    time.Time
	)

	const batchSize = 5000
	var batch []db.Statement

	for i, entry := range entries {
		if entry.Updated.After(newest) {
			newest = entry.Updated
		}

		docURL := csaf.DocumentURL(provider.VEXFeedURL, entry)
		data, err := fetchDocument(docURL)
		if err != nil {
			slog.Warn("fetch document failed", "url", docURL, "error", err)
			failed++
			continue
		}

		stmts, err := csaf.Extract(data)
		if err != nil {
			slog.Warn("extract failed", "url", docURL, "error", err)
			failed++
			continue
		}

		for _, s := range stmts {
			batch = append(batch, db.Statement{
				Vendor:        pc.ID,
				CVE:           s.CVE,
				ProductID:     s.ProductID,
				IDType:        s.IDType,
				Status:        s.Status,
				Justification: s.Justification,
				Updated:       entry.Updated.Format(time.RFC3339),
			})
		}

		if len(batch) >= batchSize {
			if err := database.BulkInsert(batch); err != nil {
				return fmt.Errorf("bulk insert: %w", err)
			}
			batch = batch[:0]
		}

		processed++
		if processed%100 == 0 {
			slog.Info("progress", "provider", pc.ID, "processed", processed, "of", len(entries), "failed", failed)
		}

		if i < 3 {
			slog.Info("processed document", "path", entry.Path, "statements", len(stmts))
		}
	}

	if len(batch) > 0 {
		if err := database.BulkInsert(batch); err != nil {
			return fmt.Errorf("bulk insert: %w", err)
		}
	}

	if !newest.IsZero() {
		if err := database.SetVendorSynced(pc.ID, newest.Format(time.RFC3339)); err != nil {
			return fmt.Errorf("set vendor synced: %w", err)
		}
	}

	slog.Info("ingest complete", "provider", pc.ID, "processed", processed, "failed", failed)
	return nil
}

func fetchDocument(url string) ([]byte, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}
