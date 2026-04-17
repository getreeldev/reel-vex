// Package ingest orchestrates source.Adapters: for each configured adapter,
// discover the feed, stream statements since the last watermark, batch-
// insert into the database, and update the watermark.
package ingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/getreeldev/reel-vex/pkg/db"
	"github.com/getreeldev/reel-vex/pkg/source"
)

// Options controls ingest behavior.
type Options struct {
	// Limit caps the number of statements emitted per adapter. Zero means
	// unlimited. Dev/testing convenience; production should leave it at 0.
	Limit int
}

// Run drives every adapter sequentially. A failure in one adapter is logged
// and skipped — the others still run.
func Run(ctx context.Context, adapters []source.Adapter, database *db.DB, opts Options) error {
	for _, a := range adapters {
		if err := runAdapter(ctx, a, database, opts); err != nil {
			slog.Error("adapter ingest failed", "adapter", a.ID(), "error", err)
			continue
		}
	}
	return nil
}

// errLimitReached signals emit() to stop streaming because Options.Limit was
// hit. Caught and swallowed by runAdapter; never escapes.
var errLimitReached = errors.New("statement limit reached")

func runAdapter(ctx context.Context, a source.Adapter, database *db.DB, opts Options) error {
	slog.Info("adapter discover", "adapter", a.ID(), "format", a.SourceFormat())
	feed, err := a.Discover(ctx)
	if err != nil {
		return fmt.Errorf("discover: %w", err)
	}
	if err := database.UpsertVendor(a.ID(), a.Name(), feed.FeedURL); err != nil {
		return fmt.Errorf("upsert vendor: %w", err)
	}

	var since time.Time
	lastSynced, err := database.VendorLastSynced(a.ID())
	if err != nil {
		return fmt.Errorf("last_synced: %w", err)
	}
	if lastSynced != "" {
		since, _ = time.Parse(time.RFC3339, lastSynced)
		slog.Info("incremental sync", "adapter", a.ID(), "since", since)
	} else {
		slog.Info("full sync", "adapter", a.ID())
	}

	const batchSize = 5000
	var (
		batch     []db.Statement
		newest    time.Time
		processed int
	)

	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := database.BulkInsert(batch); err != nil {
			return err
		}
		batch = batch[:0]
		return nil
	}

	emit := func(s source.Statement) error {
		if opts.Limit > 0 && processed >= opts.Limit {
			return errLimitReached
		}
		if s.Updated.After(newest) {
			newest = s.Updated
		}
		batch = append(batch, db.Statement{
			Vendor:        a.ID(),
			CVE:           s.CVE,
			ProductID:     s.ProductID,
			BaseID:        s.BaseID,
			Version:       s.Version,
			IDType:        s.IDType,
			Status:        s.Status,
			Justification: s.Justification,
			Updated:       s.Updated.Format(time.RFC3339),
			SourceFormat:  a.SourceFormat(),
		})
		processed++
		if len(batch) >= batchSize {
			return flush()
		}
		return nil
	}

	err = a.Sync(ctx, since, emit)
	if err != nil && !errors.Is(err, errLimitReached) {
		return fmt.Errorf("sync: %w", err)
	}
	if err := flush(); err != nil {
		return fmt.Errorf("flush: %w", err)
	}

	if !newest.IsZero() {
		if err := database.SetVendorSynced(a.ID(), newest.Format(time.RFC3339)); err != nil {
			return fmt.Errorf("set synced: %w", err)
		}
	}
	slog.Info("adapter done", "adapter", a.ID(), "processed", processed)
	return nil
}
