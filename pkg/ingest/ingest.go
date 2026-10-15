// Package ingest orchestrates source.Adapters: for each configured adapter,
// discover the feed, stream statements since the last watermark, batch-
// insert into the database, and update the watermark.
package ingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"time"

	"github.com/getreeldev/reel-vex/pkg/aliases"
	"github.com/getreeldev/reel-vex/pkg/db"
	"github.com/getreeldev/reel-vex/pkg/source"
)

// Options controls ingest behavior.
type Options struct {
	// Limit caps the number of statements emitted per adapter. Zero means
	// unlimited. Dev/testing convenience; production should leave it at 0.
	Limit int
	// SweepMaxFraction bounds removal of rows an adapter no longer emits. A
	// whole-feed sweep is refused when more than this fraction of the rows the
	// adapter owns would go, and a withdrawal when more than this fraction of
	// the CVEs it holds would. 0 (or less) disables every removal and records
	// no seen keys; >= 1 lifts the fraction guards (a whole-feed sweep that saw
	// nothing is still refused).
	SweepMaxFraction float64
	// SweepForce names adapters whose fraction guards are lifted, as
	// SweepMaxFraction 1 would lift them, on every run with these options. A
	// refused whole-feed sweep stays refused, because the rows it would delete
	// still count in the next run's denominator; this is the way out for one
	// adapter without lifting the guard for all of them. The nothing-seen and
	// empty-manifest refusals stay, and SweepMaxFraction 0 still disables
	// removal.
	SweepForce []string
}

// Run drives every adapter then every alias fetcher sequentially. A failure
// in any one is logged and skipped so the others still run.
//
// Run holds the database's ingest lock throughout, and returns an error
// wrapping db.ErrIngestRunning, having touched nothing, when another ingest
// holds it: nothing else stops a second process (a CronJob running the ingest
// subcommand beside a server's scheduler) from replacing this run's seen keys
// mid-sync, after which its sweep would delete live rows. Only once the lock
// is held does Run end every sweep session a previous run left open,
// including one a crashed process orphaned.
func Run(ctx context.Context, adapters []source.Adapter, fetchers []aliases.Fetcher, database db.Store, opts Options) error {
	if err := database.TryLockIngest(); err != nil {
		if errors.Is(err, db.ErrIngestRunning) {
			slog.Warn("ingest not started: another ingest is running on this database")
		}
		return fmt.Errorf("ingest: %w", err)
	}
	defer func() {
		if err := database.UnlockIngest(); err != nil {
			slog.Warn("ingest unlock failed", "error", err)
		}
	}()
	if err := database.ResetSweeps(); err != nil {
		slog.Warn("reset sweeps failed", "error", err)
	}
	for _, a := range adapters {
		if err := runAdapter(ctx, a, database, opts); err != nil {
			slog.Error("adapter ingest failed", "adapter", a.ID(), "error", err)
			continue
		}
	}
	for _, f := range fetchers {
		if err := f.Fetch(ctx, database); err != nil {
			slog.Error("alias fetcher failed", "fetcher", f.ID(), "error", err)
			continue
		}
	}
	// Build the broad-mode covering index if it's missing. On the cold first
	// ingest this runs once, after the index-free bulk load (the fast path), and
	// can take minutes on a prod-size table; on later cycles the index already
	// exists and this no-ops. Keeping it out of the schema migration is what lets
	// the cold load avoid maintain-during.
	slog.Info("ensuring broad-mode covering index (builds once on first ingest, may take minutes)")
	if err := database.EnsureCoveringIndex(); err != nil {
		slog.Warn("ensure covering index failed", "error", err)
	}
	// Refresh the /v1/stats cache after any ingest activity. The cache is
	// the only thing that keeps that endpoint fast on a multi-GB DB; without
	// this hook it would only refresh on first read after restart.
	if _, err := database.RefreshStats(); err != nil {
		slog.Warn("stats cache refresh failed", "error", err)
	}
	// Refresh planner statistics so broad mode picks the covering index when
	// base_id is combined with vendor/status/justification filters.
	if err := database.Optimize(); err != nil {
		slog.Warn("db optimize failed", "error", err)
	}
	return nil
}

// errLimitReached signals emit() to stop streaming because Options.Limit was
// hit. Caught and swallowed by runAdapter; never escapes.
var errLimitReached = errors.New("statement limit reached")

func runAdapter(ctx context.Context, a source.Adapter, database db.Store, opts Options) error {
	slog.Info("adapter discover", "adapter", a.ID(), "vendor", a.Vendor(), "format", a.SourceFormat())
	feed, err := a.Discover(ctx)
	if err != nil {
		return fmt.Errorf("discover: %w", err)
	}
	if err := database.UpsertVendor(a.Vendor(), a.Name()); err != nil {
		return fmt.Errorf("upsert vendor: %w", err)
	}

	var since time.Time
	lastSynced, err := database.AdapterLastSynced(a.ID())
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
		// limitHit and flushFailed are set inside the closures, so neither an
		// adapter that swallows emit's error nor one that rewraps it can make
		// a cut or partly-failed run look whole.
		limitHit, flushFailed bool
		// seen counts the keys recorded into the open sweep session.
		seen int64
	)

	// Removal: open a sweep session before Sync, so every key the sync emits
	// is recorded and FinishSweep can delete the adapter's rows it did not.
	// skip holds the first reason this run removes nothing.
	var skip string
	sessionOpen := false
	maxFraction := opts.SweepMaxFraction
	forced := maxFraction > 0 && maxFraction < 1 && slices.Contains(opts.SweepForce, a.ID())
	if forced {
		maxFraction = 1
	}
	if !(opts.SweepMaxFraction > 0) {
		skip = "disabled"
	} else if err := database.StartSweep(a.ID()); err != nil {
		slog.Error("start sweep failed; ingesting without removal", "adapter", a.ID(), "error", err)
		skip = "start error"
	} else {
		sessionOpen = true
	}
	endSession := func() {
		sessionOpen = false
		if err := database.AbortSweep(a.ID()); err != nil {
			slog.Warn("abort sweep failed", "adapter", a.ID(), "error", err)
		}
	}
	// A session still open at return means Sync panicked: end it, and log the
	// run's one sweep line.
	defer func() {
		if sessionOpen {
			endSession()
			logSweep(a.ID(), "cves:0", db.SweepResult{Seen: seen}, "aborted", false, nil)
		}
	}()

	// A ChangedDocsAdapter's stored fingerprints name the documents whose rows
	// are as its last run left them. They are cleared before this run changes
	// any row and stored again only once its removal finished, so a run that
	// stops part-way — on an error or a killed process — leaves none, and the
	// next run reads every document.
	cd, changedDocs := a.(source.ChangedDocsAdapter)
	fingerprintsCleared := false
	clearFingerprints := func() error {
		if !changedDocs || fingerprintsCleared {
			return nil
		}
		if err := database.SaveDocumentFingerprints(a.ID(), nil); err != nil {
			return fmt.Errorf("clear document fingerprints: %w", err)
		}
		fingerprintsCleared = true
		return nil
	}

	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := clearFingerprints(); err != nil {
			flushFailed = true
			return err
		}
		if err := database.BulkInsert(batch); err != nil {
			flushFailed = true
			return err
		}
		if sessionOpen {
			keys := make([]db.StatementKey, len(batch))
			for i, st := range batch {
				keys[i] = db.StatementKey{CVE: st.CVE, ProductID: st.ProductID, Scope: st.Scope,
					Stream: st.Stream, Status: st.Status, Justification: st.Justification}
			}
			if err := database.RecordSeen(a.ID(), keys); err != nil {
				flushFailed = true
				return err
			}
			seen += int64(len(keys))
		}
		batch = batch[:0]
		return nil
	}

	emit := func(s source.Statement) error {
		if opts.Limit > 0 && processed >= opts.Limit {
			limitHit = true
			return errLimitReached
		}
		if s.Updated.After(newest) {
			newest = s.Updated
		}
		versions := s.Versions
		if len(versions) == 0 && s.Version != "" {
			versions = []string{s.Version}
		}
		batch = append(batch, db.Statement{
			Vendor:        a.Vendor(),
			CVE:           s.CVE,
			ProductID:     s.ProductID,
			BaseID:        s.BaseID,
			Versions:      versions,
			VersionKind:   s.VersionKind,
			Stream:        s.Stream,
			IDType:        s.IDType,
			Status:        s.Status,
			Justification: s.Justification,
			// Force UTC: `updated` is a TEXT column compared lexicographically
			// (the `?since=` filter and the incremental watermark), which only
			// equals chronological order when every stored string uses the same
			// zone. A non-zero offset (e.g. +05:00) would sort wrong against `Z`.
			Updated:      s.Updated.UTC().Format(time.RFC3339),
			SourceFormat: a.SourceFormat(),
			Scope:        s.Scope,
			// Ownership is recorded on every write, removal enabled or not.
			AdapterID: a.ID(),
		})
		processed++
		if len(batch) >= batchSize {
			return flush()
		}
		return nil
	}

	// A ChangedDocsAdapter leaves out the documents its last run read
	// unchanged. That is only safe when this run can replace the documents it
	// does read, so without removal it reads every one, as Sync does.
	var res source.SyncResult
	if changedDocs && sessionOpen {
		last, ferr := database.DocumentFingerprints(a.ID())
		if ferr != nil {
			slog.Warn("document fingerprints unreadable; reading every document", "adapter", a.ID(), "error", ferr)
			last = nil
		}
		res, err = cd.SyncChanged(ctx, since, last, emit)
	} else {
		res, err = a.Sync(ctx, since, emit)
	}
	if err != nil && !errors.Is(err, errLimitReached) {
		// The pending batch is not flushed: the run failed.
		if skip == "" {
			skip = "sync error"
			if flushFailed {
				skip = "flush error"
			}
		}
		if sessionOpen {
			endSession()
		}
		logSweep(a.ID(), "cves:0", db.SweepResult{Seen: seen}, skip, false, nil)
		return fmt.Errorf("sync: %w", err)
	}
	if limitHit || err != nil {
		// Options.Limit cut the stream short: whatever the adapter would have
		// reported, this run did not emit its whole set.
		res = source.SyncResult{}
	}
	if err := flush(); err != nil {
		if skip == "" {
			skip = "flush error"
		}
		if sessionOpen {
			endSession()
		}
		logSweep(a.ID(), sweepScopeLabel(res), db.SweepResult{Seen: seen}, skip, false, nil)
		return fmt.Errorf("flush: %w", err)
	}

	// Remove what this run proved the vendor no longer publishes. Neither a
	// FinishSweep nor a Withdraw error fails the adapter: the data was written,
	// the watermark below still moves, and the next sync retries.
	if skip == "" {
		switch {
		case flushFailed:
			skip = "flush error"
		case limitHit:
			skip = "limit"
		}
	}
	scopeLabel := sweepScopeLabel(res)
	// replaced: this run's removal did everything its scope asked, so the
	// fingerprints of what it read may be stored and the next run may leave
	// those documents out. withdrawn: its withdrawal, if any, did too.
	replaced, withdrawn := false, true
	switch {
	case skip != "":
		if sessionOpen {
			endSession()
		}
		logSweep(a.ID(), scopeLabel, db.SweepResult{Seen: seen}, skip, false, nil)
	default:
		var scope db.SweepScope
		switch {
		case res.Complete:
			scope.All = true
		case len(res.RefreshedCVEs) > 0:
			scope.CVEs = res.RefreshedCVEs
		}
		// Removal changes rows too: the stored fingerprints go first.
		var cerr error
		if scope.All || len(scope.CVEs) > 0 || res.LiveCVEs != nil {
			cerr = clearFingerprints()
		}
		switch {
		case cerr != nil:
			endSession()
			logSweep(a.ID(), scopeLabel, db.SweepResult{Seen: seen}, "", false, cerr)
		case scope.All || len(scope.CVEs) > 0:
			sweepRes, err := database.FinishSweep(a.ID(), scope, maxFraction)
			sessionOpen = false
			// Only a whole-feed sweep has a fraction guard to lift.
			logSweep(a.ID(), scopeLabel, sweepRes, "", forced && scope.All, err)
			replaced = err == nil && !sweepRes.Refused
		default:
			endSession()
			logSweep(a.ID(), scopeLabel, db.SweepResult{Seen: seen}, "incomplete", false, nil)
			replaced = true
		}
		if res.LiveCVEs != nil && cerr == nil {
			// A document this run fetched is live even when the manifest, read
			// at another moment, does not list it yet. An empty manifest stays
			// empty, so Withdraw still refuses it.
			live := res.LiveCVEs
			if len(live) > 0 {
				live = append(slices.Clone(live), res.RefreshedCVEs...)
			}
			wres, err := database.Withdraw(a.ID(), live, maxFraction)
			logWithdraw(a.ID(), wres, forced, err)
			withdrawn = err == nil && !wres.Refused
		}
	}

	// A document whose fingerprint is not stored is read again next run.
	if res.Fingerprints != nil && replaced {
		if err := database.SaveDocumentFingerprints(a.ID(), res.Fingerprints); err != nil {
			slog.Warn("save document fingerprints failed", "adapter", a.ID(), "error", err)
		}
	}

	// Record adapter state: feed URL (always) and watermark (only if we saw
	// new data this cycle). UpsertAdapterState preserves the prior watermark
	// when the incoming one is empty, so HEAD-short-circuit cycles don't
	// erase a previously-set last_synced.
	// An adapter-reported watermark (the feed's Last-Modified) stays where it
	// was when this run's removal did not finish, so the next run fetches the
	// same feed and retries — a forced sweep included — rather than finding
	// it up to date.
	if !res.Watermark.IsZero() {
		newest = time.Time{}
		if skip == "disabled" || (replaced && withdrawn) {
			newest = res.Watermark
		}
	}
	// A document the adapter failed to read is read again next run: the
	// watermark stays a second before it (the stored form has no fraction).
	if !res.RetryFrom.IsZero() && !newest.Before(res.RetryFrom) {
		newest = res.RetryFrom.Add(-time.Second)
	}
	var newestStr string
	if !newest.IsZero() {
		newestStr = newest.UTC().Format(time.RFC3339) // UTC: see emit() above
	}
	if err := database.UpsertAdapterState(a.ID(), feed.FeedURL, newestStr); err != nil {
		return fmt.Errorf("update adapter state: %w", err)
	}
	live := "none"
	if res.LiveCVEs != nil {
		live = strconv.Itoa(len(res.LiveCVEs))
	}
	slog.Info("adapter done", "adapter", a.ID(), "processed", processed,
		"complete", res.Complete, "refreshed", len(res.RefreshedCVEs), "live", live)
	return nil
}

// sweepScopeLabel is the scope field of the sweep log line: `all` for a
// complete run, else the number of refreshed CVEs.
func sweepScopeLabel(res source.SyncResult) string {
	if res.Complete {
		return "all"
	}
	return "cves:" + strconv.Itoa(len(res.RefreshedCVEs))
}

// logSweep writes the one `sweep` line an adapter run logs: INFO, WARN on a
// refusal (deleted=0; the would-have-deleted count is in the reason), ERROR
// when FinishSweep failed. forced=true says Options.SweepForce lifted the
// fraction guard.
func logSweep(adapterID, scope string, res db.SweepResult, skipped string, forced bool, err error) {
	attrs := []any{"adapter", adapterID, "scope", scope, "seen", res.Seen, "owned", res.Owned}
	if forced {
		attrs = append(attrs, "forced", true)
	}
	switch {
	case skipped != "":
		slog.Info("sweep", append(attrs, "deleted", res.Deleted, "skipped", skipped)...)
	case err != nil:
		slog.Error("sweep", append(attrs, "deleted", res.Deleted, "error", err)...)
	case res.Refused:
		slog.Warn("sweep", append(attrs, "deleted", 0, "refused", res.Reason)...)
	default:
		slog.Info("sweep", append(attrs, "deleted", res.Deleted)...)
	}
}

// logWithdraw writes the `withdraw` line, with the same levels and forced
// field as logSweep.
func logWithdraw(adapterID string, res db.WithdrawResult, forced bool, err error) {
	attrs := []any{"adapter", adapterID, "live", res.Live, "held_cves", res.HeldCVEs, "withdrawn_cves", res.WithdrawnCVEs}
	if forced {
		attrs = append(attrs, "forced", true)
	}
	switch {
	case err != nil:
		slog.Error("withdraw", append(attrs, "deleted", res.Deleted, "error", err)...)
	case res.Refused:
		slog.Warn("withdraw", append(attrs, "deleted", 0, "refused", res.Reason)...)
	default:
		slog.Info("withdraw", append(attrs, "deleted", res.Deleted)...)
	}
}
