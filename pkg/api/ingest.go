package api

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"
)

// IngestRunner manages scheduled and on-demand ingest runs.
// Only one ingest runs at a time.
type IngestRunner struct {
	mu         sync.Mutex
	ingestFn   func() error
	interval   time.Duration
	adminToken string

	running   bool
	lastRun   time.Time
	lastError string
	nextRun   time.Time
}

// IngestStatus is the JSON response for GET /v1/ingest.
type IngestStatus struct {
	Running   bool   `json:"running"`
	LastRun   string `json:"last_run,omitempty"`
	LastError string `json:"last_error,omitempty"`
	NextRun   string `json:"next_run,omitempty"`
}

// NewIngestRunner creates a new ingest runner.
func NewIngestRunner(ingestFn func() error, interval time.Duration, adminToken string) *IngestRunner {
	return &IngestRunner{
		ingestFn:   ingestFn,
		interval:   interval,
		adminToken: adminToken,
	}
}

// TriggerIngest starts an ingest run in a goroutine.
// Returns false if an ingest is already running.
func (r *IngestRunner) TriggerIngest() bool {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return false
	}
	r.running = true
	r.mu.Unlock()

	go r.runIngest()
	return true
}

// Status returns the current ingest status.
func (r *IngestRunner) Status() IngestStatus {
	r.mu.Lock()
	defer r.mu.Unlock()

	s := IngestStatus{
		Running: r.running,
	}
	if !r.lastRun.IsZero() {
		s.LastRun = r.lastRun.Format(time.RFC3339)
	}
	s.LastError = r.lastError
	if !r.nextRun.IsZero() {
		s.NextRun = r.nextRun.Format(time.RFC3339)
	}
	return s
}

// shouldIngestOnBoot reports whether to run an ingest immediately at startup:
// when nothing has ever been ingested, or the last cycle is at least one
// interval old. Data that's still within the interval is left alone, so a
// restart/redeploy doesn't re-trigger a costly full ingest (and the DB
// contention + cold stats that come with it).
func shouldIngestOnBoot(lastIngest time.Time, interval time.Duration, now time.Time) bool {
	return lastIngest.IsZero() || now.Sub(lastIngest) >= interval
}

// StartScheduler runs ingest on the configured interval, blocking until ctx is
// cancelled. On boot it ingests immediately only if data is stale (see
// shouldIngestOnBoot); otherwise it skips the boot run and aligns the next run
// to lastIngest+interval, so the cadence survives restarts. A manual
// POST /v1/ingest can always force a run regardless.
func (r *IngestRunner) StartScheduler(ctx context.Context, lastIngest time.Time) {
	slog.Info("ingest scheduler started", "interval", r.interval)

	delay := r.interval
	if shouldIngestOnBoot(lastIngest, r.interval, time.Now()) {
		r.TriggerIngest()
	} else {
		delay = r.interval - time.Since(lastIngest)
		slog.Info("boot ingest skipped; data within schedule window",
			"last_ingest", lastIngest.Format(time.RFC3339), "next_run_in", delay.Round(time.Second))
	}

	r.mu.Lock()
	r.nextRun = time.Now().Add(delay)
	r.mu.Unlock()

	timer := time.NewTimer(delay)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("ingest scheduler stopped")
			return
		case <-timer.C:
			r.TriggerIngest()
			timer.Reset(r.interval)
			r.mu.Lock()
			r.nextRun = time.Now().Add(r.interval)
			r.mu.Unlock()
		}
	}
}

func (r *IngestRunner) runIngest() {
	slog.Info("ingest started")
	start := time.Now()

	// runIngest runs in its own goroutine, so a panic in any feed parser (e.g. a
	// nil-deref / index-out-of-range on malformed third-party feed data) would
	// otherwise crash the whole server process and — short of that — leave
	// `running` stuck true forever (every later trigger 409s, the scheduler
	// no-ops). Recover it into an error so the status reset below always runs and
	// the next cycle can proceed.
	err := func() (err error) {
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("ingest panicked: %v", p)
				slog.Error("ingest panicked", "panic", p, "stack", string(debug.Stack()))
			}
		}()
		return r.ingestFn()
	}()

	r.mu.Lock()
	r.running = false
	r.lastRun = time.Now()
	if err != nil {
		r.lastError = err.Error()
		slog.Error("ingest failed", "error", err, "duration", time.Since(start))
	} else {
		r.lastError = ""
		slog.Info("ingest completed", "duration", time.Since(start))
	}
	r.mu.Unlock()
}
