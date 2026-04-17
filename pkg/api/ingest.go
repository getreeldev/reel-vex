package api

import (
	"context"
	"log/slog"
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

// StartScheduler runs ingest immediately, then on the configured interval.
// Blocks until ctx is cancelled.
func (r *IngestRunner) StartScheduler(ctx context.Context) {
	slog.Info("ingest scheduler started", "interval", r.interval)

	// Run immediately on boot.
	r.TriggerIngest()

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	r.mu.Lock()
	r.nextRun = time.Now().Add(r.interval)
	r.mu.Unlock()

	for {
		select {
		case <-ctx.Done():
			slog.Info("ingest scheduler stopped")
			return
		case <-ticker.C:
			r.TriggerIngest()
			r.mu.Lock()
			r.nextRun = time.Now().Add(r.interval)
			r.mu.Unlock()
		}
	}
}

func (r *IngestRunner) runIngest() {
	slog.Info("ingest started")
	start := time.Now()

	err := r.ingestFn()

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
