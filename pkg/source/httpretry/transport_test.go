package httpretry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// fastTransport is New() with a negligible backoff so tests don't sleep.
func fastTransport() *Transport {
	t := New(nil)
	t.BaseDelay = time.Millisecond
	return t
}

func TestRetry_5xxThenSuccess(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable) // 503 twice
			return
		}
		w.WriteHeader(http.StatusOK) // succeed on the 3rd
	}))
	defer srv.Close()

	client := &http.Client{Transport: fastTransport()}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200 after retries, got %d", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("want 3 server hits, got %d", got)
	}
}

func TestRetry_ExhaustsAndReturnsLastResponse(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusBadGateway) // always 502
	}))
	defer srv.Close()

	client := &http.Client{Transport: fastTransport()}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("want the final 502 surfaced, got %d", resp.StatusCode)
	}
	// 1 initial + MaxRetries(3) = 4 attempts.
	if got := atomic.LoadInt32(&hits); got != 4 {
		t.Fatalf("want 4 attempts (1 + 3 retries), got %d", got)
	}
}

func TestRetry_NonRetryableStatusNotRetried(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusNotFound) // 404 is a real answer, not transient
	}))
	defer srv.Close()

	client := &http.Client{Transport: fastTransport()}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("404 must not be retried; want 1 hit, got %d", got)
	}
}

func TestRetry_NonIdempotentNotRetried(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := &http.Client{Transport: fastTransport()}
	resp, err := client.Post(srv.URL, "text/plain", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("POST must not be replayed; want 1 hit, got %d", got)
	}
}

func TestRetry_ContextCancelStops(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	// Backoff long enough that the cancel lands during the wait.
	tr := New(nil)
	tr.BaseDelay = 5 * time.Second
	client := &http.Client{Transport: tr}

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	start := time.Now()
	_, err := client.Do(req)
	if err == nil {
		t.Fatal("want a context error, got nil")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("cancel should stop retries promptly, took %v", elapsed)
	}
	// First attempt 503'd, then cancel hit during backoff before a second.
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("want 1 hit before cancel, got %d", got)
	}
}
