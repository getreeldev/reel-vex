// Package httpretry provides an http.RoundTripper that retries idempotent
// requests on transient failures — network errors and retryable 5xx / 429
// responses — with exponential backoff.
//
// Every source adapter fetches a vendor feed over HTTP, and a single transient
// blip (e.g. a CDN 503 on Canonical's tarball) otherwise fails the adapter for
// the whole ingest cycle. On a cold-start fresh box (the rebuild-and-swap
// deploy model) that leaves the feed's data entirely missing until the next
// cycle — so the resilience lives here, shared by every adapter, rather than
// in any one of them.
package httpretry

import (
	"io"
	"net/http"
	"time"
)

// Defaults applied by New.
const (
	defaultMaxRetries = 3
	defaultBaseDelay  = 500 * time.Millisecond
	maxDelay          = 8 * time.Second
)

// Transport retries idempotent requests through Base on transient failures.
// Only methods safe to replay (GET, HEAD) are retried; anything else passes
// through untouched. Backoff respects the request context, so a client Timeout
// or cancellation stops the retries promptly.
type Transport struct {
	Base       http.RoundTripper
	MaxRetries int
	BaseDelay  time.Duration
}

// New wraps base (nil = http.DefaultTransport) with the default retry policy.
func New(base http.RoundTripper) *Transport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &Transport{Base: base, MaxRetries: defaultMaxRetries, BaseDelay: defaultBaseDelay}
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !idempotent(req.Method) {
		return t.Base.RoundTrip(req)
	}

	delay := t.BaseDelay
	if delay <= 0 {
		delay = defaultBaseDelay
	}

	for attempt := 0; ; attempt++ {
		resp, err := t.Base.RoundTrip(req)

		// Success, a non-retryable outcome, or out of attempts: return as-is.
		if !retryable(resp, err) || attempt >= t.MaxRetries {
			return resp, err
		}

		// Drain + close the discarded response so the connection can be reused.
		if resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}

		// Back off, but abort immediately if the request context is done
		// (covers both an explicit cancel and the client's overall Timeout).
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(delay):
		}
		if delay *= 2; delay > maxDelay {
			delay = maxDelay
		}
	}
}

// idempotent reports whether a method is safe to replay. Adapters only GET and
// HEAD; bodied/mutating methods are never retried (no body replay, not safe).
func idempotent(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead:
		return true
	default:
		return false
	}
}

// retryable reports whether a round trip's outcome is worth retrying: a
// transport-level error (connection reset, timeout, EOF — context cancellation
// is caught by the caller's select before another attempt), or a transient
// server status.
func retryable(resp *http.Response, err error) bool {
	if err != nil {
		return true
	}
	switch resp.StatusCode {
	case http.StatusTooManyRequests, // 429
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout:      // 504
		return true
	}
	return false
}
