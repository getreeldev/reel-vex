package api

import (
	"log/slog"
	"net/http"
	"time"
)

// recordingWriter wraps http.ResponseWriter to capture the status code and
// byte count for structured request logging. Middleware wrappers that want
// to observe the response after the handler runs need this because Go's
// stdlib ResponseWriter doesn't expose either value directly.
type recordingWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *recordingWriter) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *recordingWriter) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

// logRequest emits a single structured "api_request" slog line per HTTP
// request once the handler has returned. Fields: method, path, status,
// latency_ms, bytes.
//
// Operators running reel-vex can consume these lines with any slog-aware
// log shipper (Vector, Promtail, Fluent Bit, plain jq) and forward them to
// whatever observability backend they run. No vendor coupling in this
// binary.
//
// Per-CVE attribution was attempted in v0.2.x via path-pattern extraction
// when CVE was in the URL (`/v1/cve/{id}`); v0.4.0 collapsed that route
// into POST /v1/statements, so the CVE moved into the request body. Body
// peeking from middleware is heavy (body-buffer + reset); we drop the
// per-request CVE attribute rather than carry that complexity.
func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &recordingWriter{ResponseWriter: w}
		next.ServeHTTP(rw, r)
		if rw.status == 0 {
			rw.status = http.StatusOK
		}
		slog.Info("api_request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"latency_ms", time.Since(start).Milliseconds(),
			"bytes", rw.bytes,
		)
	})
}
