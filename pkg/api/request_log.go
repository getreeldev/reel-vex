package api

import (
	"log/slog"
	"net/http"
	"strings"
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
// latency_ms, bytes, and — for /v1/cve/{id}[/summary] routes — the CVE ID.
//
// Operators running reel-vex can consume these lines with any slog-aware
// log shipper (Vector, Promtail, Fluent Bit, plain jq) and forward them to
// whatever observability backend they run. No vendor coupling in this
// binary.
func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &recordingWriter{ResponseWriter: w}
		next.ServeHTTP(rw, r)
		if rw.status == 0 {
			rw.status = http.StatusOK
		}
		attrs := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"latency_ms", time.Since(start).Milliseconds(),
			"bytes", rw.bytes,
		}
		if cve := extractCVE(r.URL.Path); cve != "" {
			attrs = append(attrs, "cve", cve)
		}
		slog.Info("api_request", attrs...)
	})
}

// extractCVE pulls the CVE identifier from a /v1/cve/{id} or
// /v1/cve/{id}/summary URL path. Returns "" for any other path. Kept
// deliberately simple — anything more structured belongs in a router-level
// observation point, not a path parser.
func extractCVE(path string) string {
	const prefix = "/v1/cve/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	rest := path[len(prefix):]
	if i := strings.Index(rest, "/"); i >= 0 {
		return rest[:i]
	}
	return rest
}
