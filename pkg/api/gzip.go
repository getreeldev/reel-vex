package api

import (
	"compress/gzip"
	"net/http"
	"strings"
)

// gzipResponse compresses response bodies for clients that advertise
// `Accept-Encoding: gzip`. OpenVEX documents are highly repetitive, so broad
// mode's potentially-large responses compress ~10×, which keeps body size from
// being the binding constraint on the fetch-once-attach-to-every-scan flow.
//
// Compression is initialised lazily on the first body Write and skipped for
// bodyless statuses (204/304), so a no-match /v1/statements still returns a
// clean 204 with no Content-Encoding and no gzip stream.
func gzipResponse(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		gw := &gzipWriter{ResponseWriter: w}
		defer gw.Close()
		next.ServeHTTP(gw, r)
	})
}

// gzipWriter wraps an http.ResponseWriter, compressing body writes through a
// gzip.Writer. The gzip.Writer is created on first Write so headers (status,
// Content-Encoding) can still be decided up front.
type gzipWriter struct {
	http.ResponseWriter
	gz     *gzip.Writer
	status int
}

func (g *gzipWriter) bodyless() bool {
	return g.status == http.StatusNoContent || g.status == http.StatusNotModified
}

func (g *gzipWriter) WriteHeader(status int) {
	g.status = status
	if !g.bodyless() {
		g.Header().Set("Content-Encoding", "gzip")
		g.Header().Add("Vary", "Accept-Encoding")
		// Length no longer matches once compressed; let the transport chunk.
		g.Header().Del("Content-Length")
	}
	g.ResponseWriter.WriteHeader(status)
}

func (g *gzipWriter) Write(b []byte) (int, error) {
	if g.status == 0 {
		g.WriteHeader(http.StatusOK)
	}
	if g.bodyless() {
		return g.ResponseWriter.Write(b)
	}
	if g.gz == nil {
		g.gz = gzip.NewWriter(g.ResponseWriter)
	}
	return g.gz.Write(b)
}

// Close flushes and finalises the gzip stream, if one was started.
func (g *gzipWriter) Close() error {
	if g.gz != nil {
		return g.gz.Close()
	}
	return nil
}
