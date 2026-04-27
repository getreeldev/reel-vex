package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestLogRequest_EmitsStructuredEvent captures slog output during a
// request and confirms the api_request line carries the expected fields.
// Exercises the full handler chain including the status-capturing writer.
func TestLogRequest_EmitsStructuredEvent(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	handler := logRequest(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest("POST", "/v1/statements", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Find the api_request line in the emitted slog output.
	var found bool
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev["msg"] != "api_request" {
			continue
		}
		found = true

		if ev["method"] != "POST" {
			t.Errorf("method: got %v, want POST", ev["method"])
		}
		if ev["path"] != "/v1/statements" {
			t.Errorf("path: got %v", ev["path"])
		}
		if ev["status"].(float64) != 202 {
			t.Errorf("status: got %v, want 202", ev["status"])
		}
		if _, ok := ev["latency_ms"]; !ok {
			t.Errorf("latency_ms missing")
		}
		if ev["bytes"].(float64) != 2 {
			t.Errorf("bytes: got %v, want 2", ev["bytes"])
		}
	}
	if !found {
		t.Fatalf("no api_request event emitted; buffer=%q", buf.String())
	}
}
