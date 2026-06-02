package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandleAnalyze_RejectsTooManyCVEs: an upload that expands past
// maxAnalyzeCVEs distinct CVEs is refused up front with a clear 400, never run
// as a vendor query that could pin the DB. This is the v0.8.1 fix for the
// large-document analyze that pinned prod for ~175s.
func TestHandleAnalyze_RejectsTooManyCVEs(t *testing.T) {
	database := setupTestDB(t)
	srv := NewServer(database, nil)

	var b strings.Builder
	b.WriteString(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[`)
	for i := 0; i <= maxAnalyzeCVEs; i++ { // maxAnalyzeCVEs+1 distinct CVEs
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"vulnerability":{"name":"CVE-2024-%d"},"products":[{"@id":"pkg:rpm/x"}],"status":"fixed"}`, i)
	}
	b.WriteString(`]}`)

	body, _ := json.Marshal(analyzeRequest{UserVEX: []json.RawMessage{json.RawMessage(b.String())}})
	req := httptest.NewRequest("POST", "/v1/analyze", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for too-many-CVEs, got %d (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "too many CVEs") {
		t.Errorf("expected a clear 'too many CVEs' message, got: %s", w.Body.String())
	}
}

// A small analyze (well under the cap) still succeeds — the guard doesn't
// break the normal path.
func TestHandleAnalyze_UnderCapSucceeds(t *testing.T) {
	database := setupTestDB(t)
	srv := NewServer(database, nil)

	doc := `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"vulnerability":{"name":"CVE-2024-1234"},"products":[{"@id":"pkg:rpm/x"}],"status":"fixed"}]}`
	body, _ := json.Marshal(analyzeRequest{UserVEX: []json.RawMessage{json.RawMessage(doc)}})
	req := httptest.NewRequest("POST", "/v1/analyze", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for a small analyze, got %d (body: %s)", w.Code, w.Body.String())
	}
}
