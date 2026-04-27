package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getreeldev/reel-vex/pkg/openvex"
)

// TestHandleStatements_OpenVEXSchema validates that /v1/statements produces a
// structurally valid OpenVEX 0.2.0 document with the user's input PURL
// echoed into products[]. OpenVEX became the only response format in v0.3.0;
// /v1/statements (the unified query endpoint) absorbed it in v0.4.0.
func TestHandleStatements_OpenVEXSchema(t *testing.T) {
	database := setupTestDB(t)
	srv := NewServer(database, nil)

	body, _ := json.Marshal(statementsRequest{
		CVEs:     []string{"CVE-2024-1234"},
		Products: []string{"pkg:rpm/test/openssl@3.0"},
	})
	req := httptest.NewRequest("POST", "/v1/statements", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}

	var doc openvex.Document
	if err := json.NewDecoder(w.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := openvex.Validate(doc); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(doc.Statements) == 0 {
		t.Fatal("no statements in response")
	}
	s := doc.Statements[0]
	if s.Vulnerability.Name != "CVE-2024-1234" {
		t.Errorf("vulnerability.name = %q", s.Vulnerability.Name)
	}
	if len(s.Products) != 1 || s.Products[0].Identifiers == nil || s.Products[0].Identifiers.PURL != "pkg:rpm/test/openssl" {
		t.Errorf("expected echoed PURL base in products[0].identifiers.purl; got %+v", s.Products[0])
	}
}
