package ranchervex

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getreeldev/reel-vex/pkg/openvex"
	"github.com/getreeldev/reel-vex/pkg/source"
)

const feedPath = "/reports/rancher.openvex.json"

func mustJSON(t *testing.T, doc openvex.Document) []byte {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}

// serveDoc stands up an httptest server returning the consolidated document at
// feedPath with the given Last-Modified. The returned counter tracks GETs so a
// test can assert a HEAD short-circuit issued no GET.
func serveDoc(t *testing.T, payload []byte, lastModified time.Time) (*httptest.Server, *int) {
	t.Helper()
	getCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc(feedPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", lastModified.UTC().Format(http.TimeFormat))
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		getCalls++
		w.Header().Set("Content-Type", "application/json")
		w.Write(payload)
	})
	return httptest.NewServer(mux), &getCalls
}

// scopedProduct builds a product Component with subcomponents.
func scopedProduct(id string, subs ...string) openvex.Component {
	c := openvex.Component{ID: id}
	for _, s := range subs {
		c.Subcomponents = append(c.Subcomponents, openvex.Component{ID: s})
	}
	return c
}

func stmt(cve, status, justification string, products ...openvex.Component) openvex.Statement {
	return openvex.Statement{
		Vulnerability: openvex.Vulnerability{Name: cve},
		Products:      products,
		Status:        status,
		Justification: justification,
	}
}

func TestNew(t *testing.T) {
	t.Run("requires id", func(t *testing.T) {
		if _, err := New(source.AdapterConfig{Type: Type, URL: "https://x/rancher.openvex.json"}); err == nil {
			t.Fatal("expected error for empty id")
		}
	})
	t.Run("requires url", func(t *testing.T) {
		if _, err := New(source.AdapterConfig{Type: Type, ID: "rancher-vex"}); err == nil {
			t.Fatal("expected error for empty url")
		}
	})
	t.Run("default name", func(t *testing.T) {
		a, err := New(source.AdapterConfig{Type: Type, ID: "rancher-vex", URL: "https://x/rancher.openvex.json"})
		if err != nil {
			t.Fatal(err)
		}
		if a.Name() != "SUSE Rancher (OpenVEX)" {
			t.Errorf("default Name(): got %q", a.Name())
		}
	})
}

func TestAdapter_Identity(t *testing.T) {
	a, err := New(source.AdapterConfig{Type: Type, ID: "rancher-vex", URL: "https://x/rancher.openvex.json"})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID() != "rancher-vex" {
		t.Errorf("ID: got %q, want rancher-vex", a.ID())
	}
	if a.Vendor() != "rancher" {
		t.Errorf("Vendor: got %q, want rancher", a.Vendor())
	}
	if a.SourceFormat() != "openvex" {
		// db.BulkInsert defaults an empty SourceFormat to "csaf" — forgetting
		// this would silently misclassify every row.
		t.Errorf("SourceFormat: got %q, want openvex", a.SourceFormat())
	}
	if Type != "rancher-vex" {
		t.Errorf("Type constant: got %q, want rancher-vex", Type)
	}
}

func TestAdapter_Sync(t *testing.T) {
	const ociID = "pkg:oci/longhorn-engine?repository_url=registry.suse.com/rancher/longhorn-engine"
	doc := openvex.Document{
		Context:   openvex.Context,
		Author:    "SUSE Rancher Security",
		Timestamp: "2026-05-01T00:00:00Z",
		Version:   1,
		Statements: []openvex.Statement{
			// emitted: CVE-named, OCI product, one Go-module subcomponent.
			stmt("CVE-2024-1", "not_affected", "vulnerable_code_not_present",
				scopedProduct(ociID, "pkg:golang/golang.org/x/net@v0.17.0")),
			// skipped: non-CVE (SUSE advisory) — no CVE alias, deferred.
			stmt("SUSE-SU-2026:1432-1", "not_affected", "vulnerable_code_not_in_execute_path",
				scopedProduct(ociID, "pkg:rpm/suse/libcap2")),
			// skipped: product with no subcomponent (would be a global claim).
			stmt("CVE-2024-2", "not_affected", "", openvex.Component{ID: ociID}),
			// emitted: golang-module product, stdlib subcomponent.
			stmt("CVE-2024-3", "not_affected", "vulnerable_code_not_present",
				scopedProduct("pkg:golang/github.com/harvester/harvester", "pkg:golang/stdlib@v1.24.6")),
			// skipped: subcomponent present but the product carries no
			// identifier — we refuse to emit an unscoped (global) row.
			stmt("CVE-2024-4", "not_affected", "vulnerable_code_not_present",
				scopedProduct("", "pkg:golang/x@v1.0.0")),
		},
	}

	server, _ := serveDoc(t, mustJSON(t, doc), time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	defer server.Close()

	a, err := New(source.AdapterConfig{Type: Type, ID: "rancher-vex", URL: server.URL + feedPath})
	if err != nil {
		t.Fatal(err)
	}

	feed, err := a.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if feed.FeedURL == "" {
		t.Error("expected FeedURL set")
	}

	var stmts []source.Statement
	if err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error {
		stmts = append(stmts, s)
		return nil
	}); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// Only the two CVE-named, subcomponent-bearing statements emit.
	if len(stmts) != 2 {
		t.Fatalf("emitted %d rows, want 2: %+v", len(stmts), stmts)
	}

	// Find the CVE-2024-1 row and verify the subcomponent→product_id /
	// product→scope mapping.
	var got *source.Statement
	for i := range stmts {
		if stmts[i].CVE == "CVE-2024-1" {
			got = &stmts[i]
		}
	}
	if got == nil {
		t.Fatal("CVE-2024-1 row not emitted")
	}
	if got.ProductID != "pkg:golang/golang.org/x/net@v0.17.0" {
		t.Errorf("ProductID (subcomponent): got %q", got.ProductID)
	}
	if got.BaseID != "pkg:golang/golang.org/x/net" {
		t.Errorf("BaseID: got %q", got.BaseID)
	}
	if got.Version != "v0.17.0" {
		t.Errorf("Version: got %q", got.Version)
	}
	if got.Scope != ociID {
		t.Errorf("Scope (product @id): got %q, want %q", got.Scope, ociID)
	}
	if got.Status != "not_affected" || got.Justification != "vulnerable_code_not_present" {
		t.Errorf("status/justification: got %q / %q", got.Status, got.Justification)
	}
	if got.IDType != "purl" {
		t.Errorf("IDType: got %q, want purl", got.IDType)
	}
	if got.Updated.IsZero() {
		t.Error("Updated should fall back to Last-Modified, got zero")
	}

	// The skipped statements must not appear.
	for _, s := range stmts {
		if s.CVE == "SUSE-SU-2026:1432-1" {
			t.Error("non-CVE statement should have been skipped")
		}
		if s.CVE == "CVE-2024-2" {
			t.Error("subcomponent-less statement should have been skipped")
		}
		if s.CVE == "CVE-2024-4" {
			t.Error("statement with an unidentified product should have been skipped")
		}
	}
}

func TestAdapter_HEADShortCircuit(t *testing.T) {
	lastModified := time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC)
	since := time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)

	doc := openvex.Document{Context: openvex.Context, Version: 1}
	server, getCalls := serveDoc(t, mustJSON(t, doc), lastModified)
	defer server.Close()

	a, _ := New(source.AdapterConfig{Type: Type, ID: "rancher-vex", URL: server.URL + feedPath})
	var emitted int
	if err := a.Sync(context.Background(), since, func(s source.Statement) error {
		emitted++
		return nil
	}); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if emitted != 0 {
		t.Errorf("expected no emit on short-circuit, got %d", emitted)
	}
	if *getCalls != 0 {
		t.Errorf("expected no GET on short-circuit, got %d", *getCalls)
	}
}

// A malformed statement aborts the whole sync — the consolidated document is
// vendor-generated and a streaming decoder can't resync mid-array, so we fail
// loudly rather than silently emit a partial feed.
func TestAdapter_AbortsOnMalformedJSON(t *testing.T) {
	server, _ := serveDoc(t, []byte(`{"@context":"x","statements":[ {not valid} ]}`), time.Now().UTC())
	defer server.Close()

	a, _ := New(source.AdapterConfig{Type: Type, ID: "rancher-vex", URL: server.URL + feedPath})
	err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error { return nil })
	if err == nil {
		t.Fatal("expected Sync to error on malformed statement JSON")
	}
}

// A non-200 GET surfaces as a sync error.
func TestAdapter_GETError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc(feedPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	a, _ := New(source.AdapterConfig{Type: Type, ID: "rancher-vex", URL: server.URL + feedPath})
	err := a.Sync(context.Background(), time.Time{}, func(s source.Statement) error { return nil })
	if err == nil {
		t.Fatal("expected Sync to error on HTTP 500 GET")
	}
}
