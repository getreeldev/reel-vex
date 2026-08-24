package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/getreeldev/reel-vex/pkg/db"
	"github.com/getreeldev/reel-vex/pkg/db/dbtest"
)

// setupArchDB seeds one vendor assertion fanned out the way Canonical
// publishes it: the same CVE + package across several architectures, plus the
// source package and an architecture-independent sibling.
func setupArchDB(t *testing.T) db.Store {
	t.Helper()
	database := dbtest.New()
	t.Cleanup(func() { database.Close() })

	row := func(productID string) db.Statement {
		return db.Statement{
			Vendor: "ubuntu", CVE: "CVE-2019-9923",
			ProductID: productID, BaseID: "pkg:deb/ubuntu/tar?distro=ubuntu-22.04",
			Version: "1.34-1", IDType: "purl",
			Status: "not_affected", Justification: "vulnerable_code_not_present",
			Updated: "2019-03-22T08:29:00Z", SourceFormat: "openvex",
		}
	}
	stmts := []db.Statement{
		row("pkg:deb/ubuntu/tar@1.34-1?arch=amd64&distro=ubuntu-22.04"),
		row("pkg:deb/ubuntu/tar@1.34-1?arch=arm64&distro=ubuntu-22.04"),
		row("pkg:deb/ubuntu/tar@1.34-1?arch=s390x&distro=ubuntu-22.04"),
		row("pkg:deb/ubuntu/tar@1.34-1?arch=source&distro=ubuntu-22.04"),
		row("pkg:deb/ubuntu/tar@1.34-1?arch=all&distro=ubuntu-22.04"),
		row("pkg:deb/ubuntu/tar@1.34-1?distro=ubuntu-22.04"),
	}
	if err := database.BulkInsert(stmts); err != nil {
		t.Fatal(err)
	}
	return database
}

// postStatements returns the response recorder for a /v1/statements request.
func postStatements(t *testing.T, srv *Server, req statementsRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(req)
	r := httptest.NewRequest("POST", "/v1/statements", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	return w
}

func TestHandleStatements_StrictArch(t *testing.T) {
	srv := NewServer(setupArchDB(t), nil)
	const amd64 = "pkg:deb/ubuntu/tar@1.34-1?arch=amd64&distro=ubuntu-22.04"

	t.Run("off by default: every architecture matches", func(t *testing.T) {
		w := postStatements(t, srv, statementsRequest{
			CVEs: []string{"CVE-2019-9923"}, Products: []string{amd64},
		})
		if got := w.Header().Get("X-Reel-Statements"); got != "6" {
			t.Errorf("X-Reel-Statements: got %q, want 6 rows", got)
		}
		if got := w.Header().Get("X-Reel-Arch"); got != "" {
			t.Errorf("X-Reel-Arch should be absent when not narrowing, got %q", got)
		}
		// All six rows are one assertion echoed under one base identifier, so
		// they group into a single statement — which is precisely why the
		// architecture mismatch is invisible without strict_arch.
		if got := w.Header().Get("X-Reel-Grouped"); got != "1" {
			t.Errorf("X-Reel-Grouped: got %q, want 1", got)
		}
	})

	t.Run("on: keeps own arch plus the architecture-independent rows", func(t *testing.T) {
		w := postStatements(t, srv, statementsRequest{
			CVEs: []string{"CVE-2019-9923"}, Products: []string{amd64}, StrictArch: true,
		})
		// amd64 + source + all + the unqualified row; arm64 and s390x dropped.
		if got := w.Header().Get("X-Reel-Statements"); got != "4" {
			t.Errorf("X-Reel-Statements: got %q, want 4 rows", got)
		}
		if got := w.Header().Get("X-Reel-Arch"); got != "amd64" {
			t.Errorf("X-Reel-Arch: got %q, want amd64", got)
		}
	})

	t.Run("no-op when the caller names no architecture", func(t *testing.T) {
		w := postStatements(t, srv, statementsRequest{
			CVEs:       []string{"CVE-2019-9923"},
			Products:   []string{"pkg:deb/ubuntu/tar?distro=ubuntu-22.04"},
			StrictArch: true,
		})
		if got := w.Header().Get("X-Reel-Statements"); got != "6" {
			t.Errorf("X-Reel-Statements: got %q, want 6 rows (nothing to be strict about)", got)
		}
		if got := w.Header().Get("X-Reel-Arch"); got != "" {
			t.Errorf("X-Reel-Arch should be absent, got %q", got)
		}
	})

	t.Run("mixed architectures widen rather than narrow", func(t *testing.T) {
		w := postStatements(t, srv, statementsRequest{
			CVEs: []string{"CVE-2019-9923"},
			Products: []string{
				amd64,
				"pkg:deb/ubuntu/tar@1.34-1?arch=arm64&distro=ubuntu-22.04",
			},
			StrictArch: true,
		})
		if got := w.Header().Get("X-Reel-Statements"); got != "5" {
			t.Errorf("X-Reel-Statements: got %q, want 5 rows (both arches + the independents)", got)
		}
		if got := w.Header().Get("X-Reel-Arch"); got != "amd64,arm64" {
			t.Errorf("X-Reel-Arch: got %q, want amd64,arm64", got)
		}
	})
}

func TestRequestArches(t *testing.T) {
	tests := []struct {
		name     string
		products []string
		want     []string
	}{
		{"none", []string{"pkg:deb/ubuntu/tar?distro=ubuntu-22.04"}, nil},
		{"single", []string{"pkg:deb/ubuntu/tar@1?arch=amd64"}, []string{"amd64"}},
		{"deduped and sorted", []string{
			"pkg:deb/ubuntu/b@1?arch=s390x",
			"pkg:deb/ubuntu/a@1?arch=amd64",
			"pkg:deb/ubuntu/c@1?arch=amd64",
		}, []string{"amd64", "s390x"}},
		{"independent values are not concrete", []string{
			"pkg:deb/ubuntu/a@1?arch=all",
			"pkg:deb/ubuntu/b@1?arch=source",
			"pkg:rpm/redhat/c@1?arch=noarch",
			"pkg:rpm/redhat/d@1?arch=src",
		}, nil},
		{"independents alongside a real arch", []string{
			"pkg:deb/ubuntu/a@1?arch=all",
			"pkg:deb/ubuntu/b@1?arch=arm64",
		}, []string{"arm64"}},
		{"cpes contribute nothing", []string{"cpe:/a:redhat:openssl:3.0"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := requestArches(tt.products); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("requestArches(%v) = %v, want %v", tt.products, got, tt.want)
			}
		})
	}
}

func TestArchAllowList(t *testing.T) {
	if got := archAllowList(nil); got != nil {
		t.Errorf("empty input should produce no filter, got %v", got)
	}
	got := archAllowList([]string{"amd64"})
	want := []string{"amd64", "noarch", "src", "source", "all"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("archAllowList([amd64]) = %v, want %v", got, want)
	}
}

// TestFilterByArch_QualifierBoundary is the case the backends' LIKE predicate
// cannot decide and this pass exists for: "%arch=amd64%" also matches
// arch=amd64_v2, which is a different architecture.
func TestFilterByArch_QualifierBoundary(t *testing.T) {
	stmts := []db.Statement{
		{ProductID: "pkg:deb/x/y@1?arch=amd64"},
		{ProductID: "pkg:deb/x/y@1?arch=amd64_v2"},
		{ProductID: "pkg:deb/x/y@1?arch=all"},
		{ProductID: "pkg:deb/x/y@1"},
	}
	got := filterByArch(stmts, []string{"amd64"})
	if len(got) != 3 {
		t.Fatalf("expected 3 kept, got %d: %v", len(got), got)
	}
	for _, s := range got {
		if s.ProductID == "pkg:deb/x/y@1?arch=amd64_v2" {
			t.Error("amd64_v2 is not amd64 and must not survive the exact pass")
		}
	}
}

func TestFilterByArch_NoFilterWhenEmpty(t *testing.T) {
	stmts := []db.Statement{{ProductID: "pkg:deb/x/y@1?arch=arm64"}}
	if got := filterByArch(stmts, nil); len(got) != 1 {
		t.Errorf("empty arch set must not filter, got %d statements", len(got))
	}
}
