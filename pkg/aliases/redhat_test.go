package aliases

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/getreeldev/reel-vex/pkg/db"
)

func fixturePath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", name)
}

func openTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestRedHatRepoToCPE_New(t *testing.T) {
	t.Run("requires id", func(t *testing.T) {
		_, err := NewRedHatRepoToCPE(Config{Type: RedHatRepoToCPEType})
		if err == nil {
			t.Fatal("expected error for empty id")
		}
	})
	t.Run("url defaults when empty", func(t *testing.T) {
		f, err := NewRedHatRepoToCPE(Config{Type: RedHatRepoToCPEType, ID: "redhat"})
		if err != nil {
			t.Fatal(err)
		}
		got := f.(*redHatRepoToCPE).url
		if got != RedHatRepoToCPEDefaultURL {
			t.Errorf("default url: got %q, want %q", got, RedHatRepoToCPEDefaultURL)
		}
	})
}

func TestRedHatRepoToCPE_FetchAgainstHTTPTest(t *testing.T) {
	fixture, err := os.ReadFile(fixturePath(t, "redhat-repository-to-cpe-sample.json"))
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(fixture)
	}))
	defer server.Close()

	f, err := NewRedHatRepoToCPE(Config{Type: RedHatRepoToCPEType, ID: "redhat", URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}

	database := openTestDB(t)
	if err := f.Fetch(context.Background(), database); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	// Sanity-check the SECDATA-1220 entry landed.
	targets, err := database.LookupAliases("repository_id", "rhel-8-for-x86_64-baseos-rpms", "cpe")
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0] != "cpe:/o:redhat:enterprise_linux:8::baseos" {
		t.Fatalf("baseos mapping: got %v, want [cpe:/o:redhat:enterprise_linux:8::baseos]", targets)
	}

	// Multi-CPE entry.
	multi, err := database.LookupAliases("repository_id", "3scale-amp-2-for-rhel-8-ppc64le-debug-rpms", "cpe")
	if err != nil {
		t.Fatal(err)
	}
	if len(multi) < 2 {
		t.Fatalf("multi-CPE repo: got %d aliases, want >= 2", len(multi))
	}

	// AliasCount reflects all rows.
	n, _ := database.AliasCount()
	if n < 5 {
		t.Errorf("alias count: got %d, want >= 5 (5 fixture repos, at least 1 CPE each)", n)
	}
}

func TestRedHatRepoToCPE_Reentrant(t *testing.T) {
	// Fetching twice produces the same row count — upserts, not duplicates.
	fixture, _ := os.ReadFile(fixturePath(t, "redhat-repository-to-cpe-sample.json"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixture)
	}))
	defer server.Close()

	f, _ := NewRedHatRepoToCPE(Config{Type: RedHatRepoToCPEType, ID: "redhat", URL: server.URL})
	database := openTestDB(t)

	ctx := context.Background()
	if err := f.Fetch(ctx, database); err != nil {
		t.Fatal(err)
	}
	first, _ := database.AliasCount()
	if err := f.Fetch(ctx, database); err != nil {
		t.Fatal(err)
	}
	second, _ := database.AliasCount()
	if first != second {
		t.Errorf("re-fetch changed row count: %d → %d (should be upsert)", first, second)
	}
}

func TestRegistry(t *testing.T) {
	Register(RedHatRepoToCPEType, NewRedHatRepoToCPE)
	f, err := New(Config{Type: RedHatRepoToCPEType, ID: "redhat"})
	if err != nil {
		t.Fatal(err)
	}
	if f.ID() != "redhat" {
		t.Errorf("ID: got %q", f.ID())
	}
}
