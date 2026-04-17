package source

import (
	"context"
	"errors"
	"testing"
	"time"
)

// mockAdapter is the Adapter reference implementation used in tests.
type mockAdapter struct {
	id, name, format string
	stmts            []Statement
	discoverErr      error
}

func (m *mockAdapter) ID() string           { return m.id }
func (m *mockAdapter) Name() string         { return m.name }
func (m *mockAdapter) SourceFormat() string { return m.format }

func (m *mockAdapter) Discover(ctx context.Context) (*FeedInfo, error) {
	if m.discoverErr != nil {
		return nil, m.discoverErr
	}
	return &FeedInfo{FeedURL: "mock://feed"}, nil
}

func (m *mockAdapter) Sync(ctx context.Context, since time.Time, emit func(Statement) error) error {
	for _, s := range m.stmts {
		if err := emit(s); err != nil {
			return err
		}
	}
	return nil
}

func TestRegistry_Unknown(t *testing.T) {
	_, err := New(AdapterConfig{Type: "nonexistent"})
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestRegistry_RoundTrip(t *testing.T) {
	Register("mock-roundtrip", func(cfg AdapterConfig) (Adapter, error) {
		return &mockAdapter{id: cfg.ID, name: cfg.Name, format: "mock"}, nil
	})
	a, err := New(AdapterConfig{Type: "mock-roundtrip", ID: "vendor-x", Name: "Vendor X"})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID() != "vendor-x" {
		t.Errorf("ID: got %q, want vendor-x", a.ID())
	}
	if a.Name() != "Vendor X" {
		t.Errorf("Name: got %q, want Vendor X", a.Name())
	}
}

func TestBuildAll(t *testing.T) {
	Register("mock-build", func(cfg AdapterConfig) (Adapter, error) {
		return &mockAdapter{id: cfg.ID, format: "mock"}, nil
	})
	adapters, err := BuildAll(Config{Adapters: []AdapterConfig{
		{Type: "mock-build", ID: "a"},
		{Type: "mock-build", ID: "b"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(adapters) != 2 {
		t.Fatalf("expected 2 adapters, got %d", len(adapters))
	}
	if adapters[0].ID() != "a" || adapters[1].ID() != "b" {
		t.Errorf("order preserved: got [%s %s]", adapters[0].ID(), adapters[1].ID())
	}
}

func TestBuildAll_Fails(t *testing.T) {
	_, err := BuildAll(Config{Adapters: []AdapterConfig{
		{Type: "definitely-unknown", ID: "x"},
	}})
	if err == nil {
		t.Fatal("expected error for unknown adapter type")
	}
}

func TestAdapterLifecycle(t *testing.T) {
	a := &mockAdapter{
		id: "test", name: "Test", format: "csaf",
		stmts: []Statement{
			{CVE: "CVE-2024-1", ProductID: "pkg:a", IDType: "purl", Status: "fixed"},
			{CVE: "CVE-2024-2", ProductID: "pkg:b", IDType: "purl", Status: "affected"},
		},
	}

	feed, err := a.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if feed.FeedURL == "" {
		t.Error("expected FeedURL set")
	}

	var collected []Statement
	err = a.Sync(context.Background(), time.Time{}, func(s Statement) error {
		collected = append(collected, s)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(collected) != 2 {
		t.Errorf("collected %d, want 2", len(collected))
	}

	// Returning error from emit stops the sync and propagates.
	sentinel := errors.New("stop")
	err = a.Sync(context.Background(), time.Time{}, func(s Statement) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got %v", err)
	}
}
