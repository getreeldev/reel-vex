// Package aliases fetches vendor-published identifier mapping files and
// persists them into the product_aliases table. Mapping files let scanners
// bridge identifier vocabularies — e.g. Red Hat's repository-to-cpe.json
// lets a PURL with `?repository_id=X` be matched against CPE-keyed VEX
// statements.
//
// Aliases are separate from source.Adapter because their payload is
// different: adapters emit VEX statements; fetchers emit mapping rows.
// Shoehorning both into the Adapter interface would pollute it.
package aliases

import (
	"context"
	"fmt"

	"github.com/getreeldev/reel-vex/pkg/db"
)

// Fetcher sources a vendor's mapping file and writes rows to product_aliases.
// One Fetcher per alias-type per vendor. Registered via Register at program
// start; looked up by New.
type Fetcher interface {
	// ID is the vendor identifier the fetcher is associated with, matching
	// the adapter ID for the same vendor (e.g. "redhat").
	ID() string

	// Fetch retrieves the mapping file and upserts rows via database. Errors
	// are returned up so callers can log or retry.
	Fetch(ctx context.Context, database *db.DB) error
}

// Config is one fetcher's configuration entry in config.yaml.
type Config struct {
	Type string `yaml:"type"`          // e.g. "redhat-repository-to-cpe"
	ID   string `yaml:"id"`            // vendor identifier, e.g. "redhat"
	URL  string `yaml:"url,omitempty"` // mapping-file URL
}

// Factory constructs a Fetcher from its Config.
type Factory func(cfg Config) (Fetcher, error)

var factories = map[string]Factory{}

// Register associates a factory with a Type string. Call once per fetcher
// type from the entry-point.
func Register(fetcherType string, f Factory) {
	factories[fetcherType] = f
}

// New looks up the factory for cfg.Type and constructs the fetcher.
func New(cfg Config) (Fetcher, error) {
	f, ok := factories[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("unknown alias fetcher type %q (did you call aliases.Register?)", cfg.Type)
	}
	return f(cfg)
}

// BuildAll instantiates every fetcher in the configs slice.
func BuildAll(cfgs []Config) ([]Fetcher, error) {
	fetchers := make([]Fetcher, 0, len(cfgs))
	for _, c := range cfgs {
		f, err := New(c)
		if err != nil {
			return nil, fmt.Errorf("fetcher %q: %w", c.ID, err)
		}
		fetchers = append(fetchers, f)
	}
	return fetchers, nil
}
