package db

import "time"

// Store is the persistence contract the rest of reel-vex depends on. The
// production implementation is the Postgres backend (pkg/db/postgres); tests
// use an in-memory fake (pkg/db/dbtest). Consumers depend only on this
// interface and the package-level data types — pkg/db pulls in no driver.
type Store interface {
	// Ingest write path.
	UpsertVendor(id, name string) error
	UpsertAdapterState(adapterID, feedURL, lastSynced string) error
	AdapterLastSynced(adapterID string) (string, error)
	BulkInsert(stmts []Statement) error
	BulkUpsertAliases(aliases []Alias) error

	// Query path.
	QueryStatements(f QueryFilters) ([]Statement, error)
	LookupAliases(sourceNS, sourceID, targetNS string) ([]string, error)
	AliasCount() (int, error)

	// Stats and lifecycle.
	Stats() (Stats, error)
	RefreshStats() (Stats, error)
	LastIngestAt() (time.Time, error)
	Optimize() error
	SetQueryTimeout(d time.Duration)
	Close() error
}
