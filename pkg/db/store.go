package db

import "time"

// Store is the persistence contract the rest of reel-vex depends on. The
// concrete *DB (SQLite via modernc) is the only implementation today; defining
// the surface as an interface lets a second backend (e.g. Postgres) drop in
// without touching the API, ingest, resolver, or alias layers. Consumers should
// depend on Store, not *DB.
//
// The method set is exactly the connection surface those consumers call — the
// data types (Statement, QueryFilters, Stats, Alias) stay package-level and are
// shared across implementations.
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

// Compile-time assertion that the SQLite implementation satisfies Store.
var _ Store = (*DB)(nil)
