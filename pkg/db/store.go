package db

import (
	"context"
	"time"
)

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

	// TryLockIngest takes the database's ingest lock, which ingest.Run holds
	// for a whole run so that two ingests on one database — two processes, or
	// the server's scheduler and the ingest subcommand — never interleave: one
	// run's ResetSweeps or StartSweep would replace the other's seen keys
	// mid-sync, and its sweep would then delete live rows. It returns
	// ErrIngestRunning, holding nothing, when the lock is held, including by
	// this process. UnlockIngest releases it; not holding it is not an error.
	TryLockIngest() error
	UnlockIngest() error

	// Removal: what a sync no longer emits. Every method taking adapterID
	// errors on an empty one, and none touches a row with no owner or another
	// adapter's row.
	//
	// StartSweep opens a sweep session for the adapter, discarding any leftover
	// one, with nothing seen yet.
	StartSweep(adapterID string) error
	// RecordSeen adds keys the sync emitted to the open session (duplicates are
	// fine and count towards Seen). Errors when no session is open.
	RecordSeen(adapterID string, keys []StatementKey) error
	// FinishSweep deletes the adapter's rows within scope whose key was not
	// recorded, then ends the session — on success, refusal and error alike.
	// Errors when no session is open. maxFraction not > 0 refuses ("sweep
	// disabled"). Scope All refuses when nothing was seen, and refuses (deleting
	// nothing) when more than maxFraction of the rows it owned would go;
	// maxFraction >= 1 disables that guard. Scope CVEs has no guard and needs
	// nothing seen: a refreshed document is authoritative, so its CVEs keep
	// exactly the rows this sync emitted — that is what replacing a document
	// means. An empty CVE list does nothing. When only ending the session
	// fails, the result still stands and the error says so.
	FinishSweep(adapterID string, scope SweepScope, maxFraction float64) (SweepResult, error)
	// AbortSweep ends the session without deleting anything. No open session is
	// not an error.
	AbortSweep(adapterID string) error
	// Withdraw deletes the adapter's rows of every CVE it holds that is absent
	// from liveCVEs, the vendor's manifest. It refuses when maxFraction is not
	// > 0, when the manifest is empty, and when more than maxFraction of the
	// held CVEs would be withdrawn.
	Withdraw(adapterID string, liveCVEs []string, maxFraction float64) (WithdrawResult, error)
	// ResetSweeps ends every open session and discards every leftover one,
	// including those a crashed process left behind.
	ResetSweeps() error

	// Query path.
	QueryStatements(f QueryFilters) ([]Statement, error)
	LookupAliases(sourceNS, sourceID, targetNS string) ([]string, error)
	AliasCount() (int, error)

	// Stats and lifecycle.
	Stats() (Stats, error)
	RefreshStats() (Stats, error)
	LastIngestAt() (time.Time, error)
	// EnsureCoveringIndex builds the broad-mode covering index if it is missing.
	// Called at the end of each ingest cycle: on the cold first load it builds
	// the index once (after the index-free bulk load — the fast path); on later
	// cycles it no-ops because the index already exists. Backends that don't need
	// it return nil.
	EnsureCoveringIndex() error
	// Ping checks the database answers. /healthz calls it, so an unreachable
	// database fails the health check instead of hiding behind cached stats.
	Ping(ctx context.Context) error
	Optimize() error
	SetQueryTimeout(d time.Duration)
	Close() error
}
