// Package dbtest provides an in-memory db.Store for tests — a faithful
// re-implementation of the query, scope-gate, and upsert semantics so that
// api/resolver/alias tests run with no real database (no Docker). The
// production backend (Postgres) is validated separately by pkg/db/postgres'
// TestPG; this fake exists only to keep the consumer tests fast and hermetic.
//
// "Faithful" means: same filter semantics (IN within a dimension, AND across
// dimensions), the same scope gate, the same deterministic ORDER BY
// (base_id, cve, product_id, source_format), and the same BulkInsert base/
// source_format defaulting, version-list normalisation, primary key and
// change guard as the real backends.
package dbtest

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/getreeldev/reel-vex/pkg/db"
)

type adapterState struct{ feedURL, lastSynced, updated string }

// Store is an in-memory db.Store.
type Store struct {
	mu       sync.Mutex
	stmts    []db.Statement
	aliases  []db.Alias
	vendors  map[string]string
	adapters map[string]adapterState
	// statsErr, when set, is returned by Stats instead of a computed result.
	// See SetStatsErr.
	statsErr error
	// sweeps holds the open sweep sessions, by adapter id.
	sweeps map[string]*sweep
}

// sweep is one open sweep session: the distinct keys recorded, and the count
// of keys recorded including duplicates (SweepResult.Seen).
type sweep struct {
	keys map[db.StatementKey]struct{}
	seen int64
}

// New returns an empty in-memory Store.
func New() *Store {
	return &Store{vendors: map[string]string{}, adapters: map[string]adapterState{}, sweeps: map[string]*sweep{}}
}

var _ db.Store = (*Store)(nil)

func (s *Store) SetQueryTimeout(time.Duration) {}
func (s *Store) Close() error                  { return nil }
func (s *Store) Optimize() error               { return nil }
func (s *Store) EnsureCoveringIndex() error    { return nil }

func (s *Store) UpsertVendor(id, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vendors[id] = name
	return nil
}

func (s *Store) UpsertAdapterState(adapterID, feedURL, lastSynced string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.adapters[adapterID]
	ls := lastSynced
	if ls == "" {
		ls = prev.lastSynced // empty preserves the prior watermark
	}
	s.adapters[adapterID] = adapterState{feedURL: feedURL, lastSynced: ls, updated: time.Now().UTC().Format(time.RFC3339)}
	return nil
}

func (s *Store) AdapterLastSynced(adapterID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.adapters[adapterID].lastSynced, nil
}

func (s *Store) LastIngestAt() (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var max string
	for _, a := range s.adapters {
		if a.updated > max {
			max = a.updated
		}
	}
	if max == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, max)
	if err != nil {
		return time.Time{}, nil
	}
	return t, nil
}

// normalize applies the same defaulting and version-list normalisation the
// real backends do on write.
func normalize(st db.Statement) db.Statement {
	if st.BaseID == "" {
		st.BaseID = st.ProductID
	}
	if st.SourceFormat == "" {
		st.SourceFormat = "csaf"
	}
	st.Versions = db.NormalizeVersions(st.Versions)
	return st
}

// samePK compares the primary key (vendor, cve, product_id, source_format,
// scope, stream, status, justification): one row per stream and verdict.
func samePK(a, b db.Statement) bool {
	return a.Vendor == b.Vendor && a.CVE == b.CVE && a.ProductID == b.ProductID &&
		a.SourceFormat == b.SourceFormat && a.Scope == b.Scope && a.Stream == b.Stream &&
		a.Status == b.Status && a.Justification == b.Justification
}

// changed is the upsert guard: an existing row is rewritten only when one of
// these differs, so an unchanged re-insert keeps its `updated` and its owner.
func changed(old, in db.Statement) bool {
	return !slices.Equal(old.Versions, in.Versions) || old.BaseID != in.BaseID ||
		old.IDType != in.IDType || old.VersionKind != in.VersionKind
}

// BulkInsert mirrors the Postgres upsert: rows sharing a primary key within
// the batch resolve last-wins, then each is appended, or replaces the stored
// row with its key only when the guard says it changed.
func (s *Store) BulkInsert(stmts []db.Statement) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var batch []db.Statement
	for _, in := range stmts {
		in = normalize(in)
		if i := slices.IndexFunc(batch, func(b db.Statement) bool { return samePK(b, in) }); i >= 0 {
			batch[i] = in
			continue
		}
		batch = append(batch, in)
	}
	for _, in := range batch {
		if i := slices.IndexFunc(s.stmts, func(st db.Statement) bool { return samePK(st, in) }); i >= 0 {
			if changed(s.stmts[i], in) {
				s.stmts[i] = in
			}
			continue
		}
		s.stmts = append(s.stmts, in)
	}
	return nil
}

func contains(set []string, v string) bool {
	for _, x := range set {
		if x == v {
			return true
		}
	}
	return false
}

// QueryStatements mirrors the real backends: AND across populated dimensions,
// IN within each, the scope gate, deterministic order, then offset/limit.
func (s *Store) QueryStatements(f db.QueryFilters) ([]db.Statement, error) {
	if len(f.CVEs) == 0 && len(f.ProductBaseIDs) == 0 {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []db.Statement
	for _, st := range s.stmts {
		if len(f.CVEs) > 0 && !contains(f.CVEs, st.CVE) {
			continue
		}
		if len(f.ProductBaseIDs) > 0 && !contains(f.ProductBaseIDs, st.BaseID) {
			continue
		}
		if len(f.Vendors) > 0 && !contains(f.Vendors, st.Vendor) {
			continue
		}
		if len(f.SourceFormats) > 0 && !contains(f.SourceFormats, st.SourceFormat) {
			continue
		}
		if len(f.Statuses) > 0 && !contains(f.Statuses, st.Status) {
			continue
		}
		if len(f.Justifications) > 0 && !contains(f.Justifications, st.Justification) {
			continue
		}
		if f.Since != "" && st.Updated < f.Since {
			continue
		}
		// Arch narrowing. The Postgres backend applies a LIKE superset here and
		// leaves the exact qualifier check to pkg/api; the fake does the same
		// substring match so the two backends can't drift on which rows survive
		// the query itself.
		if len(f.ArchAllow) > 0 && strings.Contains(st.ProductID, "arch=") {
			if !archLikeAny(st.ProductID, f.ArchAllow) {
				continue
			}
		}
		// Scope gate: no scope context => unscoped rows only; otherwise unscoped
		// OR a named scope.
		if len(f.Scopes) == 0 {
			if st.Scope != "" {
				continue
			}
		} else if st.Scope != "" && !contains(f.Scopes, st.Scope) {
			continue
		}
		st.AdapterID, st.Stream = "", "" // never selected by the Postgres query
		out = append(out, st)
	}

	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.BaseID != b.BaseID {
			return a.BaseID < b.BaseID
		}
		if a.CVE != b.CVE {
			return a.CVE < b.CVE
		}
		if a.ProductID != b.ProductID {
			return a.ProductID < b.ProductID
		}
		return a.SourceFormat < b.SourceFormat
	})

	if f.Offset > 0 {
		if f.Offset >= len(out) {
			return nil, nil
		}
		out = out[f.Offset:]
	}
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

func aliasPK(a, b db.Alias) bool {
	return a.Vendor == b.Vendor && a.SourceNS == b.SourceNS && a.SourceID == b.SourceID &&
		a.TargetNS == b.TargetNS && a.TargetID == b.TargetID
}

func (s *Store) BulkUpsertAliases(aliases []db.Alias) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, in := range aliases {
		replaced := false
		for i := range s.aliases {
			if aliasPK(s.aliases[i], in) {
				s.aliases[i] = in
				replaced = true
				break
			}
		}
		if !replaced {
			s.aliases = append(s.aliases, in)
		}
	}
	return nil
}

func (s *Store) LookupAliases(sourceNS, sourceID, targetNS string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	type row struct{ vendor, target string }
	var rows []row
	for _, a := range s.aliases {
		if a.SourceNS == sourceNS && a.SourceID == sourceID && a.TargetNS == targetNS {
			rows = append(rows, row{a.Vendor, a.TargetID})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].vendor != rows[j].vendor {
			return rows[i].vendor < rows[j].vendor
		}
		return rows[i].target < rows[j].target
	})
	var out []string
	for _, r := range rows {
		out = append(out, r.target)
	}
	return out, nil
}

func (s *Store) AliasCount() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.aliases), nil
}

func (s *Store) computeStats() db.Stats {
	cves := map[string]struct{}{}
	for _, st := range s.stmts {
		cves[st.CVE] = struct{}{}
	}
	var lastUpdated string
	for _, a := range s.adapters {
		if a.lastSynced > lastUpdated {
			lastUpdated = a.lastSynced
		}
	}
	return db.Stats{
		Vendors:     len(s.vendors),
		CVEs:        len(cves),
		Statements:  len(s.stmts),
		Aliases:     len(s.aliases),
		LastUpdated: lastUpdated,
	}
}

// SetStatsErr makes Stats return err instead of computing. Lets a test drive
// the caller's error paths (e.g. db.ErrStatsWarming) without a real backend,
// which is the only place the cold-cache condition can arise.
func (s *Store) SetStatsErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statsErr = err
}

// Stats computes live (the fake has no slow scan to cache).
func (s *Store) Stats() (db.Stats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.statsErr != nil {
		return db.Stats{}, s.statsErr
	}
	return s.computeStats(), nil
}

// RefreshStats is identical to Stats for the fake.
func (s *Store) RefreshStats() (db.Stats, error) {
	return s.Stats()
}

// archLikeAny mirrors the Postgres backend's `product_id LIKE ANY(...)` arch
// predicate: a substring match, boundaries and all left to the caller's exact
// check. Kept deliberately imprecise so the fake and Postgres return the same
// rows.
func archLikeAny(productID string, allow []string) bool {
	for _, a := range allow {
		if a == "" {
			continue
		}
		if strings.Contains(productID, "arch="+a) {
			return true
		}
	}
	return false
}

// StartSweep opens a sweep session, discarding any open one.
func (s *Store) StartSweep(adapterID string) error {
	if adapterID == "" {
		return errors.New("start sweep: empty adapter id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweeps[adapterID] = &sweep{keys: map[db.StatementKey]struct{}{}}
	return nil
}

// RecordSeen adds keys to the open session.
func (s *Store) RecordSeen(adapterID string, keys []db.StatementKey) error {
	if adapterID == "" {
		return errors.New("record seen: empty adapter id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sw, ok := s.sweeps[adapterID]
	if !ok {
		return fmt.Errorf("record seen: no open sweep for %s", adapterID)
	}
	for _, k := range keys {
		sw.keys[k] = struct{}{}
	}
	sw.seen += int64(len(keys))
	return nil
}

// FinishSweep mirrors the Postgres backend: the same checks in the same order,
// the same guard on Owned, and the session ends whatever the outcome.
func (s *Store) FinishSweep(adapterID string, scope db.SweepScope, maxFraction float64) (db.SweepResult, error) {
	if adapterID == "" {
		return db.SweepResult{}, errors.New("finish sweep: empty adapter id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sw, ok := s.sweeps[adapterID]
	if !ok {
		return db.SweepResult{}, fmt.Errorf("finish sweep: no open sweep for %s", adapterID)
	}
	delete(s.sweeps, adapterID)

	res := db.SweepResult{Seen: sw.seen}
	if !(maxFraction > 0) {
		res.Refused, res.Reason = true, "sweep disabled"
		return res, nil
	}
	if scope.All {
		if sw.seen == 0 {
			res.Refused, res.Reason = true, "nothing seen"
			return res, nil
		}
	} else if len(scope.CVEs) == 0 {
		return res, nil
	}

	keep := make([]db.Statement, 0, len(s.stmts))
	for _, st := range s.stmts {
		if st.AdapterID == adapterID && (scope.All || contains(scope.CVEs, st.CVE)) {
			res.Owned++
			if _, seen := sw.keys[db.StatementKey{CVE: st.CVE, ProductID: st.ProductID, Scope: st.Scope,
				Stream: st.Stream, Status: st.Status, Justification: st.Justification}]; !seen {
				res.Deleted++
				continue
			}
		}
		keep = append(keep, st)
	}
	if scope.All && maxFraction < 1 && float64(res.Deleted) > maxFraction*float64(res.Owned) {
		res.Refused = true
		res.Reason = fmt.Sprintf("would delete %d of %d owned rows (%.2f%%), over the %.2f%% limit",
			res.Deleted, res.Owned, 100*float64(res.Deleted)/float64(res.Owned), 100*maxFraction)
		return res, nil
	}
	s.stmts = keep
	return res, nil
}

// AbortSweep ends the session without deleting anything.
func (s *Store) AbortSweep(adapterID string) error {
	if adapterID == "" {
		return errors.New("abort sweep: empty adapter id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sweeps, adapterID)
	return nil
}

// Withdraw mirrors the Postgres backend.
func (s *Store) Withdraw(adapterID string, liveCVEs []string, maxFraction float64) (db.WithdrawResult, error) {
	if adapterID == "" {
		return db.WithdrawResult{}, errors.New("withdraw: empty adapter id")
	}
	live := map[string]struct{}{}
	for _, c := range liveCVEs {
		live[c] = struct{}{}
	}
	res := db.WithdrawResult{Live: int64(len(live))}
	if !(maxFraction > 0) {
		res.Refused, res.Reason = true, "withdraw disabled"
		return res, nil
	}
	if len(live) == 0 {
		res.Refused, res.Reason = true, "empty manifest"
		return res, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	held := map[string]struct{}{}
	gone := map[string]struct{}{}
	for _, st := range s.stmts {
		if st.AdapterID != adapterID {
			continue
		}
		held[st.CVE] = struct{}{}
		if _, ok := live[st.CVE]; !ok {
			gone[st.CVE] = struct{}{}
		}
	}
	res.HeldCVEs, res.WithdrawnCVEs = int64(len(held)), int64(len(gone))
	if maxFraction < 1 && float64(len(gone)) > maxFraction*float64(len(held)) {
		res.Refused = true
		res.Reason = fmt.Sprintf("would withdraw %d of %d held CVEs (%.2f%%), over the %.2f%% limit",
			len(gone), len(held), 100*float64(len(gone))/float64(len(held)), 100*maxFraction)
		return res, nil
	}
	keep := make([]db.Statement, 0, len(s.stmts))
	for _, st := range s.stmts {
		if _, ok := gone[st.CVE]; ok && st.AdapterID == adapterID {
			res.Deleted++
			continue
		}
		keep = append(keep, st)
	}
	s.stmts = keep
	return res, nil
}

// ResetSweeps ends every open session.
func (s *Store) ResetSweeps() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweeps = map[string]*sweep{}
	return nil
}
