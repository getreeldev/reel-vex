// Package dbtest provides an in-memory db.Store for tests — a faithful
// re-implementation of the query, scope-gate, and upsert semantics so that
// api/resolver/alias tests run with no real database (no Docker). The
// production backend (Postgres) is validated separately by pkg/db/postgres'
// TestPG; this fake exists only to keep the consumer tests fast and hermetic.
//
// "Faithful" means: same filter semantics (IN within a dimension, AND across
// dimensions), the same scope gate, the same deterministic ORDER BY
// (base_id, cve, product_id, source_format), and the same BulkInsert base/
// source_format defaulting as the real backends.
package dbtest

import (
	"sort"
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
}

// New returns an empty in-memory Store.
func New() *Store {
	return &Store{vendors: map[string]string{}, adapters: map[string]adapterState{}}
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

// pkOf returns the statement primary key (vendor, cve, product_id,
// source_format, scope) after applying the same defaulting the real backends do.
func normalize(st db.Statement) db.Statement {
	if st.BaseID == "" {
		st.BaseID = st.ProductID
	}
	if st.SourceFormat == "" {
		st.SourceFormat = "csaf"
	}
	return st
}

func samePK(a, b db.Statement) bool {
	return a.Vendor == b.Vendor && a.CVE == b.CVE && a.ProductID == b.ProductID &&
		a.SourceFormat == b.SourceFormat && a.Scope == b.Scope
}

// BulkInsert replaces-or-appends each statement by primary key. (The real
// backends' conditional-upsert skip only affects whether `updated` is rewritten
// on a no-op; for test data correctness a replace is equivalent.)
func (s *Store) BulkInsert(stmts []db.Statement) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, in := range stmts {
		in = normalize(in)
		replaced := false
		for i := range s.stmts {
			if samePK(s.stmts[i], in) {
				s.stmts[i] = in
				replaced = true
				break
			}
		}
		if !replaced {
			s.stmts = append(s.stmts, in)
		}
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
		// Scope gate: no scope context => unscoped rows only; otherwise unscoped
		// OR a named scope.
		if len(f.Scopes) == 0 {
			if st.Scope != "" {
				continue
			}
		} else if st.Scope != "" && !contains(f.Scopes, st.Scope) {
			continue
		}
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

// Stats computes live (the fake has no slow scan to cache).
func (s *Store) Stats() (db.Stats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.computeStats(), nil
}

// RefreshStats is identical to Stats for the fake.
func (s *Store) RefreshStats() (db.Stats, error) {
	return s.Stats()
}
