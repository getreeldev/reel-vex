package db

import (
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

// DB wraps a SQLite database for VEX statement storage.
type DB struct {
	db *sql.DB
}

// Statement is a VEX assertion stored in the database.
type Statement struct {
	Vendor        string
	CVE           string
	ProductID     string
	BaseID        string
	Version       string
	IDType        string
	Status        string
	Justification string
	Updated       string
	SourceFormat  string // "csaf", "oval", ... — upstream feed format
}

// Stats holds database coverage statistics.
type Stats struct {
	Vendors     int    `json:"vendors"`
	CVEs        int    `json:"cves"`
	Statements  int    `json:"statements"`
	Aliases     int    `json:"aliases"`
	LastUpdated string `json:"last_updated,omitempty"`
}

// Open opens or creates a SQLite database at the given path.
func Open(path string) (*DB, error) {
	d, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := d.Exec("PRAGMA journal_mode=WAL"); err != nil {
		d.Close()
		return nil, err
	}
	if _, err := d.Exec("PRAGMA synchronous=NORMAL"); err != nil {
		d.Close()
		return nil, err
	}
	db := &DB{db: d}
	if err := db.migrate(); err != nil {
		d.Close()
		return nil, err
	}
	return db, nil
}

// Close closes the database.
func (db *DB) Close() error {
	return db.db.Close()
}

func (db *DB) migrate() error {
	return runMigrations(db.db)
}

// UpsertVendor inserts or updates a vendor row. From v3 onward the vendors
// table is pure display metadata — feed URL and watermark moved to
// adapter_state so multiple adapters under one vendor can't stomp on each
// other.
func (db *DB) UpsertVendor(id, name string) error {
	_, err := db.db.Exec(`
		INSERT INTO vendors (id, name) VALUES (?, ?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name
	`, id, name)
	return err
}

// UpsertAdapterState records an adapter's feed URL + current watermark.
// Called at the end of each Sync cycle. timestamp should be the newest
// Updated field we saw on emitted statements this cycle ("" if nothing
// was emitted — keeps existing watermark intact).
func (db *DB) UpsertAdapterState(adapterID, feedURL, lastSynced string) error {
	// If lastSynced is empty, preserve the prior watermark (we didn't see
	// new data this cycle). feed_url is always refreshed since Discover
	// re-resolves it each cycle.
	_, err := db.db.Exec(`
		INSERT INTO adapter_state (adapter_id, feed_url, last_synced, updated)
		VALUES (?, ?, NULLIF(?, ''), ?)
		ON CONFLICT(adapter_id) DO UPDATE SET
			feed_url = excluded.feed_url,
			last_synced = COALESCE(NULLIF(excluded.last_synced, ''), adapter_state.last_synced),
			updated = excluded.updated
	`, adapterID, feedURL, lastSynced, lastSynced)
	return err
}

// AdapterLastSynced returns the last_synced timestamp for an adapter, or
// "" if the adapter has never successfully synced.
func (db *DB) AdapterLastSynced(adapterID string) (string, error) {
	var ts sql.NullString
	err := db.db.QueryRow("SELECT last_synced FROM adapter_state WHERE adapter_id = ?", adapterID).Scan(&ts)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return ts.String, nil
}

// BulkInsert inserts statements in a single transaction.
func (db *DB) BulkInsert(stmts []Statement) error {
	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	prepared, err := tx.Prepare(`
		INSERT OR REPLACE INTO statements (vendor, cve, product_id, base_id, version, id_type, status, justification, updated, source_format)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer prepared.Close()

	for _, s := range stmts {
		base := s.BaseID
		if base == "" {
			base = s.ProductID
		}
		var version any
		if s.Version != "" {
			version = s.Version
		}
		sourceFormat := s.SourceFormat
		if sourceFormat == "" {
			sourceFormat = "csaf"
		}
		if _, err := prepared.Exec(s.Vendor, s.CVE, s.ProductID, base, version, s.IDType, s.Status, s.Justification, s.Updated, sourceFormat); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// QueryByCVE returns all statements for a given CVE.
func (db *DB) QueryByCVE(cve string) ([]Statement, error) {
	rows, err := db.db.Query(`
		SELECT vendor, cve, product_id, base_id, version, id_type, status, justification, updated, source_format
		FROM statements WHERE cve = ?
	`, cve)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanStatements(rows)
}

// QueryResolve returns statements matching any of the given CVEs AND any of the
// given product base IDs, optionally filtered to specific source_formats.
// Callers should pass already-normalized base IDs (PURLs without @version
// and qualifiers; CPEs as-is). Empty sourceFormats means "no filter" —
// every format matches.
func (db *DB) QueryResolve(cves, productBaseIDs, sourceFormats []string) ([]Statement, error) {
	if len(cves) == 0 || len(productBaseIDs) == 0 {
		return nil, nil
	}

	cvePlaceholders := strings.Repeat("?,", len(cves))
	cvePlaceholders = cvePlaceholders[:len(cvePlaceholders)-1]

	prodPlaceholders := strings.Repeat("?,", len(productBaseIDs))
	prodPlaceholders = prodPlaceholders[:len(prodPlaceholders)-1]

	args := make([]any, 0, len(cves)+len(productBaseIDs)+len(sourceFormats))
	for _, c := range cves {
		args = append(args, c)
	}
	for _, p := range productBaseIDs {
		args = append(args, p)
	}

	sourceFilter := ""
	if len(sourceFormats) > 0 {
		srcPlaceholders := strings.Repeat("?,", len(sourceFormats))
		srcPlaceholders = srcPlaceholders[:len(srcPlaceholders)-1]
		sourceFilter = fmt.Sprintf(" AND source_format IN (%s)", srcPlaceholders)
		for _, sf := range sourceFormats {
			args = append(args, sf)
		}
	}

	query := fmt.Sprintf(`
		SELECT vendor, cve, product_id, base_id, version, id_type, status, justification, updated, source_format
		FROM statements
		WHERE cve IN (%s) AND base_id IN (%s)%s
	`, cvePlaceholders, prodPlaceholders, sourceFilter)

	rows, err := db.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanStatements(rows)
}

// Stats returns coverage statistics.
func (db *DB) Stats() (Stats, error) {
	var s Stats
	err := db.db.QueryRow("SELECT COUNT(DISTINCT id) FROM vendors").Scan(&s.Vendors)
	if err != nil {
		return s, err
	}
	err = db.db.QueryRow("SELECT COUNT(DISTINCT cve) FROM statements").Scan(&s.CVEs)
	if err != nil {
		return s, err
	}
	err = db.db.QueryRow("SELECT COUNT(*) FROM statements").Scan(&s.Statements)
	if err != nil {
		return s, err
	}
	err = db.db.QueryRow("SELECT COUNT(*) FROM product_aliases").Scan(&s.Aliases)
	if err != nil {
		return s, err
	}
	var lastUpdated sql.NullString
	err = db.db.QueryRow("SELECT MAX(last_synced) FROM adapter_state").Scan(&lastUpdated)
	if err != nil && err != sql.ErrNoRows {
		return s, err
	}
	if lastUpdated.Valid {
		s.LastUpdated = lastUpdated.String
	}
	return s, nil
}

// Alias is a mapping from one identifier namespace to another, as published
// by a vendor (e.g. Red Hat's repository-to-cpe.json).
type Alias struct {
	Vendor   string
	SourceNS string
	SourceID string
	TargetNS string
	TargetID string
	Updated  string
}

// BulkUpsertAliases replaces or inserts each alias row. Idempotent — safe to
// re-run with fresh data; rows for the same PK get their Updated refreshed.
func (db *DB) BulkUpsertAliases(aliases []Alias) error {
	if len(aliases) == 0 {
		return nil
	}
	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	prepared, err := tx.Prepare(`
		INSERT OR REPLACE INTO product_aliases
			(vendor, source_ns, source_id, target_ns, target_id, confidence, updated)
		VALUES (?, ?, ?, ?, ?, 1.0, ?)
	`)
	if err != nil {
		return err
	}
	defer prepared.Close()

	for _, a := range aliases {
		if _, err := prepared.Exec(a.Vendor, a.SourceNS, a.SourceID, a.TargetNS, a.TargetID, a.Updated); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LookupAliases returns all target identifiers in targetNS reached from the
// given source identifier, scanning across all vendors. Order is stable but
// not semantically meaningful; callers should treat the result as a set.
func (db *DB) LookupAliases(sourceNS, sourceID, targetNS string) ([]string, error) {
	rows, err := db.db.Query(`
		SELECT target_id FROM product_aliases
		WHERE source_ns = ? AND source_id = ? AND target_ns = ?
		ORDER BY vendor, target_id
	`, sourceNS, sourceID, targetNS)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// AliasCount returns the total number of rows in product_aliases. Used by
// stats + smoke tests.
func (db *DB) AliasCount() (int, error) {
	var n int
	err := db.db.QueryRow("SELECT COUNT(*) FROM product_aliases").Scan(&n)
	return n, err
}

func scanStatements(rows *sql.Rows) ([]Statement, error) {
	var stmts []Statement
	for rows.Next() {
		var s Statement
		var just, version sql.NullString
		if err := rows.Scan(&s.Vendor, &s.CVE, &s.ProductID, &s.BaseID, &version, &s.IDType, &s.Status, &just, &s.Updated, &s.SourceFormat); err != nil {
			return nil, err
		}
		s.Justification = just.String
		s.Version = version.String
		stmts = append(stmts, s)
	}
	return stmts, rows.Err()
}
