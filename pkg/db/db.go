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
	IDType        string
	Status        string
	Justification string
	Updated       string
}

// Stats holds database coverage statistics.
type Stats struct {
	Vendors    int
	CVEs       int
	Statements int
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
	_, err := db.db.Exec(`
		CREATE TABLE IF NOT EXISTS vendors (
			id          TEXT PRIMARY KEY,
			name        TEXT NOT NULL,
			feed_url    TEXT NOT NULL,
			last_synced TEXT
		);

		CREATE TABLE IF NOT EXISTS statements (
			vendor        TEXT NOT NULL,
			cve           TEXT NOT NULL,
			product_id    TEXT NOT NULL,
			id_type       TEXT NOT NULL,
			status        TEXT NOT NULL,
			justification TEXT,
			updated       TEXT NOT NULL,
			PRIMARY KEY (vendor, cve, product_id)
		);

		CREATE INDEX IF NOT EXISTS idx_statements_cve ON statements(cve);
		CREATE INDEX IF NOT EXISTS idx_statements_product ON statements(product_id);
	`)
	return err
}

// UpsertVendor inserts or updates a vendor record.
func (db *DB) UpsertVendor(id, name, feedURL string) error {
	_, err := db.db.Exec(`
		INSERT INTO vendors (id, name, feed_url) VALUES (?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, feed_url=excluded.feed_url
	`, id, name, feedURL)
	return err
}

// SetVendorSynced updates the last_synced timestamp for a vendor.
func (db *DB) SetVendorSynced(id, timestamp string) error {
	_, err := db.db.Exec("UPDATE vendors SET last_synced = ? WHERE id = ?", timestamp, id)
	return err
}

// VendorLastSynced returns the last_synced timestamp for a vendor, or "" if never synced.
func (db *DB) VendorLastSynced(id string) (string, error) {
	var ts sql.NullString
	err := db.db.QueryRow("SELECT last_synced FROM vendors WHERE id = ?", id).Scan(&ts)
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
		INSERT OR REPLACE INTO statements (vendor, cve, product_id, id_type, status, justification, updated)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer prepared.Close()

	for _, s := range stmts {
		if _, err := prepared.Exec(s.Vendor, s.CVE, s.ProductID, s.IDType, s.Status, s.Justification, s.Updated); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// QueryByCVE returns all statements for a given CVE.
func (db *DB) QueryByCVE(cve string) ([]Statement, error) {
	rows, err := db.db.Query(`
		SELECT vendor, cve, product_id, id_type, status, justification, updated
		FROM statements WHERE cve = ?
	`, cve)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanStatements(rows)
}

// QueryResolve returns statements matching any of the given CVEs AND any of the given product IDs.
func (db *DB) QueryResolve(cves, productIDs []string) ([]Statement, error) {
	if len(cves) == 0 || len(productIDs) == 0 {
		return nil, nil
	}

	cvePlaceholders := strings.Repeat("?,", len(cves))
	cvePlaceholders = cvePlaceholders[:len(cvePlaceholders)-1]

	prodPlaceholders := strings.Repeat("?,", len(productIDs))
	prodPlaceholders = prodPlaceholders[:len(prodPlaceholders)-1]

	query := fmt.Sprintf(`
		SELECT vendor, cve, product_id, id_type, status, justification, updated
		FROM statements
		WHERE cve IN (%s) AND product_id IN (%s)
	`, cvePlaceholders, prodPlaceholders)

	args := make([]any, 0, len(cves)+len(productIDs))
	for _, c := range cves {
		args = append(args, c)
	}
	for _, p := range productIDs {
		args = append(args, p)
	}

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
	return s, err
}

func scanStatements(rows *sql.Rows) ([]Statement, error) {
	var stmts []Statement
	for rows.Next() {
		var s Statement
		var just sql.NullString
		if err := rows.Scan(&s.Vendor, &s.CVE, &s.ProductID, &s.IDType, &s.Status, &just, &s.Updated); err != nil {
			return nil, err
		}
		s.Justification = just.String
		stmts = append(stmts, s)
	}
	return stmts, rows.Err()
}
