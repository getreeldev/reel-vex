package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/getreeldev/reel-vex/pkg/db"
)

// Removal. A sync records every key it emits into a per-adapter seen table;
// FinishSweep then deletes the adapter's rows that are not in it, and Withdraw
// deletes the adapter's rows of CVEs absent from the vendor's manifest. On the
// full Ubuntu OpenVEX feed (~196M owned rows) a sweep needed ~84-116 GB of
// transient disk above the database's steady size and took 85 minutes.

// sweepTimeout bounds one FinishSweep or Withdraw, all of its statements. The
// store methods take no context, so a shutdown cannot cancel a running sweep;
// this bound and the per-statement server-side one below are what end it.
// Above the statement bound because a sweep that deletes many rows runs its
// anti join and then one DELETE per batch.
const sweepTimeout = 6 * time.Hour

// sweepStatementTimeoutSQL bounds each statement of a sweep or withdrawal,
// applied with SET LOCAL so one orphaned by a crashed process dies instead of
// running on holding locks. The longest statement is a whole-feed sweep's anti
// join, 85 minutes on the full Ubuntu feed.
const sweepStatementTimeoutSQL = `'2h'`

// sweepBatchRows bounds the ctids one DELETE takes. ARRAY() fails above 2^26
// elements ("invalid memory alloc request size 1073741824"), which a sweep of
// Ubuntu OpenVEX's ~196M owned rows reaches when about a third of them go;
// batches keep every array far below it. A variable so a test can force many
// batches.
var sweepBatchRows = 5_000_000

// sweepDDLTimeout bounds creating and dropping seen tables. Each DROP also
// sets lock_timeout '30s': an orphaned sweep still running server-side holds a
// lock on its seen table, and the next run must fail rather than block behind
// it for up to two hours.
const sweepDDLTimeout = 2 * time.Minute

// seenTable names the adapter's seen table: sweep_seen_ + the id lowercased
// with everything outside [a-z0-9_] replaced by _, cut to 32 characters, + _ +
// the first 8 hex characters of sha256(id). The hash keeps distinct ids
// distinct after the folding; the whole stays under the 63-byte identifier
// limit. Always quote it with pgx.Identifier.
func seenTable(adapterID string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(adapterID) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	name := b.String()
	if len(name) > 32 {
		name = name[:32]
	}
	sum := sha256.Sum256([]byte(adapterID))
	return "sweep_seen_" + name + "_" + hex.EncodeToString(sum[:4])
}

// sweepSession returns the keys recorded so far and whether a session is open.
func (p *DB) sweepSession(adapterID string) (int64, bool) {
	p.sweepMu.Lock()
	defer p.sweepMu.Unlock()
	n, ok := p.sweepSeen[adapterID]
	return n, ok
}

// dropSeenTable drops one seen table behind a 30 s lock timeout.
func (p *DB) dropSeenTable(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), sweepDDLTimeout)
	defer cancel()
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '30s'`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DROP TABLE IF EXISTS `+pgx.Identifier{name}.Sanitize()); err != nil {
		return fmt.Errorf("drop %s: %w", name, err)
	}
	return tx.Commit(ctx)
}

// endSweep closes the adapter's session and drops its seen table.
func (p *DB) endSweep(adapterID string) error {
	p.sweepMu.Lock()
	delete(p.sweepSeen, adapterID)
	p.sweepMu.Unlock()
	return p.dropSeenTable(seenTable(adapterID))
}

// StartSweep opens a sweep session: any leftover seen table for the adapter is
// dropped and an empty one created. The seen table is UNLOGGED rather than
// TEMP because RecordSeen batches arrive on different pool connections. It has
// no index and no key, and autovacuum is off for it: it is insert-only and
// tens of GB at Ubuntu scale, and since PG13 inserts alone trigger autovacuum
// and auto-analyze, which would vacuum it repeatedly during a sweep.
func (p *DB) StartSweep(adapterID string) error {
	if adapterID == "" {
		return errors.New("start sweep: empty adapter id")
	}
	name := seenTable(adapterID)
	if err := p.dropSeenTable(name); err != nil {
		return fmt.Errorf("start sweep: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), sweepDDLTimeout)
	defer cancel()
	if _, err := p.pool.Exec(ctx, `CREATE UNLOGGED TABLE `+pgx.Identifier{name}.Sanitize()+` (
			cve           TEXT NOT NULL,
			product_id    TEXT NOT NULL,
			scope         TEXT NOT NULL,
			stream        TEXT NOT NULL,
			status        TEXT NOT NULL,
			justification TEXT NOT NULL
		) WITH (autovacuum_enabled = false)`); err != nil {
		return fmt.Errorf("start sweep: create %s: %w", name, err)
	}
	p.sweepMu.Lock()
	if p.sweepSeen == nil {
		p.sweepSeen = map[string]int64{}
	}
	p.sweepSeen[adapterID] = 0
	p.sweepMu.Unlock()
	return nil
}

// seenCols is the COPY column order for the seen table.
var seenCols = []string{"cve", "product_id", "scope", "stream", "status", "justification"}

// RecordSeen appends keys to the adapter's seen table.
func (p *DB) RecordSeen(adapterID string, keys []db.StatementKey) error {
	if adapterID == "" {
		return errors.New("record seen: empty adapter id")
	}
	if _, ok := p.sweepSession(adapterID); !ok {
		return fmt.Errorf("record seen: no open sweep for %s", adapterID)
	}
	if len(keys) == 0 {
		return nil
	}
	rows := make([][]any, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, []any{k.CVE, k.ProductID, k.Scope, k.Stream, k.Status, k.Justification})
	}
	if _, err := p.pool.CopyFrom(context.Background(), pgx.Identifier{seenTable(adapterID)}, seenCols, pgx.CopyFromRows(rows)); err != nil {
		return fmt.Errorf("record seen: %w", err)
	}
	p.sweepMu.Lock()
	if _, ok := p.sweepSeen[adapterID]; ok {
		p.sweepSeen[adapterID] += int64(len(keys))
	}
	p.sweepMu.Unlock()
	return nil
}

// sweepGoneSQL counts the adapter's rows within scope and records the ctids of
// the unseen ones in _sweep_gone, in one pass over them; nothing is deleted
// yet, so the guard can refuse without having written to statements. Verified
// with EXPLAIN (TestPG asserts it): NOT EXISTS must stay in a WHERE clause,
// where it plans as an anti join that can spill — in a SELECT list it plans as
// a SubPlan that cannot, or scans seen once per owned row, which never
// finishes at scale. The key is (cve, product_id, scope, stream, status,
// justification) — the verdict is part of a row's identity, so a row whose
// verdict changed is swept and its successor kept — and every one of them is
// NOT NULL in both tables, so plain equality is correct. $1 is the adapter id;
// scoped adds $2, the CVE list.
func sweepGoneSQL(seen string, scoped bool) string {
	cveFilter := ""
	if scoped {
		cveFilter = ` AND s.cve = ANY($2::text[])`
	}
	return `
		WITH owned AS MATERIALIZED (
			SELECT s.ctid AS row_ctid, s.cve, s.product_id, s.scope, s.stream, s.status, s.justification
			FROM statements s WHERE s.adapter_id = $1` + cveFilter + `
		), gone AS (
			INSERT INTO _sweep_gone
			SELECT o.row_ctid FROM owned o
			WHERE NOT EXISTS (SELECT 1 FROM ` + pgx.Identifier{seen}.Sanitize() + ` k
				WHERE k.cve = o.cve AND k.product_id = o.product_id AND k.scope = o.scope
				  AND k.stream = o.stream AND k.status = o.status AND k.justification = o.justification)
			RETURNING 1
		)
		SELECT (SELECT count(*) FROM owned), (SELECT count(*) FROM gone)`
}

// sweepDeleteSQL deletes one batch: the rows whose ctids _sweep_gone holds on
// its pages [$2, $3). The page range reads only those pages (a Tid Range
// Scan), so the batches together read the gone set once, and the delete is a
// Tid Scan, as `DELETE … USING` would plan a full scan. adapter_id is checked
// again so a ctid can only ever delete the adapter's own row.
const sweepDeleteSQL = `
	DELETE FROM statements d
	WHERE d.adapter_id = $1
	  AND d.ctid = ANY (ARRAY(
		SELECT g.row_ctid FROM _sweep_gone g
		WHERE g.ctid >= $2::tid AND g.ctid < $3::tid))`

// setSweepLocals applies the session settings a sweep or withdrawal runs
// under, scoped to tx: enough work_mem for the anti join, the per-statement
// server-side bound, a check that notices a vanished client within seconds
// (PG 14+), and — only where the role may set it — a temp-file cap so an
// oversized sweep fails cleanly (a managed database's role cannot).
func setSweepLocals(ctx context.Context, tx pgx.Tx) error {
	for _, q := range []string{
		`SET LOCAL work_mem = '512MB'`,
		`SET LOCAL statement_timeout = ` + sweepStatementTimeoutSQL,
		`SET LOCAL client_connection_check_interval = '10s'`,
	} {
		if _, err := tx.Exec(ctx, q); err != nil {
			return err
		}
	}
	var superuser string
	if err := tx.QueryRow(ctx, `SELECT current_setting('is_superuser')`).Scan(&superuser); err != nil {
		return err
	}
	if superuser == "on" {
		if _, err := tx.Exec(ctx, `SET LOCAL temp_file_limit = '100GB'`); err != nil {
			return err
		}
	}
	return nil
}

// FinishSweep deletes the adapter's unseen rows within scope in one
// transaction, then drops the seen table — only after the transaction has
// ended, because the ANALYZE inside it locks the seen table and a DROP there
// would wait on itself.
func (p *DB) FinishSweep(adapterID string, scope db.SweepScope, maxFraction float64) (db.SweepResult, error) {
	if adapterID == "" {
		return db.SweepResult{}, errors.New("finish sweep: empty adapter id")
	}
	seen, ok := p.sweepSession(adapterID)
	if !ok {
		return db.SweepResult{}, fmt.Errorf("finish sweep: no open sweep for %s", adapterID)
	}
	res, err := p.finishSweep(adapterID, seen, scope, maxFraction)
	if endErr := p.endSweep(adapterID); endErr != nil && err == nil {
		err = fmt.Errorf("finish sweep: end session: %w", endErr)
	}
	return res, err
}

func (p *DB) finishSweep(adapterID string, seen int64, scope db.SweepScope, maxFraction float64) (db.SweepResult, error) {
	res := db.SweepResult{Seen: seen}
	if !(maxFraction > 0) {
		res.Refused, res.Reason = true, "sweep disabled"
		return res, nil
	}
	if scope.All {
		if seen == 0 {
			res.Refused, res.Reason = true, "nothing seen"
			return res, nil
		}
	} else if len(scope.CVEs) == 0 {
		return res, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), sweepTimeout)
	defer cancel()
	// Repeatable read gives every statement the snapshot the gone set was
	// found in, as one statement had: no ctid it recorded can be reused by
	// another row before the last batch, and a row changed concurrently fails
	// the sweep instead of being deleted on stale evidence.
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return res, fmt.Errorf("finish sweep: %w", err)
	}
	defer tx.Rollback(context.Background())
	if err := setSweepLocals(ctx, tx); err != nil {
		return res, fmt.Errorf("finish sweep: %w", err)
	}
	seenName := seenTable(adapterID)
	// Without fresh statistics on the seen table the planner misestimates the
	// anti join ~40x.
	if _, err := tx.Exec(ctx, `ANALYZE `+pgx.Identifier{seenName}.Sanitize()); err != nil {
		return res, fmt.Errorf("finish sweep: analyze: %w", err)
	}
	// TEMP is fine here: one transaction, one connection. A temp table is
	// written without WAL and outside shared buffers, so a refused sweep costs
	// its pass over the owned rows and nothing written to statements.
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE _sweep_gone (row_ctid tid NOT NULL) ON COMMIT DROP`); err != nil {
		return res, fmt.Errorf("finish sweep: %w", err)
	}
	args := []any{adapterID}
	if !scope.All {
		args = append(args, scope.CVEs)
	}
	var owned, gone int64
	if err := tx.QueryRow(ctx, sweepGoneSQL(seenName, !scope.All), args...).Scan(&owned, &gone); err != nil {
		return res, fmt.Errorf("finish sweep: %w", err)
	}
	res.Owned, res.Deleted = owned, gone
	// The guard's denominator is Owned, not Seen: adapters emit duplicate keys
	// (Red Hat CSAF emitted 29M statements for 10.8M rows). A scoped sweep has
	// no guard — a parsed document is authoritative and can drop to nothing.
	if scope.All && maxFraction < 1 && float64(gone) > maxFraction*float64(owned) {
		res.Refused = true
		res.Reason = fmt.Sprintf("would delete %d of %d owned rows (%.2f%%), over the %.2f%% limit",
			gone, owned, 100*float64(gone)/float64(owned), 100*maxFraction)
		if err := tx.Rollback(ctx); err != nil {
			return res, fmt.Errorf("finish sweep: rollback: %w", err)
		}
		return res, nil
	}
	if gone > 0 {
		deleted, err := deleteGone(ctx, tx, adapterID)
		if err != nil {
			return res, fmt.Errorf("finish sweep: %w", err)
		}
		res.Deleted = deleted
	}
	if err := tx.Commit(ctx); err != nil {
		return res, fmt.Errorf("finish sweep: commit: %w", err)
	}
	return res, nil
}

// deleteGone deletes the rows _sweep_gone names, in batches of at most
// sweepBatchRows. A batch is a range of the gone table's pages: no heap page
// holds more than (block size - 24) / 28 tuples (Postgres'
// MaxHeapTuplesPerPage), so that many pages per batch never exceed the bound.
func deleteGone(ctx context.Context, tx pgx.Tx, adapterID string) (int64, error) {
	var pages, blockSize int64
	if err := tx.QueryRow(ctx, `SELECT pg_relation_size('_sweep_gone') / current_setting('block_size')::bigint,
		current_setting('block_size')::bigint`).Scan(&pages, &blockSize); err != nil {
		return 0, err
	}
	step := max(int64(sweepBatchRows)/((blockSize-24)/28), 1)
	var deleted int64
	for first := int64(0); first < pages; first += step {
		from := pgtype.TID{BlockNumber: uint32(first), Valid: true}
		to := pgtype.TID{BlockNumber: uint32(min(first+step, pages)), Valid: true}
		tag, err := tx.Exec(ctx, sweepDeleteSQL, adapterID, from, to)
		if err != nil {
			return deleted, err
		}
		deleted += tag.RowsAffected()
	}
	return deleted, nil
}

// AbortSweep drops the adapter's seen table without deleting anything.
func (p *DB) AbortSweep(adapterID string) error {
	if adapterID == "" {
		return errors.New("abort sweep: empty adapter id")
	}
	if _, ok := p.sweepSession(adapterID); !ok {
		return nil
	}
	if err := p.endSweep(adapterID); err != nil {
		return fmt.Errorf("abort sweep: %w", err)
	}
	return nil
}

// withdrawSQL finds the CVEs the adapter holds and those of them absent from
// _live_cves. held reads idx_statements_adapter; NOT EXISTS sits in a WHERE
// clause so it plans as an anti join.
const withdrawSQL = `
	WITH held AS MATERIALIZED (SELECT DISTINCT cve FROM statements WHERE adapter_id = $1),
	     gone AS (SELECT h.cve FROM held h
	              WHERE NOT EXISTS (SELECT 1 FROM _live_cves l WHERE l.cve = h.cve))
	SELECT (SELECT count(*) FROM held), (SELECT coalesce(array_agg(cve), '{}') FROM gone)`

// Withdraw deletes the adapter's rows of CVEs absent from liveCVEs, in one
// transaction under the sweep's session settings and time bound.
func (p *DB) Withdraw(adapterID string, liveCVEs []string, maxFraction float64) (db.WithdrawResult, error) {
	if adapterID == "" {
		return db.WithdrawResult{}, errors.New("withdraw: empty adapter id")
	}
	live := dedupe(liveCVEs)
	res := db.WithdrawResult{Live: int64(len(live))}
	if !(maxFraction > 0) {
		res.Refused, res.Reason = true, "withdraw disabled"
		return res, nil
	}
	if len(live) == 0 {
		res.Refused, res.Reason = true, "empty manifest"
		return res, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), sweepTimeout)
	defer cancel()
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return res, fmt.Errorf("withdraw: %w", err)
	}
	defer tx.Rollback(context.Background())
	if err := setSweepLocals(ctx, tx); err != nil {
		return res, fmt.Errorf("withdraw: %w", err)
	}
	// TEMP is fine here: one transaction, one connection. Autovacuum never
	// analyzes temp tables, hence the explicit ANALYZE.
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE _live_cves (cve TEXT NOT NULL) ON COMMIT DROP`); err != nil {
		return res, fmt.Errorf("withdraw: %w", err)
	}
	rows := make([][]any, 0, len(live))
	for _, c := range live {
		rows = append(rows, []any{c})
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"_live_cves"}, []string{"cve"}, pgx.CopyFromRows(rows)); err != nil {
		return res, fmt.Errorf("withdraw: load manifest: %w", err)
	}
	if _, err := tx.Exec(ctx, `ANALYZE _live_cves`); err != nil {
		return res, fmt.Errorf("withdraw: analyze: %w", err)
	}
	var held int64
	var gone []string
	if err := tx.QueryRow(ctx, withdrawSQL, adapterID).Scan(&held, &gone); err != nil {
		return res, fmt.Errorf("withdraw: %w", err)
	}
	res.HeldCVEs, res.WithdrawnCVEs = held, int64(len(gone))
	if maxFraction < 1 && float64(len(gone)) > maxFraction*float64(held) {
		res.Refused = true
		res.Reason = fmt.Sprintf("would withdraw %d of %d held CVEs (%.2f%%), over the %.2f%% limit",
			len(gone), held, 100*float64(len(gone))/float64(held), 100*maxFraction)
		return res, nil
	}
	if len(gone) > 0 {
		tag, err := tx.Exec(ctx, `DELETE FROM statements WHERE adapter_id = $1 AND cve = ANY($2::text[])`, adapterID, gone)
		if err != nil {
			return res, fmt.Errorf("withdraw: %w", err)
		}
		res.Deleted = tag.RowsAffected()
	}
	if err := tx.Commit(ctx); err != nil {
		return res, fmt.Errorf("withdraw: commit: %w", err)
	}
	return res, nil
}

// dedupe returns the distinct values of in, in first-seen order.
func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// ResetSweeps ends every open session and drops every seen table in the
// current schema — including ones a crashed process left behind, each tens of
// GB at Ubuntu scale. Each DROP runs behind a 30 s lock timeout (see
// sweepDDLTimeout); a table that cannot be dropped is reported in the error,
// and the rest are still dropped.
func (p *DB) ResetSweeps() error {
	p.sweepMu.Lock()
	p.sweepSeen = nil
	p.sweepMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), sweepDDLTimeout)
	defer cancel()
	// In LIKE `_` is a wildcard; escape it so only the real prefix matches.
	rows, err := p.pool.Query(ctx, `
		SELECT tablename FROM pg_tables
		WHERE schemaname = current_schema() AND tablename LIKE 'sweep\_seen\_%'`)
	if err != nil {
		return fmt.Errorf("reset sweeps: %w", err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return fmt.Errorf("reset sweeps: %w", err)
	}
	var errs []error
	for _, n := range names {
		if err := p.dropSeenTable(n); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("reset sweeps: %w", err)
	}
	return nil
}
