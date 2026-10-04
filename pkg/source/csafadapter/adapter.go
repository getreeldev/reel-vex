// Package csafadapter implements source.Adapter for CSAF 2.0 VEX feeds.
// It delegates CSAF parsing to pkg/csaf; this package only owns the
// orchestration glue (discover, walk changes.csv, fetch, emit).
package csafadapter

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/getreeldev/reel-vex/pkg/csaf"
	"github.com/getreeldev/reel-vex/pkg/source"
	"github.com/getreeldev/reel-vex/pkg/source/httpretry"
)

// Type is the adapter-type string used in config.yaml.
const Type = "csaf"

// New constructs a CSAF adapter from its config entry.
func New(cfg source.AdapterConfig) (source.Adapter, error) {
	if cfg.ID == "" {
		return nil, fmt.Errorf("csaf adapter: id required")
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("csaf adapter %q: url required (should point to provider-metadata.json)", cfg.ID)
	}
	return &Adapter{
		id:          cfg.ID,
		name:        cfg.Name,
		metadataURL: cfg.URL,
		http:        &http.Client{Timeout: 60 * time.Second, Transport: httpretry.New(nil)},
	}, nil
}

// Adapter streams statements from a CSAF 2.0 provider-metadata.json feed.
type Adapter struct {
	id          string
	name        string
	metadataURL string

	// Cached after Discover. Empty until then.
	feedURL string

	http *http.Client
}

func (a *Adapter) ID() string { return a.id }

// Vendor returns the vendor identifier for emitted statements. For CSAF
// adapters the adapter ID IS the vendor (one CSAF adapter per vendor is
// the canonical model). If a deployment ever runs multiple CSAF adapters
// for the same vendor, they'd need distinct IDs and an explicit vendor
// config field — which we can add additively when that use case arrives.
func (a *Adapter) Vendor() string       { return a.id }
func (a *Adapter) Name() string         { return a.name }
func (a *Adapter) SourceFormat() string { return "csaf" }

// Discover resolves the provider-metadata.json, records the VEX feed URL,
// and — if the config left Name empty — picks up the publisher name from
// the metadata.
func (a *Adapter) Discover(ctx context.Context) (*source.FeedInfo, error) {
	p, err := csaf.DiscoverProvider(a.http, a.metadataURL)
	if err != nil {
		return nil, fmt.Errorf("discover %s: %w", a.id, err)
	}
	if a.name == "" {
		a.name = p.Name
	}
	a.feedURL = p.VEXFeedURL
	return &source.FeedInfo{FeedURL: p.VEXFeedURL}, nil
}

// Sync walks the feed's changes.csv and fetches each referenced CSAF
// document, extracting VEX statements. Per-document fetch and parse errors
// are logged and skipped so that one broken advisory doesn't abort the
// whole run; a run with any such skip reports itself incomplete, and the
// skipped document is left out of RefreshedCVEs. It reads changes.csv and the
// distribution's index.txt first, back to back, so the two describe one moment
// of the feed. A cold start reads every document exactly once — from the bulk
// archive when the archive's copy is current, else from the feed — and then
// every index.txt document neither of those read; it is Complete only when it
// read every document index.txt lists.
func (a *Adapter) Sync(ctx context.Context, since time.Time, emit func(source.Statement) error) (source.SyncResult, error) {
	if a.feedURL == "" {
		if _, err := a.Discover(ctx); err != nil {
			return source.SyncResult{}, err
		}
	}
	coldStart := since.IsZero()

	entries, skippedLines, err := csaf.FetchFeedEntries(a.http, a.feedURL, since)
	if err != nil {
		return source.SyncResult{}, fmt.Errorf("fetch changes.csv: %w", err)
	}
	var failed int
	if skippedLines > 0 {
		// A line that does not parse may name a document this run never reads.
		slog.Warn("csaf changes.csv lines unparseable; skipped", "adapter", a.id, "skipped_lines", skippedLines)
		failed += skippedLines
	}
	livePaths := a.fetchLiveIndex(ctx)

	// emit's own error is recorded so the cold-start fallback below can tell
	// "the orchestrator refused a statement" (return it) from "the archive
	// is broken" (crawl instead). errors.Is cannot: emit returns anything.
	var emitErr error
	emitRecorded := func(s source.Statement) error {
		if err := emit(s); err != nil {
			emitErr = err
			return err
		}
		return nil
	}

	// refreshed holds the CVEs of the documents fully read this run, from the
	// archive or the feed; fetched those read from the feed itself; attempted
	// those the feed was asked for, read or not, so none is asked for twice.
	refreshed := map[string]struct{}{}
	fetched := map[string]struct{}{}
	attempted := map[string]struct{}{}
	markRefreshed := func(docPath string) {
		if cve := docCVE(docPath); cve != "" {
			refreshed[cve] = struct{}{}
		}
	}

	// A document listed twice in changes.csv is read once, dated by its
	// newest line.
	newestLine := map[string]time.Time{}
	var newestEntry time.Time
	for _, e := range entries {
		if cve := docCVE(e.Path); cve != "" && e.Updated.After(newestLine[cve]) {
			newestLine[cve] = e.Updated
		}
		if e.Updated.After(newestEntry) {
			newestEntry = e.Updated
		}
	}

	// Cold start: try the bulk archive (one ~300 MB tar.zst) instead of
	// crawling ~70K documents one HTTP GET at a time (hours). The archive is a
	// weekly cut, so it skips every document changes.csv dates after the cut:
	// emitting the archive's old copy as well as the feed's current one would
	// make both versions' rows "seen", and the old verdicts would survive the
	// sweep. The crawl below then reads every changes.csv document the archive
	// did not — the post-cut delta when the archive was read whole, everything
	// after the point it broke when it failed part-way, and any entry that
	// failed to extract. Feeds without an archive (e.g. SUSE) crawl it all.
	if coldStart {
		unreadable, err := a.syncFromArchive(ctx, entries, emitRecorded, markRefreshed)
		switch {
		case emitErr != nil:
			return source.SyncResult{}, emitErr
		case ctx.Err() != nil:
			return source.SyncResult{}, ctx.Err()
		case err != nil:
			// Documents the archive fully read before failing are current (it
			// skipped every one changes.csv dates after the cut) and stay read.
			slog.Warn("csaf bulk archive failed; crawling the documents it did not read", "adapter", a.id, "error", err)
		default:
			failed += unreadable
		}
	}

	for i, entry := range entries {
		if err := ctx.Err(); err != nil {
			return source.SyncResult{}, err
		}
		cve := docCVE(entry.Path)
		if cve != "" {
			if _, ok := refreshed[cve]; ok {
				continue // read from the archive, whose copy is current
			}
			if _, ok := attempted[cve]; ok {
				continue
			}
			attempted[cve] = struct{}{}
			entry.Updated = newestLine[cve]
		}
		ok, err := a.readDocument(ctx, entry.Path, entry.Updated, emit)
		if err != nil {
			return source.SyncResult{}, err
		}
		if !ok {
			failed++
			continue
		}
		// A document with no statements still refreshes: the vendor
		// re-published it with nothing in it, so its old rows are gone.
		markRefreshed(entry.Path)
		if cve != "" {
			fetched[cve] = struct{}{}
		}
		if i > 0 && i%100 == 0 {
			slog.Info("csaf progress", "adapter", a.id, "processed", i, "of", len(entries))
		}
	}

	// A cold start also reads every live document changes.csv does not list
	// and the archive did not hold (Red Hat had 6 such in 2026-10), by its
	// index.txt path, dated by its own current_release_date.
	if coldStart && livePaths != nil {
		fallback := newestEntry
		if fallback.IsZero() {
			fallback = time.Now().UTC()
		}
		var extra int
		for _, p := range livePaths {
			if err := ctx.Err(); err != nil {
				return source.SyncResult{}, err
			}
			cve := docCVE(p)
			if _, ok := refreshed[cve]; ok {
				continue
			}
			if _, ok := attempted[cve]; ok {
				continue
			}
			attempted[cve] = struct{}{}
			extra++
			ok, err := a.readDocument(ctx, p, time.Time{}, func(s source.Statement) error {
				if s.Updated.IsZero() {
					s.Updated = fallback
				}
				return emit(s)
			})
			if err != nil {
				return source.SyncResult{}, err
			}
			if !ok {
				failed++
				continue
			}
			markRefreshed(p)
			fetched[cve] = struct{}{}
		}
		if extra > 0 {
			slog.Info("csaf index.txt documents changes.csv does not list", "adapter", a.id, "read", extra)
		}
	}

	// A manifest that lacks a document this run just fetched from the same
	// feed is not a list of every live document: the vendor may be rewriting
	// it. Archive-read documents are not checked, because the archive is a
	// week old and holds documents withdrawn since.
	live := cvesOf(livePaths)
	if live != nil {
		inLive := make(map[string]struct{}, len(live))
		for _, cve := range live {
			inLive[cve] = struct{}{}
		}
		var missing []string
		for cve := range fetched {
			if _, ok := inLive[cve]; !ok {
				missing = append(missing, cve)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			slog.Warn("csaf index.txt lacks documents fetched this run; no live manifest this run",
				"adapter", a.id, "missing", len(missing), "first", missing[0])
			live = nil
		}
	}

	// Complete needs the manifest, and every document it lists read.
	complete := coldStart && failed == 0 && live != nil
	for _, cve := range live {
		if _, ok := refreshed[cve]; !ok {
			complete = false
			break
		}
	}
	res := source.SyncResult{
		Complete:      complete,
		RefreshedCVEs: make([]string, 0, len(refreshed)),
		LiveCVEs:      live,
	}
	for cve := range refreshed {
		res.RefreshedCVEs = append(res.RefreshedCVEs, cve)
	}
	sort.Strings(res.RefreshedCVEs)
	if failed > 0 {
		slog.Warn("csaf sync skipped documents on error; run is incomplete", "adapter", a.id, "failed", failed)
	}
	return res, nil
}

// readDocument fetches one document by its path under the feed, checks it is
// the CSAF document the path names, and emits its statements dated updated —
// or, when updated is zero, by the document's own current_release_date (zero
// when it has none; the caller's emit dates those). It returns false, logged,
// when the document could not be read, and an error only from emit.
func (a *Adapter) readDocument(ctx context.Context, docPath string, updated time.Time, emit func(source.Statement) error) (bool, error) {
	docURL := a.feedURL + docPath
	data, err := a.fetchDocument(ctx, docURL)
	if err != nil {
		slog.Warn("csaf fetch failed", "adapter", a.id, "url", docURL, "error", err)
		return false, nil
	}
	if err := checkDocument(data, docCVE(docPath)); err != nil {
		slog.Warn("csaf document refused", "adapter", a.id, "url", docURL, "error", err)
		return false, nil
	}
	stmts, err := csaf.Extract(data)
	if err != nil {
		slog.Warn("csaf extract failed", "adapter", a.id, "url", docURL, "error", err)
		return false, nil
	}
	if updated.IsZero() {
		updated = releaseDate(data, time.Time{})
	}
	return true, emitStatements(stmts, updated, emit)
}

// emitStatements emits a document's statements, each dated updated.
func emitStatements(stmts []csaf.Statement, updated time.Time, emit func(source.Statement) error) error {
	for _, s := range stmts {
		if err := emit(source.Statement{
			CVE:           s.CVE,
			ProductID:     s.ProductID,
			BaseID:        s.BaseID,
			Version:       s.Version,
			IDType:        s.IDType,
			Status:        s.Status,
			Justification: s.Justification,
			Updated:       updated,
		}); err != nil {
			return err
		}
	}
	return nil
}

// checkDocument refuses a body that is not the CSAF document for cve: an
// HTTP 200 carrying an error object ({"message":"Service Unavailable"}) or
// an empty one extracts to zero statements without error, and counted as
// refreshed it would delete every row of that CVE. A CSAF document has a
// document.csaf_version and a document.tracking.id, and the document for a CVE
// names it as its tracking id (Red Hat and SUSE both do) or in its
// vulnerabilities — about a fifth of SUSE's documents carry no vulnerabilities
// array at all and are a valid "nothing stated". cve "" (a path that names no
// CVE) checks the shape only.
func checkDocument(data []byte, cve string) error {
	var doc struct {
		Document *struct {
			CSAFVersion string `json:"csaf_version"`
			Tracking    *struct {
				ID string `json:"id"`
			} `json:"tracking"`
		} `json:"document"`
		Vulnerabilities []struct {
			CVE string `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("not a CSAF document: %w", err)
	}
	if doc.Document == nil || doc.Document.CSAFVersion == "" || doc.Document.Tracking == nil || doc.Document.Tracking.ID == "" {
		return errors.New("not a CSAF document: no document.csaf_version or document.tracking.id")
	}
	if cve == "" || strings.EqualFold(doc.Document.Tracking.ID, cve) {
		return nil
	}
	for _, v := range doc.Vulnerabilities {
		if strings.EqualFold(v.CVE, cve) {
			return nil
		}
	}
	return fmt.Errorf("document %q does not name %s", doc.Document.Tracking.ID, cve)
}

// cveDocName matches a CSAF VEX document's file name, e.g. "cve-2024-6387.json".
var cveDocName = regexp.MustCompile(`(?i)^cve-\d{4}-\d+\.json$`)

// docCVE returns the upper-cased CVE id a document path names, or "" when it
// names none. Red Hat paths carry a year directory ("2024/cve-2024-6387.json"),
// SUSE's do not, and archive entries are prefixed "csaf_vex_<date>/"; only the
// base name matters.
func docCVE(docPath string) string {
	base := path.Base(docPath)
	if !cveDocName.MatchString(base) {
		return ""
	}
	return strings.ToUpper(base[:len(base)-len(".json")])
}

// liveIndexFile sits next to changes.csv and lists the path of every document
// the distribution currently publishes, one per line.
const liveIndexFile = "index.txt"

// fetchLiveIndex reads index.txt into the paths of the CVE documents it
// lists. It never fails the sync: when the file cannot be fetched or read, or
// names no CVE document at all, it logs a warning and returns nil ("no
// manifest this run"), never an empty slice.
func (a *Adapter) fetchLiveIndex(ctx context.Context) []string {
	indexURL := a.feedURL + liveIndexFile
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, indexURL, nil)
	if err != nil {
		slog.Warn("csaf index.txt unreadable; no live manifest this run", "adapter", a.id, "error", err)
		return nil
	}
	resp, err := a.http.Do(req)
	if err != nil {
		slog.Warn("csaf index.txt unreadable; no live manifest this run", "adapter", a.id, "url", indexURL, "error", err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		slog.Warn("csaf index.txt unreadable; no live manifest this run", "adapter", a.id, "url", indexURL, "status", resp.StatusCode)
		return nil
	}

	var (
		live    []string
		skipped int
	)
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if docCVE(line) == "" {
			skipped++
			continue
		}
		live = append(live, line)
	}
	if err := scanner.Err(); err != nil {
		slog.Warn("csaf index.txt unreadable; no live manifest this run", "adapter", a.id, "url", indexURL, "error", err)
		return nil
	}
	if len(live) == 0 {
		slog.Warn("csaf index.txt names no CVE document; no live manifest this run", "adapter", a.id, "url", indexURL, "skipped_lines", skipped)
		return nil
	}
	slog.Info("csaf index.txt read", "adapter", a.id, "live", len(live), "skipped_lines", skipped)
	return live
}

// cvesOf returns the CVE ids the index paths name, nil for nil.
func cvesOf(paths []string) []string {
	if paths == nil {
		return nil
	}
	cves := make([]string, len(paths))
	for i, p := range paths {
		cves[i] = docCVE(p)
	}
	return cves
}

func (a *Adapter) fetchDocument(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
