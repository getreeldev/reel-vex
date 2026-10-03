// Package csafadapter implements source.Adapter for CSAF 2.0 VEX feeds.
// It delegates CSAF parsing to pkg/csaf; this package only owns the
// orchestration glue (discover, walk changes.csv, fetch, emit).
package csafadapter

import (
	"bufio"
	"context"
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
// skipped document is left out of RefreshedCVEs. After the documents it reads
// the distribution's index.txt into LiveCVEs.
func (a *Adapter) Sync(ctx context.Context, since time.Time, emit func(source.Statement) error) (source.SyncResult, error) {
	if a.feedURL == "" {
		if _, err := a.Discover(ctx); err != nil {
			return source.SyncResult{}, err
		}
	}

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

	refreshed := map[string]struct{}{}
	markRefreshed := func(docPath string) {
		if cve := docCVE(docPath); cve != "" {
			refreshed[cve] = struct{}{}
		}
	}
	var failed int

	// Cold start: try the bulk archive (one ~300 MB tar.zst) instead of
	// crawling ~317K documents one HTTP GET at a time (hours). On success the
	// archive seeds everything up to its weekly cut date, and we then fetch
	// only the post-archive delta via changes.csv. Feeds without an archive
	// (e.g. SUSE) fall through to the full crawl unchanged.
	effectiveSince := since
	if since.IsZero() {
		archiveDate, ok, skipped, err := a.syncFromArchive(ctx, emitRecorded, markRefreshed)
		switch {
		case emitErr != nil:
			return source.SyncResult{}, emitErr
		case ctx.Err() != nil:
			return source.SyncResult{}, ctx.Err()
		case err != nil:
			// Documents the archive fully read before failing stay refreshed;
			// its skips do not count, because the crawl re-reads everything.
			slog.Warn("csaf bulk archive failed; falling back to full changes.csv crawl", "adapter", a.id, "error", err)
		case ok:
			// archiveDate is the delta floor. It comes from the filename, or
			// the archive's Last-Modified as a fallback. Only if BOTH are
			// unavailable is it zero — in which case we deliberately leave
			// effectiveSince zero so the changes.csv crawl runs in full. That's
			// slow, but it guarantees no silent coverage gap (jumping to now()
			// would skip every advisory changed before this run).
			effectiveSince = archiveDate
			failed += skipped
		}
	}

	entries, err := csaf.FetchFeedEntries(a.http, a.feedURL, effectiveSince)
	if err != nil {
		return source.SyncResult{}, fmt.Errorf("fetch changes.csv: %w", err)
	}

	for i, entry := range entries {
		if err := ctx.Err(); err != nil {
			return source.SyncResult{}, err
		}
		docURL := csaf.DocumentURL(a.feedURL, entry)
		data, err := a.fetchDocument(ctx, docURL)
		if err != nil {
			slog.Warn("csaf fetch failed", "adapter", a.id, "url", docURL, "error", err)
			failed++
			continue
		}
		stmts, err := csaf.Extract(data)
		if err != nil {
			slog.Warn("csaf extract failed", "adapter", a.id, "url", docURL, "error", err)
			failed++
			continue
		}
		for _, s := range stmts {
			if err := emit(source.Statement{
				CVE:           s.CVE,
				ProductID:     s.ProductID,
				BaseID:        s.BaseID,
				Version:       s.Version,
				IDType:        s.IDType,
				Status:        s.Status,
				Justification: s.Justification,
				Updated:       entry.Updated,
			}); err != nil {
				return source.SyncResult{}, err
			}
		}
		// A document with no statements still refreshes: the vendor
		// re-published it with nothing in it, so its old rows are gone.
		markRefreshed(entry.Path)
		if i > 0 && i%100 == 0 {
			slog.Info("csaf progress", "adapter", a.id, "processed", i, "of", len(entries))
		}
	}

	res := source.SyncResult{
		Complete:      since.IsZero() && failed == 0,
		RefreshedCVEs: make([]string, 0, len(refreshed)),
		LiveCVEs:      a.fetchLiveCVEs(ctx),
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

// fetchLiveCVEs reads index.txt into CVE ids. It never fails the sync: when
// the file cannot be fetched or read, or names no CVE at all, it logs a
// warning and returns nil ("no manifest this run"), never an empty slice.
func (a *Adapter) fetchLiveCVEs(ctx context.Context) []string {
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
		cve := docCVE(line)
		if cve == "" {
			skipped++
			continue
		}
		live = append(live, cve)
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
