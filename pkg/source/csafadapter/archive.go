package csafadapter

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/getreeldev/reel-vex/pkg/csaf"
	"github.com/getreeldev/reel-vex/pkg/source"
	"github.com/getreeldev/reel-vex/pkg/source/httpretry"
	"github.com/klauspost/compress/zstd"
)

// archiveLatestFile sits next to changes.csv and holds the filename of the
// current weekly bulk archive, e.g. "csaf_vex_2026-05-23.tar.zst". Red Hat
// publishes it; vendors without it (e.g. SUSE) return 404 and we fall back to
// the per-document changes.csv crawl.
const archiveLatestFile = "archive_latest.txt"

// archiveHTTPTimeout bounds the bulk-archive download. The default per-document
// client uses 60s, far too tight for a ~300 MB body.
const archiveHTTPTimeout = 10 * time.Minute

// syncFromArchive performs a one-shot bulk cold-start: it downloads the
// vendor's full CSAF VEX archive (one ~300 MB tar.zst instead of ~70K
// per-document GETs that take hours), walks it locally, and emits every
// statement, each document dated by its own current_release_date. It skips
// every document the given changes.csv entries date after the archive's cut
// (all of them when the cut date is unknown): the archive holds an older copy
// of those, and the caller fetches them fresh. refreshed is called with the
// path of every entry fully emitted, including entries that yield no
// statements; it is called as the walk goes, so the entries read before a
// part-way failure have already been reported. An entry that fails to extract
// is logged and not reported, so the caller fetches it from the feed; the
// returned count is of failed entries whose name carries no CVE, which nothing
// can read again.
//
// No archive published for this feed returns (0, nil). A non-nil error means
// an archive existed but processing failed; the caller crawls what it did not
// read. An error from emit is returned as is.
func (a *Adapter) syncFromArchive(ctx context.Context, entries []csaf.FeedEntry, emit func(source.Statement) error, refreshed func(docPath string)) (unreadable int, err error) {
	name, err := a.fetchArchiveName(ctx)
	if err != nil {
		return 0, err
	}
	if name == "" {
		return 0, nil // no archive published -> caller crawls
	}
	archiveDate := parseArchiveDate(name)

	slog.Info("csaf bulk archive: downloading", "adapter", a.id, "file", name)
	body, lastModified, err := a.fetchArchiveBytes(ctx, a.feedURL+name)
	if err != nil {
		return 0, fmt.Errorf("download archive %s: %w", name, err)
	}
	// Prefer the filename date; fall back to the archive's Last-Modified so a
	// filename-format change can't silently zero the cut date (which then
	// skips every changes.csv document, the slow but gap-free path).
	if archiveDate.IsZero() {
		archiveDate = lastModified
	}
	fresh := map[string]struct{}{}
	for _, e := range entries {
		if archiveDate.IsZero() || e.Updated.After(archiveDate) {
			if cve := docCVE(e.Path); cve != "" {
				fresh[cve] = struct{}{}
			}
		}
	}
	slog.Info("csaf bulk archive: walking", "adapter", a.id, "compressed_bytes", len(body), "changed_since_cut", len(fresh))

	zr, err := zstd.NewReader(bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("zstd reader: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)

	// Each archived document is dated by its own
	// document.tracking.current_release_date, the date the vendor last changed
	// it; the archive date is only the fallback for a document without a
	// readable one.
	fallback := archiveDate
	if fallback.IsZero() {
		fallback = time.Now().UTC()
	}

	var docs, emitted, skipped, stale int
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("tar walk: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || !strings.HasSuffix(hdr.Name, ".json") {
			continue
		}
		cve := docCVE(hdr.Name)
		if _, ok := fresh[cve]; ok {
			stale++
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return 0, fmt.Errorf("read %s: %w", hdr.Name, err)
		}
		if err := checkDocument(data, cve); err != nil {
			slog.Warn("csaf archive entry refused", "adapter", a.id, "entry", hdr.Name, "error", err)
			skipped++
			if cve == "" {
				unreadable++
			}
			continue
		}
		stmts, err := csaf.Extract(data)
		if err != nil {
			slog.Warn("csaf archive extract failed", "adapter", a.id, "entry", hdr.Name, "error", err)
			skipped++
			if cve == "" {
				unreadable++
			}
			continue
		}
		docs++
		if err := emitStatements(stmts, releaseDate(data, fallback), emit); err != nil {
			return 0, err
		}
		emitted += len(stmts)
		refreshed(hdr.Name)
		if docs%20000 == 0 {
			slog.Info("csaf bulk archive progress", "adapter", a.id, "docs", docs, "emitted", emitted)
		}
	}
	slog.Info("csaf bulk archive: done", "adapter", a.id, "docs", docs, "emitted", emitted, "skipped", skipped,
		"changed_since_cut", stale, "archive_date", archiveDate.Format("2006-01-02"))
	return unreadable, nil
}

// fetchArchiveName reads archive_latest.txt; "" (nil error) means not published.
func (a *Adapter) fetchArchiveName(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.feedURL+archiveLatestFile, nil)
	if err != nil {
		return "", err
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", nil // feed has no bulk archive
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("archive_latest.txt: HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(string(b))
	// Guard against junk / path traversal — must be a bare archive filename.
	if !strings.HasSuffix(name, ".tar.zst") || strings.ContainsAny(name, "/\\") {
		return "", nil
	}
	return name, nil
}

// fetchArchiveBytes downloads the archive fully into memory. Buffering (rather
// than streaming HTTP->zstd->tar) keeps the multi-minute local walk from
// holding the HTTP connection past its deadline — same rationale as ubuntuvex.
func (a *Adapter) fetchArchiveBytes(ctx context.Context, url string) ([]byte, time.Time, error) {
	cl := &http.Client{Timeout: archiveHTTPTimeout, Transport: httpretry.New(nil)}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, time.Time{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	lastModified, _ := http.ParseTime(resp.Header.Get("Last-Modified"))
	body, err := io.ReadAll(resp.Body)
	return body, lastModified.UTC(), err
}

// releaseDate returns a CSAF document's document.tracking.current_release_date
// in UTC, or fallback when the document has none that parses as RFC 3339.
func releaseDate(data []byte, fallback time.Time) time.Time {
	var doc struct {
		Document struct {
			Tracking struct {
				CurrentReleaseDate string `json:"current_release_date"`
			} `json:"tracking"`
		} `json:"document"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fallback
	}
	t, err := time.Parse(time.RFC3339, doc.Document.Tracking.CurrentReleaseDate)
	if err != nil {
		return fallback
	}
	return t.UTC()
}

// parseArchiveDate extracts the date from "csaf_vex_2026-05-23.tar.zst".
// Returns zero time if the name doesn't match the expected shape.
func parseArchiveDate(name string) time.Time {
	s := strings.TrimSuffix(strings.TrimPrefix(name, "csaf_vex_"), ".tar.zst")
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}
