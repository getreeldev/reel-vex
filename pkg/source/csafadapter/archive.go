package csafadapter

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/getreeldev/reel-vex/pkg/csaf"
	"github.com/getreeldev/reel-vex/pkg/source"
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
// vendor's full CSAF VEX archive (one ~300 MB tar.zst instead of ~317K
// per-document GETs that take hours), walks it locally, and emits every
// statement. Returns the archive's date — the floor for the follow-up
// changes.csv delta — and ok=true if an archive was found and processed.
//
// ok=false with nil error means no archive is published for this feed; the
// caller falls back to the full changes.csv crawl. A non-nil error means an
// archive existed but processing failed; the caller may also fall back.
func (a *Adapter) syncFromArchive(ctx context.Context, emit func(source.Statement) error) (archiveDate time.Time, ok bool, err error) {
	name, err := a.fetchArchiveName(ctx)
	if err != nil {
		return time.Time{}, false, err
	}
	if name == "" {
		return time.Time{}, false, nil // no archive published -> caller crawls
	}
	archiveDate = parseArchiveDate(name)

	slog.Info("csaf bulk archive: downloading", "adapter", a.id, "file", name)
	body, lastModified, err := a.fetchArchiveBytes(ctx, a.feedURL+name)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("download archive %s: %w", name, err)
	}
	// Prefer the filename date; fall back to the archive's Last-Modified so a
	// filename-format change can't silently zero the delta floor (which would
	// otherwise skip the post-archive changes.csv crawl and leave a gap).
	if archiveDate.IsZero() {
		archiveDate = lastModified
	}
	slog.Info("csaf bulk archive: walking", "adapter", a.id, "compressed_bytes", len(body))

	zr, err := zstd.NewReader(bytes.NewReader(body))
	if err != nil {
		return time.Time{}, false, fmt.Errorf("zstd reader: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)

	// All archive docs share the archive date as their Updated timestamp; the
	// follow-up changes.csv delta (since archiveDate) refreshes any that changed
	// after the archive was cut, with their precise dates.
	updated := archiveDate
	if updated.IsZero() {
		updated = time.Now().UTC()
	}

	var docs, emitted int
	for {
		if err := ctx.Err(); err != nil {
			return time.Time{}, false, err
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return time.Time{}, false, fmt.Errorf("tar walk: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || !strings.HasSuffix(hdr.Name, ".json") {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return time.Time{}, false, fmt.Errorf("read %s: %w", hdr.Name, err)
		}
		stmts, err := csaf.Extract(data)
		if err != nil {
			slog.Warn("csaf archive extract failed", "adapter", a.id, "entry", hdr.Name, "error", err)
			continue
		}
		docs++
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
				return time.Time{}, false, err
			}
			emitted++
		}
		if docs%20000 == 0 {
			slog.Info("csaf bulk archive progress", "adapter", a.id, "docs", docs, "emitted", emitted)
		}
	}
	slog.Info("csaf bulk archive: done", "adapter", a.id, "docs", docs, "emitted", emitted, "archive_date", archiveDate.Format("2006-01-02"))
	return archiveDate, true, nil
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
	cl := &http.Client{Timeout: archiveHTTPTimeout}
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
