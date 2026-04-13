package csaf

import (
	"bufio"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// FeedEntry is a single entry from changes.csv.
type FeedEntry struct {
	Path    string // e.g. "2024/cve-2024-6387.json" or "cve-2024-6387.json"
	Updated time.Time
}

// FetchFeedEntries fetches and parses changes.csv from a VEX distribution.
// If since is non-zero, only entries newer than since are returned.
// Returns entries in the order they appear in the file (vendor-dependent sorting).
func FetchFeedEntries(feedURL string, since time.Time) ([]FeedEntry, error) {
	csvURL := feedURL + "changes.csv"
	resp, err := http.Get(csvURL)
	if err != nil {
		return nil, fmt.Errorf("fetch changes.csv: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("changes.csv returned %d", resp.StatusCode)
	}

	var entries []FeedEntry
	scanner := bufio.NewScanner(resp.Body)
	// Some feeds are large (Red Hat ~15MB). Increase buffer.
	scanner.Buffer(make([]byte, 0, 1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		entry, err := parseCSVLine(line)
		if err != nil {
			continue // skip malformed lines
		}

		if !since.IsZero() && !entry.Updated.After(since) {
			// For newest-first feeds (Red Hat), we can stop early.
			// For oldest-first feeds (SUSE), we skip old entries.
			// To handle both: just filter.
			continue
		}

		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read changes.csv: %w", err)
	}

	return entries, nil
}

// parseCSVLine parses a line like: "2024/cve-2024-6387.json","2024-07-01T12:00:00+00:00"
func parseCSVLine(line string) (FeedEntry, error) {
	parts := strings.SplitN(line, ",", 2)
	if len(parts) != 2 {
		return FeedEntry{}, fmt.Errorf("invalid csv line")
	}

	path := strings.Trim(parts[0], "\"")
	tsStr := strings.Trim(parts[1], "\"")

	ts, err := time.Parse(time.RFC3339, tsStr)
	if err != nil {
		return FeedEntry{}, fmt.Errorf("parse timestamp %q: %w", tsStr, err)
	}

	return FeedEntry{Path: path, Updated: ts}, nil
}

// DocumentURL constructs the full URL for a feed entry.
func DocumentURL(feedURL string, entry FeedEntry) string {
	return feedURL + entry.Path
}
