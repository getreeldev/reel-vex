package aliases

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/getreeldev/reel-vex/pkg/db"
)

// RedHatRepoToCPEType is the config `type:` string for Red Hat's
// repository-to-cpe mapping.
const RedHatRepoToCPEType = "redhat-repository-to-cpe"

// RedHatRepoToCPEDefaultURL is the public Red Hat mapping-file URL. Can be
// overridden per-deployment via config.
const RedHatRepoToCPEDefaultURL = "https://security.access.redhat.com/data/metrics/repository-to-cpe.json"

// NewRedHatRepoToCPE constructs the Red Hat repository-to-cpe fetcher.
// URL defaults to the public production URL if the config leaves it empty.
func NewRedHatRepoToCPE(cfg Config) (Fetcher, error) {
	if cfg.ID == "" {
		return nil, fmt.Errorf("%s: id required", RedHatRepoToCPEType)
	}
	url := cfg.URL
	if url == "" {
		url = RedHatRepoToCPEDefaultURL
	}
	return &redHatRepoToCPE{
		id:   cfg.ID,
		url:  url,
		http: &http.Client{Timeout: 60 * time.Second},
	}, nil
}

type redHatRepoToCPE struct {
	id   string
	url  string
	http *http.Client
}

func (f *redHatRepoToCPE) ID() string { return f.id }

// repoToCPESchema mirrors the file layout Red Hat publishes:
//
//	{"data": {"<repo_id>": {"cpes": ["cpe:/...", ...]}}}
//
// Other fields (e.g. repo_relative_urls) are ignored.
type repoToCPESchema struct {
	Data map[string]struct {
		CPEs []string `json:"cpes"`
	} `json:"data"`
}

func (f *redHatRepoToCPE) Fetch(ctx context.Context, database *db.DB) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return err
	}
	resp, err := f.http.Do(req)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", f.url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch %s: HTTP %d", f.url, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return f.parseAndUpsert(ctx, database, data)
}

// parseAndUpsert is split out so tests can pass fixture bytes without an
// HTTP server.
func (f *redHatRepoToCPE) parseAndUpsert(ctx context.Context, database *db.DB, raw []byte) error {
	var doc repoToCPESchema
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	if len(doc.Data) == 0 {
		return fmt.Errorf("parse: empty data map (malformed mapping file?)")
	}
	now := time.Now().UTC().Format(time.RFC3339)

	aliases := make([]db.Alias, 0, len(doc.Data))
	for repoID, entry := range doc.Data {
		for _, cpe := range entry.CPEs {
			aliases = append(aliases, db.Alias{
				Vendor:   f.id,
				SourceNS: "repository_id",
				SourceID: repoID,
				TargetNS: "cpe",
				TargetID: cpe,
				Updated:  now,
			})
		}
	}
	if err := database.BulkUpsertAliases(aliases); err != nil {
		return fmt.Errorf("upsert: %w", err)
	}
	slog.Info("alias fetch", "fetcher", f.id, "type", RedHatRepoToCPEType, "rows", len(aliases), "repos", len(doc.Data))
	return nil
}
