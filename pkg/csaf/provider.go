package csaf

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Provider holds the discovered metadata for a CSAF provider.
type Provider struct {
	Name       string
	VEXFeedURL string // directory_url of the VEX distribution
}

// providerMetadata is the subset of provider-metadata.json we need.
type providerMetadata struct {
	Publisher struct {
		Name string `json:"name"`
	} `json:"publisher"`
	Distributions []distribution `json:"distributions"`
}

type distribution struct {
	DirectoryURL string `json:"directory_url"`
}

// DiscoverProvider fetches a CSAF provider-metadata.json and returns the VEX feed URL.
func DiscoverProvider(metadataURL string) (*Provider, error) {
	resp, err := http.Get(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("fetch provider metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider metadata returned %d", resp.StatusCode)
	}

	var meta providerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("decode provider metadata: %w", err)
	}

	// Find the VEX distribution (directory_url containing "vex")
	var vexURL string
	for _, d := range meta.Distributions {
		if d.DirectoryURL != "" && strings.Contains(strings.ToLower(d.DirectoryURL), "vex") {
			vexURL = d.DirectoryURL
			break
		}
	}
	if vexURL == "" {
		return nil, fmt.Errorf("no VEX distribution found in provider metadata")
	}

	// Ensure trailing slash
	if !strings.HasSuffix(vexURL, "/") {
		vexURL += "/"
	}

	return &Provider{
		Name:       meta.Publisher.Name,
		VEXFeedURL: vexURL,
	}, nil
}
