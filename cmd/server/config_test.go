package main

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const committedConfig = "../../config.yaml"

// TestCommittedConfigBuilds enforces the "config.yaml is the source of truth"
// invariant: the committed config must instantiate every adapter and alias
// fetcher cleanly, so a fresh deploy from the repo can't boot with a dormant or
// broken feed (e.g. an unknown adapter type, or a required field missing).
func TestCommittedConfigBuilds(t *testing.T) {
	registerAdapters()
	adapters, _, err := loadPipeline(committedConfig)
	if err != nil {
		t.Fatalf("loadPipeline(%s): %v", committedConfig, err)
	}
	if len(adapters) == 0 {
		t.Fatalf("%s built zero adapters", committedConfig)
	}
}

// TestRancherURLIsIndexNotConsolidated guards the v0.6.4 switch — and the
// config drift that left the committed file on the old URL through several
// releases. The Rancher adapter must point at index.json (the per-package
// walk), never the Git-LFS-backed consolidated reports/rancher.openvex.json.
// The danger is silent: repoCoords accepts the old URL and fetchIndex parses
// the OpenVEX doc as an empty index manifest, so a stale URL yields zero
// Rancher coverage with no error — exactly what a fresh deploy would do.
func TestRancherURLIsIndexNotConsolidated(t *testing.T) {
	data, err := os.ReadFile(committedConfig)
	if err != nil {
		t.Fatal(err)
	}
	var cfg serverConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, a := range cfg.Adapters {
		if a.Type != "rancher-vex" {
			continue
		}
		found = true
		if !strings.HasSuffix(a.URL, "/index.json") {
			t.Errorf("rancher-vex url = %q; must end in /index.json (per-package walk)", a.URL)
		}
		if strings.Contains(a.URL, "rancher.openvex.json") {
			t.Errorf("rancher-vex url = %q points at the deprecated LFS consolidated doc", a.URL)
		}
	}
	if !found {
		t.Fatal("no rancher-vex adapter in config.yaml")
	}
}
