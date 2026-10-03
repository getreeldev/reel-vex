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

// TestRancherURLIsSnapshotTarball guards the rancher-vex url in the committed
// config: the adapter reads the repository snapshot tarball the hub's
// vex-repository.json names, and a URL still pointing at the old index.json
// walk (or the Git-LFS-backed consolidated rancher.openvex.json) fails every
// Rancher sync. It must be the bare .tar.gz, not the spec's go-getter form
// ending in //vexhub-main.
func TestRancherURLIsSnapshotTarball(t *testing.T) {
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
		if !strings.HasSuffix(a.URL, ".tar.gz") {
			t.Errorf("rancher-vex url = %q; must end in .tar.gz (the repository snapshot)", a.URL)
		}
	}
	if !found {
		t.Fatal("no rancher-vex adapter in config.yaml")
	}
}
