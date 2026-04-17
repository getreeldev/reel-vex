package source

// Config is the root of the adapter list in config.yaml.
type Config struct {
	Adapters []AdapterConfig `yaml:"adapters"`
}

// AdapterConfig is one adapter's configuration. Type selects the factory
// registered for that format; other fields are interpreted by each adapter
// (e.g. CSAF reads URL as the provider-metadata.json location).
type AdapterConfig struct {
	Type string `yaml:"type"`           // "csaf", "redhat-oval", ...
	ID   string `yaml:"id"`             // vendor identifier: "redhat", "suse"
	Name string `yaml:"name,omitempty"` // human-readable name
	URL  string `yaml:"url,omitempty"`  // adapter-specific entry-point URL
}
