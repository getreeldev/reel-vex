package source

import "fmt"

// Factory constructs an Adapter from its AdapterConfig.
type Factory func(cfg AdapterConfig) (Adapter, error)

var factories = map[string]Factory{}

// Register associates a factory with a Type string. Call once per adapter
// type from the entry-point (cmd/server/main.go). Not safe for concurrent
// use with New.
func Register(adapterType string, f Factory) {
	factories[adapterType] = f
}

// New looks up the factory for cfg.Type and constructs the adapter.
func New(cfg AdapterConfig) (Adapter, error) {
	f, ok := factories[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("unknown adapter type %q (did you call source.Register?)", cfg.Type)
	}
	return f(cfg)
}

// BuildAll instantiates every adapter in cfg in configured order. First
// construction error aborts; no adapter starts until all succeed.
func BuildAll(cfg Config) ([]Adapter, error) {
	adapters := make([]Adapter, 0, len(cfg.Adapters))
	for _, ac := range cfg.Adapters {
		a, err := New(ac)
		if err != nil {
			return nil, fmt.Errorf("adapter %q: %w", ac.ID, err)
		}
		adapters = append(adapters, a)
	}
	return adapters, nil
}
