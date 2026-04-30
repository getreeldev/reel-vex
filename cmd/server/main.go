package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/getreeldev/reel-vex/pkg/aliases"
	"github.com/getreeldev/reel-vex/pkg/api"
	"github.com/getreeldev/reel-vex/pkg/db"
	"github.com/getreeldev/reel-vex/pkg/ingest"
	"github.com/getreeldev/reel-vex/pkg/source"
	"github.com/getreeldev/reel-vex/pkg/source/csafadapter"
	"github.com/getreeldev/reel-vex/pkg/source/debianoval"
	"github.com/getreeldev/reel-vex/pkg/source/redhatoval"
	"github.com/getreeldev/reel-vex/pkg/source/ubuntuoval"
	"github.com/getreeldev/reel-vex/pkg/source/ubuntuvex"
)

// registerAdapters wires every known adapter and alias fetcher into their
// respective registries. Done once at program start so the rest of the code
// can resolve both purely through the factory functions.
func registerAdapters() {
	source.Register(csafadapter.Type, csafadapter.New)
	source.Register(redhatoval.Type, redhatoval.New)
	source.Register(ubuntuoval.Type, ubuntuoval.New)
	source.Register(ubuntuvex.Type, ubuntuvex.New)
	source.Register(debianoval.Type, debianoval.New)
	aliases.Register(aliases.RedHatRepoToCPEType, aliases.NewRedHatRepoToCPE)
}

// serverConfig is the top-level shape of config.yaml. Both adapters and
// alias fetchers are optional; an adapter-only config is valid (no alias
// enrichment), as is an alias-only config (rare but valid for backfill).
type serverConfig struct {
	Adapters []source.AdapterConfig `yaml:"adapters"`
	Aliases  []aliases.Config       `yaml:"aliases"`
}

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "config.yaml", "path to config file")
	dbPath := flag.String("db", "vex.db", "path to SQLite database")
	limit := flag.Int("limit", 0, "max statements per adapter (0 = unlimited)")
	addr := flag.String("addr", ":8080", "listen address for serve command")
	ingestInterval := flag.Duration("ingest-interval", 24*time.Hour, "interval between scheduled ingests")
	adminToken := flag.String("admin-token", "", "bearer token for admin endpoints (empty = no auth)")
	flag.Parse()

	registerAdapters()

	cmd := flag.Arg(0)
	switch cmd {
	case "serve":
		return runServe(*configPath, *dbPath, *addr, *ingestInterval, *adminToken)
	case "ingest":
		return runIngest(*configPath, *dbPath, *limit)
	case "stats":
		return runStats(*dbPath)
	case "query":
		cve := flag.Arg(1)
		if cve == "" {
			return fmt.Errorf("usage: reel-vex query <CVE-ID>")
		}
		return runQuery(*dbPath, cve)
	default:
		fmt.Fprintf(os.Stderr, "Usage: reel-vex [flags] <command>\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  serve     Start the HTTP API server\n")
		fmt.Fprintf(os.Stderr, "  ingest    Ingest CSAF VEX feeds into the database\n")
		fmt.Fprintf(os.Stderr, "  stats     Show database statistics\n")
		fmt.Fprintf(os.Stderr, "  query     Query VEX statements for a CVE\n")
		fmt.Fprintf(os.Stderr, "\nFlags:\n")
		flag.PrintDefaults()
		return nil
	}
}

func runIngest(configPath, dbPath string, limit int) error {
	adapters, fetchers, err := loadPipeline(configPath)
	if err != nil {
		return err
	}

	database, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer database.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	return ingest.Run(ctx, adapters, fetchers, database, ingest.Options{Limit: limit})
}

// loadPipeline reads the YAML config at configPath and instantiates every
// adapter and alias fetcher. Call registerAdapters() first.
func loadPipeline(configPath string) ([]source.Adapter, []aliases.Fetcher, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read config: %w", err)
	}
	var cfg serverConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, nil, fmt.Errorf("parse config: %w", err)
	}
	if len(cfg.Adapters) == 0 {
		return nil, nil, fmt.Errorf("config %s has no adapters; expected an `adapters:` list", configPath)
	}
	adapters, err := source.BuildAll(source.Config{Adapters: cfg.Adapters})
	if err != nil {
		return nil, nil, err
	}
	fetchers, err := aliases.BuildAll(cfg.Aliases)
	if err != nil {
		return nil, nil, err
	}
	return adapters, fetchers, nil
}

func runStats(dbPath string) error {
	database, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer database.Close()

	stats, err := database.Stats()
	if err != nil {
		return fmt.Errorf("get stats: %w", err)
	}

	fmt.Printf("Vendors:    %d\n", stats.Vendors)
	fmt.Printf("CVEs:       %d\n", stats.CVEs)
	fmt.Printf("Statements: %d\n", stats.Statements)
	return nil
}

func runServe(configPath, dbPath, addr string, ingestInterval time.Duration, adminToken string) error {
	adapters, fetchers, err := loadPipeline(configPath)
	if err != nil {
		return err
	}

	database, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer database.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ingestFn := func() error {
		return ingest.Run(ctx, adapters, fetchers, database, ingest.Options{})
	}
	runner := api.NewIngestRunner(ingestFn, ingestInterval, adminToken)

	srv := &http.Server{
		Addr:         addr,
		Handler:      api.NewServer(database, runner),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go runner.StartScheduler(ctx)

	go func() {
		<-ctx.Done()
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	slog.Info("starting server", "addr", addr, "ingest_interval", ingestInterval)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func runQuery(dbPath, cve string) error {
	database, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer database.Close()

	stmts, err := database.QueryStatements(db.QueryFilters{CVEs: []string{cve}})
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}

	if len(stmts) == 0 {
		fmt.Printf("No statements found for %s\n", cve)
		return nil
	}

	fmt.Printf("%s: %d statements\n\n", cve, len(stmts))
	for _, s := range stmts {
		just := ""
		if s.Justification != "" {
			just = fmt.Sprintf(" (%s)", s.Justification)
		}
		fmt.Printf("  [%s] %s %s%s\n", s.Vendor, s.Status, s.ProductID, just)
	}
	return nil
}
