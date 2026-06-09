package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/getreeldev/reel-vex/pkg/aliases"
	"github.com/getreeldev/reel-vex/pkg/api"
	"github.com/getreeldev/reel-vex/pkg/db"
	"github.com/getreeldev/reel-vex/pkg/db/postgres"
	"github.com/getreeldev/reel-vex/pkg/ingest"
	"github.com/getreeldev/reel-vex/pkg/source"
	"github.com/getreeldev/reel-vex/pkg/source/alpinesecdb"
	"github.com/getreeldev/reel-vex/pkg/source/amazonalas"
	"github.com/getreeldev/reel-vex/pkg/source/csafadapter"
	"github.com/getreeldev/reel-vex/pkg/source/debianoval"
	"github.com/getreeldev/reel-vex/pkg/source/ranchervex"
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
	source.Register(ranchervex.Type, ranchervex.New)
	source.Register(alpinesecdb.Type, alpinesecdb.New)
	source.Register(amazonalas.Type, amazonalas.New)
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
	dbPath := flag.String("db", "", "Postgres connection URL (postgres://user:pass@host:5432/db?sslmode=...) — required")
	limit := flag.Int("limit", 0, "max statements per adapter (0 = unlimited)")
	addr := flag.String("addr", ":8080", "listen address for serve command")
	ingestInterval := flag.Duration("ingest-interval", 24*time.Hour, "interval between scheduled ingests")
	adminToken := flag.String("admin-token", "", "bearer token for admin endpoints (empty = no auth)")
	sbomMaxMB := flag.Int("sbom-max-mb", 10, "max body size in MB for SBOM-accepting endpoints (/v1/analyze, /v1/statements)")
	statementsMax := flag.Int("statements-max", 50000, "max statements returned by /v1/statements (0 = unlimited); broad mode is truncated with HTTP 200 + X-Reel-Truncated header when hit")
	analyzeMaxCVEs := flag.Int("analyze-max-cves", 10000, "max distinct CVEs a /v1/analyze request may query before a 400; a cheap up-front reject (the covering index keeps the query base-bound; -query-timeout is the real backstop). Aligned with -max-sbom-vulns. Host-tunable.")
	queryTimeout := flag.Duration("query-timeout", 20*time.Second, "hard ceiling on a single DB statement query; an over-broad request returns 503 when hit. Raise on dedicated hardware.")
	maxSBOMComponents := flag.Int("max-sbom-components", 50000, "max components in an inbound SBOM before a 400")
	maxSBOMVulns := flag.Int("max-sbom-vulns", 10000, "max vulnerabilities in an inbound SBOM before a 400")
	maxStatementsItems := flag.Int("max-statements-items", 10000, "max items in the cves/products arrays on /v1/statements before a 400")
	maxUserVEXStatements := flag.Int("max-user-vex-statements", 25000, "max flattened user-VEX statements per /v1/analyze request before a 400")
	noScheduler := flag.Bool("no-scheduler", false, "serve without the in-process ingest scheduler — for read-only API replicas behind a load balancer; run ingest separately (e.g. a CronJob invoking the `ingest` subcommand)")
	flag.Parse()

	registerAdapters()

	cmd := flag.Arg(0)
	switch cmd {
	case "serve":
		return runServe(serveOptions{
			configPath:           *configPath,
			dbPath:               *dbPath,
			addr:                 *addr,
			ingestInterval:       *ingestInterval,
			adminToken:           *adminToken,
			sbomMaxMB:            *sbomMaxMB,
			statementsMax:        *statementsMax,
			analyzeMaxCVEs:       *analyzeMaxCVEs,
			queryTimeout:         *queryTimeout,
			maxSBOMComponents:    *maxSBOMComponents,
			maxSBOMVulns:         *maxSBOMVulns,
			maxStatementsItems:   *maxStatementsItems,
			maxUserVEXStatements: *maxUserVEXStatements,
			noScheduler:          *noScheduler,
		})
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

// openStore opens the storage backend. reel-vex is Postgres-only; -db must be a
// postgres:// (or postgresql://) connection URL. The composition root owns this
// so pkg/db stays free of any driver import (no cycle).
func openStore(dbPath string) (db.Store, error) {
	if !strings.HasPrefix(dbPath, "postgres://") && !strings.HasPrefix(dbPath, "postgresql://") {
		return nil, fmt.Errorf("-db must be a postgres:// connection URL, got %q", dbPath)
	}
	return postgres.Open(dbPath)
}

func runIngest(configPath, dbPath string, limit int) error {
	adapters, fetchers, err := loadPipeline(configPath)
	if err != nil {
		return err
	}

	database, err := openStore(dbPath)
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
	database, err := openStore(dbPath)
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

// version is the build version, surfaced via /v1/stats. Injected at build time
// with -ldflags "-X main.version=<tag>"; "dev" for local/CI builds.
var version = "dev"

// serveOptions bundles the serve-command knobs. Every field maps to a server
// flag; keeping them in a struct avoids a long, mis-orderable positional
// signature on runServe.
type serveOptions struct {
	configPath, dbPath, addr string
	ingestInterval           time.Duration
	adminToken               string
	sbomMaxMB                int
	statementsMax            int
	analyzeMaxCVEs           int
	queryTimeout             time.Duration
	maxSBOMComponents        int
	maxSBOMVulns             int
	maxStatementsItems       int
	maxUserVEXStatements     int
	noScheduler              bool
}

func runServe(opts serveOptions) error {
	adapters, fetchers, err := loadPipeline(opts.configPath)
	if err != nil {
		return err
	}

	database, err := openStore(opts.dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer database.Close()
	database.SetQueryTimeout(opts.queryTimeout)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ingestFn := func() error {
		return ingest.Run(ctx, adapters, fetchers, database, ingest.Options{})
	}
	runner := api.NewIngestRunner(ingestFn, opts.ingestInterval, opts.adminToken)

	apiSrv := api.NewServer(database, runner)
	apiSrv.SetSBOMMaxBytes(int64(opts.sbomMaxMB) << 20)
	apiSrv.SetStatementsMax(opts.statementsMax)
	apiSrv.SetAnalyzeMaxCVEs(opts.analyzeMaxCVEs)
	apiSrv.SetMaxSBOMComponents(opts.maxSBOMComponents)
	apiSrv.SetMaxSBOMVulns(opts.maxSBOMVulns)
	apiSrv.SetMaxStatementsItems(opts.maxStatementsItems)
	apiSrv.SetMaxUserVEXStatements(opts.maxUserVEXStatements)
	apiSrv.SetVersion(version)

	// WriteTimeout must stay above the DB query ceiling, else a long-but-allowed
	// query would have its response cut off by the HTTP server before
	// QueryStatements returns its 503. Tie the two together so raising
	// -query-timeout doesn't silently break responses.
	writeTimeout := 30 * time.Second
	if d := opts.queryTimeout + 10*time.Second; d > writeTimeout {
		writeTimeout = d
	}
	srv := &http.Server{
		Addr:         opts.addr,
		Handler:      apiSrv,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: writeTimeout,
		IdleTimeout:  60 * time.Second,
	}

	// Scheduled ingest runs in-process unless -no-scheduler is set. Read-only
	// API replicas behind a load balancer set it so they only serve; a single
	// separate worker (e.g. a CronJob running the `ingest` subcommand) owns
	// writes. With one app on a box (the default), leave it on.
	if opts.noScheduler {
		slog.Info("ingest scheduler disabled (-no-scheduler); this instance serves reads only")
	} else {
		// Gate the boot ingest on data freshness: a restart within the ingest
		// interval shouldn't re-run a full (contention-heavy) ingest. Best-effort —
		// a lookup error yields the zero time, which StartScheduler treats as stale
		// and ingests, preserving the old always-ingest-on-boot behaviour on doubt.
		lastIngest, err := database.LastIngestAt()
		if err != nil {
			slog.Warn("could not read last ingest time; will ingest on boot", "error", err)
		}
		go runner.StartScheduler(ctx, lastIngest)
	}

	// Warm the /v1/stats cache in the background. The first call after restart
	// would otherwise hit a 30-60s SQL scan on a multi-GB DB before the
	// ingest scheduler's first cycle refreshes the cache.
	go func() {
		if _, err := database.RefreshStats(); err != nil {
			slog.Warn("startup stats cache warmup failed", "error", err)
		}
		if err := database.Optimize(); err != nil {
			slog.Warn("startup db optimize failed", "error", err)
		}
	}()

	go func() {
		<-ctx.Done()
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	slog.Info("starting server", "addr", opts.addr, "ingest_interval", opts.ingestInterval)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func runQuery(dbPath, cve string) error {
	database, err := openStore(dbPath)
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
