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

	"github.com/getreeldev/reel-vex/pkg/api"
	"github.com/getreeldev/reel-vex/pkg/db"
	"github.com/getreeldev/reel-vex/pkg/ingest"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "config.yaml", "path to config file")
	dbPath := flag.String("db", "vex.db", "path to SQLite database")
	limit := flag.Int("limit", 0, "max documents per provider (0 = unlimited)")
	addr := flag.String("addr", ":8080", "listen address for serve command")
	flag.Parse()

	cmd := flag.Arg(0)
	switch cmd {
	case "serve":
		return runServe(*dbPath, *addr)
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
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	var cfg ingest.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	database, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer database.Close()

	return ingest.Run(cfg, database, ingest.Options{Limit: limit})
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

func runServe(dbPath, addr string) error {
	database, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer database.Close()

	srv := &http.Server{
		Addr:         addr,
		Handler:      api.NewServer(database),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	go func() {
		<-ctx.Done()
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	slog.Info("starting server", "addr", addr)
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

	stmts, err := database.QueryByCVE(cve)
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
