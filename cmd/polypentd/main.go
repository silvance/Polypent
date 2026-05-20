// Command polypentd is the PolyPent core daemon.
//
// Subcommands:
//
//	polypentd serve [--config path]   start the API server
//	polypentd migrate [--config path] apply pending DB migrations
//	polypentd --version               print version information
//
// Behavior beyond Phase 1 arrives in later phases per docs/migration-plan.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/silvance/polypent/internal/api"
	"github.com/silvance/polypent/internal/audit"
	"github.com/silvance/polypent/internal/auth"
	"github.com/silvance/polypent/internal/collector"
	"github.com/silvance/polypent/internal/collector/mock"
	"github.com/silvance/polypent/internal/config"
	"github.com/silvance/polypent/internal/project"
	"github.com/silvance/polypent/internal/queue"
	"github.com/silvance/polypent/internal/run"
	"github.com/silvance/polypent/internal/scope"
	pgstore "github.com/silvance/polypent/internal/store/postgres"
	"github.com/silvance/polypent/internal/target"
	"github.com/silvance/polypent/internal/telemetry"
	"github.com/silvance/polypent/internal/version"
	"github.com/silvance/polypent/internal/worker"
)

const binaryName = "polypentd"

func main() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "--version", "-version", "version":
			fmt.Println(version.String(binaryName))
			return
		case "serve":
			os.Exit(runServe(os.Args[2:]))
		case "migrate":
			os.Exit(runMigrate(os.Args[2:]))
		case "-h", "--help", "help":
			printUsage(os.Stdout)
			return
		}
	}
	printUsage(os.Stderr)
	os.Exit(2)
}

func printUsage(w *os.File) {
	_, _ = fmt.Fprintf(w, `polypentd — PolyPent core daemon

Usage:
  %s serve    [--config path]   start the API server
  %s migrate  [--config path]   apply pending DB migrations
  %s --version                  print version

`, binaryName, binaryName, binaryName)
}

func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to config YAML (optional; env vars take precedence)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}

	log, err := telemetry.NewLogger(os.Stderr, cfg.Log.Level, cfg.Log.Format)
	if err != nil {
		fmt.Fprintln(os.Stderr, "log:", err)
		return 1
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	pool, err := pgstore.Open(ctx, cfg.Database.URL)
	if err != nil {
		log.Error("database open", "err", err)
		return 1
	}
	defer pool.Close()

	tokens := auth.NewStore(pool)
	auditLog, err := audit.New(pool, []byte(cfg.Audit.SigningKey))
	if err != nil {
		log.Error("audit init", "err", err)
		return 1
	}
	projects := project.NewStore(pool)

	if err := maybeBootstrap(ctx, log, tokens); err != nil {
		log.Error("bootstrap", "err", err)
		return 1
	}

	scopeStore := scope.NewStore(pool)
	q := queue.New(pool, cfg.Queue.LeaseDuration)
	planner := run.NewPlanner(pool, q, scopeStore, auditLog)
	runs := run.NewStore(pool)

	reg := collector.NewRegistry()
	reg.Register(mock.New())

	pool2Ctx, poolCancel := context.WithCancel(ctx)
	defer poolCancel()
	workerPool := worker.New(q, reg, log, worker.Options{
		Size: cfg.Queue.Workers,
		Poll: cfg.Queue.PollInterval,
	})
	workerDone := make(chan struct{})
	go func() {
		workerPool.Run(pool2Ctx)
		close(workerDone)
	}()

	srv := api.New(cfg.Server.Addr, cfg.Server.ShutdownTimeout, api.Deps{
		Logger:     log,
		Projects:   projects,
		Tokens:     tokens,
		Audit:      auditLog,
		Scope:      scopeStore,
		Targets:    target.NewStore(pool),
		Planner:    planner,
		Runs:       runs,
		Queue:      q,
		Collectors: reg,
	})
	log.Info("server listening", "addr", cfg.Server.Addr, "workers", cfg.Queue.Workers)
	srvErr := srv.ListenAndServeWithShutdown(ctx, cfg.Server.ShutdownTimeout)
	poolCancel()
	<-workerDone
	if srvErr != nil && !errors.Is(srvErr, http.ErrServerClosed) {
		log.Error("server", "err", srvErr)
		return 1
	}
	log.Info("server stopped")
	return 0
}

func runMigrate(args []string) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to config YAML")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	if err := pgstore.Migrate(cfg.Database.URL); err != nil {
		fmt.Fprintln(os.Stderr, "migrate:", err)
		return 1
	}
	fmt.Println("migrations applied")
	return 0
}

// maybeBootstrap mints a one-time admin token if the api_tokens table is
// empty. The plaintext is written to the daemon log exactly once. The
// operator is expected to capture it, then issue project-scoped tokens via
// the API.
func maybeBootstrap(ctx context.Context, log *slog.Logger, tokens *auth.Store) error {
	has, err := tokens.HasAny(ctx)
	if err != nil {
		return err
	}
	if has {
		return nil
	}
	tok, err := tokens.Issue(ctx, auth.RoleAdmin, nil, "bootstrap", 0)
	if err != nil {
		return err
	}
	log.Info("BOOTSTRAP TOKEN ISSUED — capture this now; it will not be shown again",
		"token", tok.Plaintext)
	return nil
}
