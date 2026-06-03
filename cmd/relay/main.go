package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cinchcli/relay/internal/media"
	relay "github.com/cinchcli/relay/internal/relay"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "invite":
			runInviteCLI(os.Args[2:])
			return
		case "user":
			runUserCLI(os.Args[2:])
			return
		}
	}
	runServer()
}

// newLoggerHandler returns a slog.Handler configured from LOG_LEVEL and
// LOG_FORMAT-style strings. Unknown level strings fall back to Info;
// unknown formats fall back to text. Pure — has no side effects — so
// it can be exercised by tests with a custom writer.
func newLoggerHandler(levelStr, formatStr string, w io.Writer) slog.Handler {
	level := slog.LevelInfo
	switch strings.ToLower(levelStr) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	if strings.EqualFold(formatStr, "json") {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}

// initLogger configures slog.Default based on LOG_LEVEL and LOG_FORMAT env vars.
// LOG_LEVEL: debug | info (default) | warn | error (case-insensitive).
// LOG_FORMAT: text (default) | json (case-insensitive).
// Output goes to stderr.
func initLogger() {
	h := newLoggerHandler(os.Getenv("LOG_LEVEL"), os.Getenv("LOG_FORMAT"), os.Stderr)
	slog.SetDefault(slog.New(h))
}

func runServer() {
	initLogger()

	fs := flag.NewFlagSet("server", flag.ExitOnError)
	var portFlag string
	fs.StringVar(&portFlag, "port", "", "TCP port to listen on (overrides PORT env; default 8080)")
	fs.StringVar(&portFlag, "p", "", "short alias for --port")
	_ = fs.Parse(os.Args[1:])

	// All environment is parsed once, here, into a typed Config.
	cfg := relay.LoadConfig()
	if portFlag != "" {
		cfg.Port = portFlag // --port/-p overrides PORT env
	}
	if cfg.DatabaseURL == "" {
		slog.Error("DATABASE_URL is required")
		os.Exit(1)
	}

	store, err := relay.NewStore(cfg.DatabaseURL)
	if err != nil {
		slog.Error("failed to open database", "err", err)
		os.Exit(1)
	}
	defer store.Close()

	if cfg.BootstrapInviteCode != "" {
		if err := relay.ApplyBootstrapInvite(store, cfg.BootstrapInviteCode, os.Stderr); err != nil {
			slog.Error("bootstrap invite failed", "err", err)
			os.Exit(1)
		}
	}

	// Build media backend from the parsed config (MEDIA_BACKEND=local|s3).
	mediaStore, err := media.NewStoreFromConfig(cfg.Media)
	if err != nil {
		slog.Error("failed to init media backend", "err", err)
		os.Exit(1)
	}

	// Retention sweep: deletes expired remote clips hourly and purges their
	// media objects from the configured backend.
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			runRetentionSweep(store, mediaStore)
		}
	}()

	hub := relay.NewHub()
	go hub.Run()

	// Evict expired WebSocket auth tickets so unconsumed tickets don't leak.
	relay.StartWSTicketReaper(context.Background())

	handler := relay.NewHandler(store, hub)
	handler.SetMediaStore(mediaStore)
	handler.BaseURL = cfg.BaseURL
	handler.CORSOrigins = cfg.CORSOrigins

	// OAuth providers — relay works without these (self-host username form fallback).
	handler.OAuth = relay.NewOAuthProviders(
		cfg.BaseURL,
		cfg.GitHubClientID,
		cfg.GitHubClientSecret,
		cfg.GoogleClientID,
		cfg.GoogleClientSecret,
	)

	// Telemetry proxy — silently disabled when config is absent.
	handler.TelemetryURL = cfg.TelemetryURL
	handler.TelemetryAPIKey = cfg.TelemetryAPIKey
	handler.SetInternalServiceSecret(cfg.InternalServiceSecret)
	handler.SetInternalQuotaWriteSecret(cfg.InternalQuotaWriteSecret)
	handler.SetInternalReadSecret(cfg.InternalReadSecret)

	// Self-host carve-out: skip hosted-plan enforcement checks (device limit on
	// CompleteDeviceCode, plan-derived retention clamp on UpdateDeviceRetention)
	// when CINCH_PLAN_ENFORCEMENT_DISABLED is set. Hosted cinchcli.com leaves it
	// unset; self-hosters pay for their own Postgres + storage.
	if cfg.PlanEnforcementDisabled {
		store.EnforcementDisabled = true
		slog.Warn("plan enforcement disabled via CINCH_PLAN_ENFORCEMENT_DISABLED — self-host mode")
	}

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	logStartupStatus(mediaStore, handler.OAuth, cfg.Media.BackendName())

	slog.Info("relay listening", "version", version, "port", cfg.Port)
	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: mux,
		// Cap header-read time to defend against slowloris-style attacks
		// without affecting hijacked WebSocket connections (/ws) or
		// Connect-RPC streaming endpoints (/v1/events), which need to stay
		// open long after the request headers are parsed. ReadTimeout /
		// WriteTimeout are intentionally left at 0 for the same reason; add
		// them per-handler if a specific route needs a bound.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}

// logStartupStatus prints one line per subsystem so operators can confirm
// at a glance that the relay came up with the expected integrations wired.
// DB connectivity is implicit: NewStore() above already Pings and exits on
// failure, so reaching this point means the database is reachable.
func logStartupStatus(mediaStore media.Store, oauth *relay.OAuthProviders, backend string) {
	slog.Info("startup database ok")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := mediaStore.HealthCheck(ctx); err != nil {
		slog.Error("startup media healthcheck failed", "backend", backend, "err", err)
	} else {
		slog.Info("startup media ok", "backend", backend)
	}

	if oauth != nil && oauth.GitHub != nil {
		slog.Info("startup oauth github configured")
	} else {
		slog.Info("startup oauth github not configured")
	}
	if oauth != nil && oauth.Google != nil {
		slog.Info("startup oauth google configured")
	} else {
		slog.Info("startup oauth google not configured")
	}
}

func runRetentionSweep(store *relay.Store, ms media.Store) {
	mediaPaths, err := store.SweepAllUsersRetentionReturningMedia()
	if err != nil {
		slog.Error("retention sweep failed", "err", err)
		return
	}
	ctx := context.Background()
	for _, key := range mediaPaths {
		if err := ms.Delete(ctx, key); err != nil {
			slog.Error("retention sweep media delete failed", "key", key, "err", err)
		}
	}

	if n, err := store.SweepTombstones(7); err != nil {
		slog.Warn("tombstone sweep failed", "err", err)
	} else if n > 0 {
		slog.Info("tombstone sweep removed tombstones", "count", n)
	}

	if n, err := store.SweepOldRequestCounts(7); err != nil {
		slog.Warn("request count sweep failed", "err", err)
	} else if n > 0 {
		slog.Info("request count sweep removed old rows", "count", n)
	}

	if n, err := store.SweepStaleIdempotencyKeys(24 * time.Hour); err != nil {
		slog.Warn("idempotency key sweep failed", "err", err)
	} else if n > 0 {
		slog.Info("idempotency key sweep nulled stale keys", "count", n)
	}
}
