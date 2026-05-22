package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
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

// resolveDSN returns the Postgres DSN from either DATABASE_URL or
// DATABASE_URL_FILE. DATABASE_URL wins when both are set so operators can
// override a file-mounted secret in a local debug session without unmounting
// it. Trailing whitespace and newlines in file contents are stripped — many
// secret stores (Docker secrets, k8s Secret volume mounts, vault-agent
// templates) append a newline when rendering the value.
//
// Returns an error if both env vars are empty, or if DATABASE_URL_FILE
// points at a path that cannot be read. The file-read error is returned
// verbatim so the operator sees the exact OS error (permission denied,
// no such file, etc.) — these are the failure modes that actually bite
// in production.
func resolveDSN(envURL, envPath string) (string, error) {
	if envURL != "" {
		return envURL, nil
	}
	if envPath == "" {
		return "", errors.New("set DATABASE_URL or DATABASE_URL_FILE")
	}
	b, err := os.ReadFile(envPath)
	if err != nil {
		return "", fmt.Errorf("read DATABASE_URL_FILE %q: %w", envPath, err)
	}
	dsn := strings.TrimSpace(string(b))
	if dsn == "" {
		return "", fmt.Errorf("DATABASE_URL_FILE %q is empty", envPath)
	}
	return dsn, nil
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

	port := portFlag
	if port == "" {
		port = os.Getenv("PORT")
	}
	if port == "" {
		port = "8080"
	}

	dsn, err := resolveDSN(os.Getenv("DATABASE_URL"), os.Getenv("DATABASE_URL_FILE"))
	if err != nil {
		slog.Error("DATABASE_URL resolution failed", "err", err)
		os.Exit(1)
	}

	store, err := relay.NewStore(dsn)
	if err != nil {
		slog.Error("failed to open database", "err", err)
		os.Exit(1)
	}
	defer store.Close()

	if code := os.Getenv("RELAY_BOOTSTRAP_INVITE_CODE"); code != "" {
		if err := relay.ApplyBootstrapInvite(store, code, os.Stderr); err != nil {
			slog.Error("bootstrap invite failed", "err", err)
			os.Exit(1)
		}
	}

	// Build media backend from env (MEDIA_BACKEND=local|s3; see DEPLOY.md).
	mediaStore, err := media.NewStore()
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

	handler := relay.NewHandler(store, hub)
	handler.SetMediaStore(mediaStore)

	// BASE_URL is the public HTTPS root (e.g. https://api.cinchcli.com).
	handler.BaseURL = os.Getenv("BASE_URL")

	// CORS_ORIGINS: comma-separated extra allowed origins for self-hosters.
	if corsEnv := os.Getenv("CORS_ORIGINS"); corsEnv != "" {
		for _, o := range strings.Split(corsEnv, ",") {
			if trimmed := strings.TrimSpace(o); trimmed != "" {
				handler.CORSOrigins = append(handler.CORSOrigins, trimmed)
			}
		}
	}

	// OAuth providers — relay works without these (self-host username form fallback).
	handler.OAuth = relay.NewOAuthProviders(
		handler.BaseURL,
		os.Getenv("GITHUB_CLIENT_ID"),
		os.Getenv("GITHUB_CLIENT_SECRET"),
		os.Getenv("GOOGLE_CLIENT_ID"),
		os.Getenv("GOOGLE_CLIENT_SECRET"),
	)

	// Telemetry proxy — silently disabled when env vars are absent.
	handler.TelemetryURL = strings.TrimRight(os.Getenv("TELEMETRY_URL"), "/")
	handler.TelemetryAPIKey = os.Getenv("TELEMETRY_API_KEY")
	handler.SetInternalServiceSecret(os.Getenv("INTERNAL_SERVICE_SECRET"))

	// Self-host carve-out: when CINCH_PLAN_ENFORCEMENT_DISABLED is "1"
	// or "true" (case-insensitive), skip plan-tier enforcement checks
	// (device limit on CompleteDeviceCode, plan-derived retention clamp
	// on UpdateDeviceRetention). Operators of self-hosted relays pay
	// for their own Postgres + storage, so we don't gate them. Hosted
	// cinchcli.com leaves this unset.
	if v := os.Getenv("CINCH_PLAN_ENFORCEMENT_DISABLED"); v == "1" || strings.EqualFold(v, "true") {
		store.EnforcementDisabled = true
		slog.Warn("plan enforcement disabled via CINCH_PLAN_ENFORCEMENT_DISABLED — self-host mode")
	}

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	logStartupStatus(mediaStore, handler.OAuth)

	slog.Info("relay listening", "version", version, "port", port)
	srv := &http.Server{
		Addr:    ":" + port,
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
func logStartupStatus(mediaStore media.Store, oauth *relay.OAuthProviders) {
	slog.Info("startup database ok")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := mediaStore.HealthCheck(ctx); err != nil {
		slog.Error("startup media healthcheck failed", "backend", mediaBackendName(), "err", err)
	} else {
		slog.Info("startup media ok", "backend", mediaBackendName())
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

func mediaBackendName() string {
	b := os.Getenv("MEDIA_BACKEND")
	if b == "" {
		return "local"
	}
	return b
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
