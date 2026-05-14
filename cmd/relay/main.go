package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cinchcli/relay/internal/media"
	relay "github.com/cinchcli/relay/internal/relay"
)

var version = "dev"

func main() {
	var portFlag string
	flag.StringVar(&portFlag, "port", "", "TCP port to listen on (overrides PORT env; default 8080)")
	flag.StringVar(&portFlag, "p", "", "short alias for --port")
	flag.Parse()

	port := portFlag
	if port == "" {
		port = os.Getenv("PORT")
	}
	if port == "" {
		port = "8080"
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}

	store, err := relay.NewStore(dsn)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer store.Close()

	// Build media backend from env (MEDIA_BACKEND=local|s3; see DEPLOY.md).
	mediaStore, err := media.NewStore()
	if err != nil {
		log.Fatalf("failed to init media backend: %v", err)
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

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	logStartupStatus(mediaStore, handler.OAuth)

	fmt.Printf("cinch relay v%s listening on :%s\n", version, port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// logStartupStatus prints one line per subsystem so operators can confirm
// at a glance that the relay came up with the expected integrations wired.
// DB connectivity is implicit: NewStore() above already Pings and exits on
// failure, so reaching this point means the database is reachable.
func logStartupStatus(mediaStore media.Store, oauth *relay.OAuthProviders) {
	log.Printf("startup: database ok")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := mediaStore.HealthCheck(ctx); err != nil {
		log.Printf("startup: media (%s) FAILED: %v", mediaBackendName(), err)
	} else {
		log.Printf("startup: media (%s) ok", mediaBackendName())
	}

	if oauth != nil && oauth.GitHub != nil {
		log.Printf("startup: oauth github configured")
	} else {
		log.Printf("startup: oauth github not configured")
	}
	if oauth != nil && oauth.Google != nil {
		log.Printf("startup: oauth google configured")
	} else {
		log.Printf("startup: oauth google not configured")
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
		log.Printf("retention sweep: %v", err)
		return
	}
	ctx := context.Background()
	for _, key := range mediaPaths {
		if err := ms.Delete(ctx, key); err != nil {
			log.Printf("retention sweep: delete %q: %v", key, err)
		}
	}

	if n, err := store.SweepTombstones(7); err != nil {
		log.Printf("tombstone sweep: %v", err)
	} else if n > 0 {
		log.Printf("tombstone sweep: removed %d tombstones", n)
	}

	if n, err := store.SweepOldRequestCounts(7); err != nil {
		log.Printf("request count sweep: %v", err)
	} else if n > 0 {
		log.Printf("request count sweep: removed %d old rows", n)
	}
}
