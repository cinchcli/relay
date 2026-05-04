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

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "cinch.db"
	}

	store, err := relay.NewStore(dbPath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer store.Close()

	// Build media backend from env (MEDIA_BACKEND=local|s3; see DEPLOY.md).
	mediaStore, err := media.NewStore()
	if err != nil {
		log.Fatalf("failed to init media backend: %v", err)
	}
	log.Printf("media backend: %s", mediaBackendName())

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

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	handler.StartPlaygroundReset()

	fmt.Printf("cinch relay v%s listening on :%s\n", version, port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("server error: %v", err)
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
	if len(mediaPaths) == 0 {
		return
	}
	ctx := context.Background()
	for _, key := range mediaPaths {
		if err := ms.Delete(ctx, key); err != nil {
			log.Printf("retention sweep: delete %q: %v", key, err)
		}
	}
}
