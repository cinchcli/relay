package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

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

	// Reconcile orphaned media files on startup
	if err := store.ReconcileMedia(); err != nil {
		log.Printf("media reconciliation: %v", err)
	}

	// Retention sweep: deletes expired remote clips hourly.
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if err := store.SweepAllUsersRetention(); err != nil {
				log.Printf("retention sweep error: %v", err)
			}
		}
	}()

	hub := relay.NewHub()
	go hub.Run()

	handler := relay.NewHandler(store, hub)

	// BASE_URL is the public HTTPS root (e.g. https://api.cinchcli.com).
	// Required for OAuth redirect URIs and device-code verification URIs.
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
