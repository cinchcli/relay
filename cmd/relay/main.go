package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
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

	// Grace sweeper: NULLs stale master tokens past the 7-day migration window.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go relay.RunGraceSweeper(ctx, store)

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
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	handler.StartPlaygroundReset()

	fmt.Printf("cinch relay v%s listening on :%s\n", version, port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
