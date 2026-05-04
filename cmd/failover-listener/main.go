package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"
)

type serverConfig struct {
	failoverScript string
	failbackScript string
	flushScript    string
}

var globalState state

func main() {
	cfg := serverConfig{
		failoverScript: os.Getenv("FAILOVER_SCRIPT"),
		failbackScript: os.Getenv("FAILBACK_SCRIPT"),
		flushScript:    os.Getenv("FLUSH_SCRIPT"),
	}

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:9090"
	}

	mux := buildMux(cfg)

	log.Printf("failover-listener starting on %s", addr)
	log.Printf("  FAILOVER_SCRIPT=%q", cfg.failoverScript)
	log.Printf("  FAILBACK_SCRIPT=%q", cfg.failbackScript)
	log.Printf("  FLUSH_SCRIPT=%q", cfg.flushScript)

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 5 * time.Minute,
		IdleTimeout:  60 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func buildMux(cfg serverConfig) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("POST /failover", makeScriptHandler(cfg.failoverScript, "failover"))
	mux.HandleFunc("POST /failback", makeFailbackHandler(cfg))
	return mux
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "ok")
}

func makeScriptHandler(scriptPath, name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if scriptPath == "" {
			http.Error(w, name+" script not configured (set "+envKey(name)+")", http.StatusServiceUnavailable)
			return
		}
		if !globalState.tryLock() {
			http.Error(w, "another operation is in progress", http.StatusConflict)
			return
		}
		defer globalState.unlock()

		log.Printf("[%s] starting %s", name, scriptPath)
		if err := runScript(r.Context(), scriptPath, w); err != nil {
			log.Printf("[%s] script failed: %v", name, err)
			return
		}
		log.Printf("[%s] script completed successfully", name)
	}
}

func makeFailbackHandler(cfg serverConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cfg.failbackScript == "" {
			http.Error(w, "failback script not configured (set FAILBACK_SCRIPT)", http.StatusServiceUnavailable)
			return
		}
		if !globalState.tryLock() {
			http.Error(w, "another operation is in progress", http.StatusConflict)
			return
		}
		defer globalState.unlock()

		if cfg.flushScript != "" {
			log.Printf("[failback] running flush: %s", cfg.flushScript)
			if err := runScript(r.Context(), cfg.flushScript, w); err != nil {
				log.Printf("[failback] flush script failed: %v — aborting failback", err)
				return
			}
		}

		log.Printf("[failback] running failback: %s", cfg.failbackScript)
		if err := runScript(r.Context(), cfg.failbackScript, w); err != nil {
			log.Printf("[failback] failback script failed: %v", err)
			return
		}
		log.Printf("[failback] completed successfully")
	}
}

func runScript(ctx context.Context, path string, w http.ResponseWriter) error {
	if fw, ok := w.(http.Flusher); ok {
		defer fw.Flush()
	}

	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", path)
	out, err := cmd.CombinedOutput()

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "ERROR: script exited with error: %v\n", err)
		io.WriteString(w, string(out))
		return err
	}

	io.WriteString(w, string(out))
	return nil
}

func envKey(name string) string {
	switch name {
	case "failover":
		return "FAILOVER_SCRIPT"
	case "failback":
		return "FAILBACK_SCRIPT"
	}
	return "UNKNOWN_SCRIPT"
}
