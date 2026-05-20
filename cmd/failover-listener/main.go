package main

import (
	"context"
	"fmt"
	"log/slog"
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

	slog.Info("failover-listener starting", "addr", addr)
	slog.Info("failover-listener config",
		"failover_script", cfg.failoverScript,
		"failback_script", cfg.failbackScript,
		"flush_script", cfg.flushScript,
	)

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 5 * time.Minute,
		IdleTimeout:  60 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("server error", "err", err)
		os.Exit(1)
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

		slog.Info("script starting", "name", name, "script", scriptPath)
		if err := runScript(r.Context(), scriptPath, w); err != nil {
			slog.Error("script failed", "name", name, "err", err)
			return
		}
		slog.Info("script completed successfully", "name", name)
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
			slog.Info("failback running flush", "script", cfg.flushScript)
			if err := runScript(r.Context(), cfg.flushScript, w); err != nil {
				slog.Error("failback flush script failed, aborting failback", "err", err)
				return
			}
		}

		slog.Info("failback running failback", "script", cfg.failbackScript)
		if err := runScript(r.Context(), cfg.failbackScript, w); err != nil {
			slog.Error("failback script failed", "err", err)
			return
		}
		slog.Info("failback completed successfully")
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
		w.Write(out)
		return err
	}

	w.Write(out)
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
