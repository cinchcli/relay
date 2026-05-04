package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestHealthEndpoint(t *testing.T) {
	mux := buildMux(serverConfig{})
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestFailoverRequiresPOST(t *testing.T) {
	mux := buildMux(serverConfig{failoverScript: "/bin/true"})
	req := httptest.NewRequest(http.MethodGet, "/failover", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestFailoverMissingScript(t *testing.T) {
	mux := buildMux(serverConfig{failoverScript: ""})
	req := httptest.NewRequest(http.MethodPost, "/failover", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when FAILOVER_SCRIPT is empty, got %d", w.Code)
	}
}

func TestFailbackMissingScript(t *testing.T) {
	mux := buildMux(serverConfig{failbackScript: ""})
	req := httptest.NewRequest(http.MethodPost, "/failback", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when FAILBACK_SCRIPT is empty, got %d", w.Code)
	}
}

func TestFailoverRunsScript(t *testing.T) {
	f, err := os.CreateTemp("", "test-script-*.sh")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString("#!/bin/sh\necho 'failover triggered'\n")
	f.Close()
	os.Chmod(f.Name(), 0755)

	mux := buildMux(serverConfig{failoverScript: f.Name()})
	req := httptest.NewRequest(http.MethodPost, "/failover", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); body == "" {
		t.Error("expected script output in response body")
	}
}

func TestFailoverScriptFailureReturns500(t *testing.T) {
	f, _ := os.CreateTemp("", "fail-script-*.sh")
	defer os.Remove(f.Name())
	f.WriteString("#!/bin/sh\nexit 1\n")
	f.Close()
	os.Chmod(f.Name(), 0755)

	mux := buildMux(serverConfig{failoverScript: f.Name()})
	req := httptest.NewRequest(http.MethodPost, "/failover", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on script failure, got %d", w.Code)
	}
}
