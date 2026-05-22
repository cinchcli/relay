package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewLoggerHandler_LevelGating(t *testing.T) {
	cases := []struct {
		name      string
		levelStr  string
		emitDebug bool
		emitInfo  bool
		emitWarn  bool
		emitError bool
	}{
		{"default (empty → info)", "", false, true, true, true},
		{"debug emits all", "debug", true, true, true, true},
		{"info gates debug only", "info", false, true, true, true},
		{"warn gates debug+info", "warn", false, false, true, true},
		{"error gates everything below", "error", false, false, false, true},
		{"unknown level → info default", "verbose", false, true, true, true},
		{"case-insensitive: DEBUG", "DEBUG", true, true, true, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			h := newLoggerHandler(tc.levelStr, "text", &buf)
			logger := slog.New(h)
			logger.Debug("dbg")
			logger.Info("info")
			logger.Warn("warn")
			logger.Error("err")

			out := buf.String()
			checks := []struct {
				msg  string
				want bool
			}{
				{"dbg", tc.emitDebug},
				{"info", tc.emitInfo},
				{"warn", tc.emitWarn},
				{"err", tc.emitError},
			}
			for _, c := range checks {
				got := strings.Contains(out, "msg="+c.msg) || strings.Contains(out, `"msg":"`+c.msg+`"`)
				if got != c.want {
					t.Errorf("level=%q msg=%q present=%v want=%v\noutput: %s", tc.levelStr, c.msg, got, c.want, out)
				}
			}
		})
	}
}

func TestNewLoggerHandler_Format(t *testing.T) {
	t.Run("text default", func(t *testing.T) {
		var buf bytes.Buffer
		slog.New(newLoggerHandler("info", "", &buf)).Info("hello", "k", "v")
		out := buf.String()
		if !strings.Contains(out, "msg=hello") || !strings.Contains(out, "k=v") {
			t.Errorf("text handler missing key=value pairs: %s", out)
		}
		// Should NOT be valid JSON
		var anyJSON map[string]any
		if err := json.Unmarshal([]byte(out), &anyJSON); err == nil {
			t.Errorf("text output unexpectedly parsed as JSON: %s", out)
		}
	})

	t.Run("json explicit", func(t *testing.T) {
		var buf bytes.Buffer
		slog.New(newLoggerHandler("info", "json", &buf)).Info("hello", "k", "v")
		var parsed map[string]any
		if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
			t.Fatalf("json handler did not produce parseable JSON: %v\noutput: %s", err, buf.String())
		}
		if parsed["msg"] != "hello" {
			t.Errorf("expected msg=hello, got %v", parsed["msg"])
		}
		if parsed["k"] != "v" {
			t.Errorf("expected k=v, got %v", parsed["k"])
		}
	})

	t.Run("json case-insensitive", func(t *testing.T) {
		var buf bytes.Buffer
		slog.New(newLoggerHandler("info", "JSON", &buf)).Info("hi")
		if buf.Len() == 0 {
			t.Fatal("no output")
		}
		var parsed map[string]any
		if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
			t.Errorf("JSON (uppercase) format should produce JSON output: %s", buf.String())
		}
	})

	t.Run("unknown format falls back to text", func(t *testing.T) {
		var buf bytes.Buffer
		slog.New(newLoggerHandler("info", "logfmt", &buf)).Info("hi")
		if !strings.Contains(buf.String(), "msg=hi") {
			t.Errorf("unknown format should fall back to text, got: %s", buf.String())
		}
	})
}

func TestResolveDSN(t *testing.T) {
	t.Run("env URL wins when set", func(t *testing.T) {
		got, err := resolveDSN("postgres://from-env/db", "/tmp/should-not-be-read")
		if err != nil {
			t.Fatalf("resolveDSN: %v", err)
		}
		if got != "postgres://from-env/db" {
			t.Errorf("got %q, want from-env", got)
		}
	})

	t.Run("env URL wins even when both set", func(t *testing.T) {
		// Order matters for local debugging — operator overrides a
		// file-mounted secret by exporting DATABASE_URL in their shell.
		dir := t.TempDir()
		path := filepath.Join(dir, "dsn")
		if err := os.WriteFile(path, []byte("postgres://from-file/db"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := resolveDSN("postgres://from-env/db", path)
		if err != nil {
			t.Fatalf("resolveDSN: %v", err)
		}
		if got != "postgres://from-env/db" {
			t.Errorf("env URL must win when both set; got %q", got)
		}
	})

	t.Run("reads from file when only path set", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "dsn")
		if err := os.WriteFile(path, []byte("postgres://from-file/db"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := resolveDSN("", path)
		if err != nil {
			t.Fatalf("resolveDSN: %v", err)
		}
		if got != "postgres://from-file/db" {
			t.Errorf("got %q, want from-file", got)
		}
	})

	t.Run("strips trailing newline from file content", func(t *testing.T) {
		// Many secret stores append a newline when rendering — Docker
		// secrets, k8s Secret volume mounts, vault-agent templates.
		// Without TrimSpace, the trailing \n turns the DSN into garbage.
		dir := t.TempDir()
		path := filepath.Join(dir, "dsn")
		if err := os.WriteFile(path, []byte("postgres://from-file/db\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := resolveDSN("", path)
		if err != nil {
			t.Fatalf("resolveDSN: %v", err)
		}
		if got != "postgres://from-file/db" {
			t.Errorf("trailing newline not stripped; got %q", got)
		}
	})

	t.Run("strips surrounding whitespace from file content", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "dsn")
		if err := os.WriteFile(path, []byte("\t  postgres://from-file/db  \n\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := resolveDSN("", path)
		if err != nil {
			t.Fatalf("resolveDSN: %v", err)
		}
		if got != "postgres://from-file/db" {
			t.Errorf("surrounding whitespace not stripped; got %q", got)
		}
	})

	t.Run("errors when both empty", func(t *testing.T) {
		_, err := resolveDSN("", "")
		if err == nil {
			t.Fatal("expected error when both env vars empty")
		}
		if !strings.Contains(err.Error(), "DATABASE_URL") {
			t.Errorf("error must mention DATABASE_URL so operator knows what to set; got %q", err.Error())
		}
	})

	t.Run("errors when file is missing", func(t *testing.T) {
		_, err := resolveDSN("", "/tmp/this-path-does-not-exist-resolveDSN-test")
		if err == nil {
			t.Fatal("expected error for missing file")
		}
		// The OS error must surface so the operator can debug
		// permission-denied vs not-found.
		if !strings.Contains(err.Error(), "DATABASE_URL_FILE") {
			t.Errorf("error must mention DATABASE_URL_FILE so operator knows which path failed; got %q", err.Error())
		}
	})

	t.Run("errors when file is empty after trim", func(t *testing.T) {
		// Empty file is a misconfiguration (the secret didn't render) —
		// surface it rather than letting pgx fail with a cryptic
		// "missing user" error 30 seconds later.
		dir := t.TempDir()
		path := filepath.Join(dir, "dsn")
		if err := os.WriteFile(path, []byte("   \n\t\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := resolveDSN("", path)
		if err == nil {
			t.Fatal("expected error for empty file")
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Errorf("error must call out emptiness; got %q", err.Error())
		}
	})
}
