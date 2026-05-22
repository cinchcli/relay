package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
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
