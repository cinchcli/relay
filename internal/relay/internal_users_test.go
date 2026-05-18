package relay_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	relay "github.com/cinchcli/relay/internal/relay"
)

func TestInternalCursor_RoundTrip(t *testing.T) {
	in := relay.InternalCursorPayload{
		CreatedAt: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
		UserID:    "01HXYZ123",
	}
	s := relay.EncodeInternalCursor(in)
	if s == "" {
		t.Fatal("EncodeInternalCursor returned empty string")
	}
	if strings.ContainsAny(s, "+/=") {
		t.Fatalf("cursor should be base64-RawURL (no +/=), got %q", s)
	}
	out, err := relay.DecodeInternalCursor(s)
	if err != nil {
		t.Fatalf("DecodeInternalCursor: %v", err)
	}
	if !out.CreatedAt.Equal(in.CreatedAt) || out.UserID != in.UserID {
		t.Fatalf("round-trip mismatch: in=%+v out=%+v", in, out)
	}
}

func TestInternalCursor_RejectsGarbage(t *testing.T) {
	cases := []string{
		"!!!not-base64!!!", // bad base64
		"eyJpZCI6IiJ9",     // valid base64 → '{"id":""}'; missing/empty id
	}
	for _, s := range cases {
		if _, err := relay.DecodeInternalCursor(s); err == nil {
			t.Fatalf("expected error for cursor %q", s)
		}
	}
}

func TestInternalUsers_UnavailableWhenNoSecret(t *testing.T) {
	ts, _ := setupTestServer(t) // no secret configured

	req, _ := http.NewRequest("GET", ts.URL+"/internal/users", nil)
	req.Header.Set("Authorization", "Bearer anything")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
}

func TestInternalUsers_RejectsWrongSecret(t *testing.T) {
	ts, _ := setupTestServerWithSecret(t, "correct-secret")

	req, _ := http.NewRequest("GET", ts.URL+"/internal/users", nil)
	req.Header.Set("Authorization", "Bearer wrong-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestInternalUsers_RejectsBadIncludeDemo(t *testing.T) {
	ts, _ := setupTestServerWithSecret(t, "test-secret")

	req, _ := http.NewRequest("GET", ts.URL+"/internal/users?include_demo=potato", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad include_demo, got %d", resp.StatusCode)
	}
}

func TestInternalUsers_HappyPathEmpty(t *testing.T) {
	ts, _ := setupTestServerWithSecret(t, "test-secret")

	req, _ := http.NewRequest("GET", ts.URL+"/internal/users", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var got struct {
		Users      []map[string]any `json:"users"`
		NextCursor string           `json:"next_cursor"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Users) != 0 {
		t.Fatalf("expected empty users on fresh store, got %d", len(got.Users))
	}
	if got.NextCursor != "" {
		t.Fatalf("expected empty cursor, got %q", got.NextCursor)
	}
}
