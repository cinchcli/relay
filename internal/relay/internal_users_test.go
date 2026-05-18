package relay_test

import (
	"encoding/json"
	"fmt"
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

func TestInternalUsers_ReturnsAggregates(t *testing.T) {
	ts, store := setupTestServerWithSecret(t, "test-secret")

	if err := store.CreateUser("alice"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := store.UpsertUserCapabilities(relay.UserCapabilities{
		UserID: "alice", DeviceLimit: 10, RetentionDays: 90, RateLimit: 0,
	}); err != nil {
		t.Fatalf("UpsertUserCapabilities: %v", err)
	}

	req, _ := http.NewRequest("GET", ts.URL+"/internal/users", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	var got struct {
		Users []struct {
			UserID       string `json:"user_id"`
			DeviceCount  int    `json:"device_count"`
			Capabilities *struct {
				DeviceLimit int `json:"device_limit"`
			} `json:"capabilities"`
		} `json:"users"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Users) != 1 || got.Users[0].UserID != "alice" {
		t.Fatalf("expected alice, got %+v", got.Users)
	}
	if got.Users[0].Capabilities == nil || got.Users[0].Capabilities.DeviceLimit != 10 {
		t.Fatalf("expected device_limit=10, got %+v", got.Users[0].Capabilities)
	}
}

func TestInternalUsers_RejectsBadLimit(t *testing.T) {
	ts, _ := setupTestServerWithSecret(t, "test-secret")

	cases := []string{"0", "-1", "1001", "notanumber"}
	for _, v := range cases {
		req, _ := http.NewRequest("GET", ts.URL+"/internal/users?limit="+v, nil)
		req.Header.Set("Authorization", "Bearer test-secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("limit=%s: %v", v, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("limit=%s: expected 400, got %d", v, resp.StatusCode)
		}
	}
}

func TestInternalUsers_RejectsBadCursor(t *testing.T) {
	ts, _ := setupTestServerWithSecret(t, "test-secret")

	req, _ := http.NewRequest("GET", ts.URL+"/internal/users?cursor=!!!garbage!!!", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad cursor, got %d", resp.StatusCode)
	}
}

func TestInternalUsers_RejectsBadUpdatedSince(t *testing.T) {
	ts, _ := setupTestServerWithSecret(t, "test-secret")

	req, _ := http.NewRequest("GET", ts.URL+"/internal/users?updated_since=not-a-date", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad updated_since, got %d", resp.StatusCode)
	}
}

func TestInternalUsers_PaginatesEndToEnd(t *testing.T) {
	ts, store := setupTestServerWithSecret(t, "test-secret")

	for i := 0; i < 3; i++ {
		uid := fmt.Sprintf("user-%d", i)
		if err := store.CreateUser(uid); err != nil {
			t.Fatalf("CreateUser %s: %v", uid, err)
		}
	}

	req, _ := http.NewRequest("GET", ts.URL+"/internal/users?limit=2", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("page 1 request: %v", err)
	}
	defer resp.Body.Close()

	var p1 struct {
		Users      []map[string]any `json:"users"`
		NextCursor string           `json:"next_cursor"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&p1); err != nil {
		t.Fatalf("decode page 1: %v", err)
	}
	if len(p1.Users) != 2 {
		t.Fatalf("page 1 expected 2 users, got %d", len(p1.Users))
	}
	if p1.NextCursor == "" {
		t.Fatal("page 1 should have a next_cursor")
	}

	req2, _ := http.NewRequest("GET", ts.URL+"/internal/users?limit=2&cursor="+p1.NextCursor, nil)
	req2.Header.Set("Authorization", "Bearer test-secret")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("page 2 request: %v", err)
	}
	defer resp2.Body.Close()

	var p2 struct {
		Users      []map[string]any `json:"users"`
		NextCursor string           `json:"next_cursor"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&p2); err != nil {
		t.Fatalf("decode page 2: %v", err)
	}
	if len(p2.Users) != 1 {
		t.Fatalf("page 2 expected 1 user, got %d", len(p2.Users))
	}
	if p2.NextCursor != "" {
		t.Fatalf("page 2 should not have a next_cursor, got %q", p2.NextCursor)
	}
}
