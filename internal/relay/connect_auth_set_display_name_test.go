package relay_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"
	cinchv1 "github.com/cinchcli/relay/internal/cinchv1"
	"github.com/cinchcli/relay/internal/cinchv1/cinchv1connect"
)

func TestSetDisplayName_HappyPath(t *testing.T) {
	ts, _, store := setupTestServerWithStore(t)

	token, _, userID := login(t, ts.URL)

	client := cinchv1connect.NewAuthServiceClient(http.DefaultClient, ts.URL)
	req := connect.NewRequest(&cinchv1.SetDisplayNameRequest{DisplayName: "  New Name  "})
	req.Header().Set("Authorization", "Bearer "+token)

	resp, err := client.SetDisplayName(context.Background(), req)
	if err != nil {
		t.Fatalf("SetDisplayName: %v", err)
	}
	if !resp.Msg.Ok || resp.Msg.DisplayName != "New Name" {
		t.Fatalf("unexpected response: %+v", resp.Msg)
	}

	var stored string
	_ = store.DB().QueryRow(`SELECT display_name FROM users WHERE id = $1`, userID).Scan(&stored)
	if stored != "New Name" {
		t.Fatalf("stored = %q, want %q", stored, "New Name")
	}
}

func TestSetDisplayName_RejectsEmpty(t *testing.T) {
	ts, _, _ := setupTestServerWithStore(t)
	token, _, _ := login(t, ts.URL)

	client := cinchv1connect.NewAuthServiceClient(http.DefaultClient, ts.URL)
	req := connect.NewRequest(&cinchv1.SetDisplayNameRequest{DisplayName: "   "})
	req.Header().Set("Authorization", "Bearer "+token)

	_, err := client.SetDisplayName(context.Background(), req)
	if err == nil || connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestSetDisplayName_RejectsTooLong(t *testing.T) {
	ts, _, _ := setupTestServerWithStore(t)
	token, _, _ := login(t, ts.URL)

	client := cinchv1connect.NewAuthServiceClient(http.DefaultClient, ts.URL)
	long := strings.Repeat("a", 65)
	req := connect.NewRequest(&cinchv1.SetDisplayNameRequest{DisplayName: long})
	req.Header().Set("Authorization", "Bearer "+token)

	_, err := client.SetDisplayName(context.Background(), req)
	if err == nil || connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestSetDisplayName_RequiresAuth(t *testing.T) {
	ts, _, _ := setupTestServerWithStore(t)

	client := cinchv1connect.NewAuthServiceClient(http.DefaultClient, ts.URL)
	req := connect.NewRequest(&cinchv1.SetDisplayNameRequest{DisplayName: "Alice"})
	// intentionally no Authorization header

	_, err := client.SetDisplayName(context.Background(), req)
	if err == nil || connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

func TestSetDisplayName_REST_HappyPath(t *testing.T) {
	ts, _, store := setupTestServerWithStore(t)
	token, _, userID := login(t, ts.URL)

	body := strings.NewReader(`{"display_name":"  Alice  "}`)
	req, _ := http.NewRequest("POST", ts.URL+"/auth/display-name", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(b))
	}
	var got struct {
		Ok          bool   `json:"ok"`
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !got.Ok || got.DisplayName != "Alice" {
		t.Fatalf("got %+v", got)
	}

	var stored string
	_ = store.DB().QueryRow(`SELECT display_name FROM users WHERE id = $1`, userID).Scan(&stored)
	if stored != "Alice" {
		t.Fatalf("stored = %q", stored)
	}
}

func TestSetDisplayName_REST_RejectsEmpty(t *testing.T) {
	ts, _, _ := setupTestServerWithStore(t)
	_, _, _ = login(t, ts.URL)
	token, _, _ := login(t, ts.URL)

	body := strings.NewReader(`{"display_name":"   "}`)
	req, _ := http.NewRequest("POST", ts.URL+"/auth/display-name", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestSetDisplayName_REST_RejectsTooLong(t *testing.T) {
	ts, _, _ := setupTestServerWithStore(t)
	token, _, _ := login(t, ts.URL)

	long := strings.Repeat("a", 65)
	payload, _ := json.Marshal(map[string]string{"display_name": long})
	req, _ := http.NewRequest("POST", ts.URL+"/auth/display-name", strings.NewReader(string(payload)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestSetDisplayName_REST_AcceptsExactly64Bytes(t *testing.T) {
	ts, _, _ := setupTestServerWithStore(t)
	token, _, _ := login(t, ts.URL)

	exact := strings.Repeat("a", 64)
	payload, _ := json.Marshal(map[string]string{"display_name": exact})
	req, _ := http.NewRequest("POST", ts.URL+"/auth/display-name", strings.NewReader(string(payload)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(b))
	}
}

func TestSetDisplayName_REST_RequiresAuth(t *testing.T) {
	ts, _, _ := setupTestServerWithStore(t)
	_, _, _ = login(t, ts.URL) // ensure store has data but don't use token

	body := strings.NewReader(`{"display_name":"Alice"}`)
	req, _ := http.NewRequest("POST", ts.URL+"/auth/display-name", body)
	req.Header.Set("Content-Type", "application/json")
	// intentionally no Authorization header
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}
