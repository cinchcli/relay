package relay_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"
	cinchv1 "github.com/cinchcli/cinch-core/go/cinch/v1"
	"github.com/cinchcli/cinch-core/go/cinch/v1/cinchv1connect"
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
