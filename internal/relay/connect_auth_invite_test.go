package relay_test

import (
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"

	cinchv1 "github.com/cinchcli/cinch-core/go/cinch/v1"
	"github.com/cinchcli/cinch-core/go/cinch/v1/cinchv1connect"
	relay "github.com/cinchcli/relay/internal/relay"
)

func TestConnectLogin_RejectsWithoutInvite(t *testing.T) {
	ts, _, _ := setupTestServerWithStore(t)

	client := cinchv1connect.NewAuthServiceClient(http.DefaultClient, ts.URL)
	_, err := client.Login(t.Context(), connect.NewRequest(&cinchv1.LoginRequest{}))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("expected CodePermissionDenied, got %v: %v", connect.CodeOf(err), err)
	}
}

func TestConnectLogin_AcceptsValidInvite_FirstUserBecomesAdmin(t *testing.T) {
	ts, _, store := setupTestServerWithStore(t)

	code := "cinch_inv_connect_first"
	hash := relay.HashInviteCode(code)
	if err := store.CreateInvite(hash, nil, "bootstrap", 1, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	hostname := "connect-host"
	display := "han"
	client := cinchv1connect.NewAuthServiceClient(http.DefaultClient, ts.URL)
	resp, err := client.Login(t.Context(), connect.NewRequest(&cinchv1.LoginRequest{
		Hostname:    &hostname,
		InviteCode:  &code,
		DisplayName: &display,
	}))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if resp.Msg.UserId == "" {
		t.Fatal("empty user_id in response")
	}

	admin, err := store.IsUserAdmin(resp.Msg.UserId)
	if err != nil {
		t.Fatalf("IsUserAdmin: %v", err)
	}
	if !admin {
		t.Fatal("first user via Connect Login should be admin")
	}

	users, err := store.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 || users[0].DisplayName != "han" {
		t.Fatalf("user row wrong: %+v", users)
	}
}

func TestConnectLogin_RejectsExhaustedInvite(t *testing.T) {
	ts, _, store := setupTestServerWithStore(t)

	code := "cinch_inv_connect_exhaust"
	hash := relay.HashInviteCode(code)
	if err := store.CreateInvite(hash, nil, "", 1, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := store.RedeemInvite(hash); err != nil {
		t.Fatalf("pre-consume: %v", err)
	}

	client := cinchv1connect.NewAuthServiceClient(http.DefaultClient, ts.URL)
	_, err := client.Login(t.Context(), connect.NewRequest(&cinchv1.LoginRequest{
		InviteCode: &code,
	}))
	if err == nil {
		t.Fatal("expected error for exhausted invite, got nil")
	}
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("expected CodePermissionDenied, got %v: %v", connect.CodeOf(err), err)
	}
}
