package relay_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	cinchv1 "github.com/cinchcli/cinch-core/go/cinch/v1"
	relay "github.com/cinchcli/relay/internal/relay"
)

func TestAuthLogin_RejectsWithoutInvite(t *testing.T) {
	ts, _, _ := setupTestServerWithStore(t)

	// Post with no invite_code field at all.
	body := strings.NewReader(`{}`)
	resp, err := http.Post(ts.URL+"/auth/login", "application/json", body)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAuthLogin_AcceptsValidInvite_FirstUserBecomesAdmin(t *testing.T) {
	ts, _, store := setupTestServerWithStore(t)

	code := "cinch_inv_first1"
	hash := relay.HashInviteCode(code)
	if err := store.CreateInvite(hash, nil, "bootstrap", 1, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	hostname := "macbook"
	display := "han"
	payload, _ := json.Marshal(cinchv1.LoginRequest{
		Hostname:    &hostname,
		InviteCode:  &code,
		DisplayName: &display,
	})
	resp, err := http.Post(ts.URL+"/auth/login", "application/json", strings.NewReader(string(payload)))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var loginResp cinchv1.LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if loginResp.UserId == "" {
		t.Fatal("empty user_id")
	}

	admin, err := store.IsUserAdmin(loginResp.UserId)
	if err != nil {
		t.Fatalf("IsUserAdmin: %v", err)
	}
	if !admin {
		t.Fatal("first user should be admin")
	}

	users, err := store.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 || users[0].DisplayName != "han" {
		t.Fatalf("user row wrong: %+v", users)
	}
}

func TestAuthLogin_RejectsExhaustedInvite(t *testing.T) {
	ts, _, store := setupTestServerWithStore(t)

	code := "cinch_inv_exhaust"
	hash := relay.HashInviteCode(code)
	if err := store.CreateInvite(hash, nil, "", 1, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Pre-consume the one allowed use.
	if err := store.RedeemInvite(hash); err != nil {
		t.Fatalf("pre-consume failed: %v", err)
	}

	payload, _ := json.Marshal(cinchv1.LoginRequest{InviteCode: &code})
	resp, err := http.Post(ts.URL+"/auth/login", "application/json", strings.NewReader(string(payload)))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}
