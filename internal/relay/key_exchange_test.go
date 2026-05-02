package relay

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cinchv1 "github.com/cinchcli/relay/internal/gen/cinch/v1"
	"github.com/cinchcli/relay/internal/protocol"
	"github.com/gorilla/websocket"
)

// keyExchangeTestServer mirrors buildRevokeTestServer — fresh in-memory
// store/hub/handler/test server. Returned for direct access.
func keyExchangeTestServer(t *testing.T) (*httptest.Server, *Store, *Hub) {
	t.Helper()

	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	hub := NewHub()
	go hub.Run()

	handler := NewHandler(store, hub)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	return ts, store, hub
}

// keyExchangeLogin opens a fresh OAuth-only login and returns the per-device
// token, user_id and device_id.
func keyExchangeLogin(t *testing.T, ts *httptest.Server, hostname string) (token, userID, deviceID string) {
	t.Helper()

	body, _ := json.Marshal(cinchv1.LoginRequest{Hostname: stringPtr(hostname)})
	resp, err := http.Post(ts.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	var lr cinchv1.LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	return lr.Token, lr.UserId, lr.DeviceId
}

// TestKeyBundleGet_ReturnsPendingSinceWhenAwaiting verifies the new
// always-200 contract: when the device has registered a public key but
// no bundle has been saved yet, GET /auth/key-bundle returns 200 with
// empty ephemeral/bundle fields and a non-empty pending_since timestamp.
func TestKeyBundleGet_ReturnsPendingSinceWhenAwaiting(t *testing.T) {
	ts, store, _ := keyExchangeTestServer(t)
	token, _, deviceID := keyExchangeLogin(t, ts, "host-a")

	if err := store.SetDevicePublicKey(deviceID, "test-pubkey-b64", "deadbeef"); err != nil {
		t.Fatalf("set pubkey: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth/key-bundle", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get key bundle: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 (always-200 contract), got %d", resp.StatusCode)
	}
	var got KeyBundleResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.EphemeralPublicKey != "" || got.EncryptedBundle != "" {
		t.Fatalf("expected empty bundle fields, got eph=%q bundle=%q", got.EphemeralPublicKey, got.EncryptedBundle)
	}
	if got.PendingSince == "" {
		t.Fatalf("expected pending_since to be set")
	}
	if _, perr := time.Parse(time.RFC3339, got.PendingSince); perr != nil {
		t.Fatalf("pending_since not RFC3339: %v (%q)", perr, got.PendingSince)
	}
}

// TestKeyBundleRetry_BroadcastsToUser verifies POST /auth/key-bundle/retry
// emits a key_exchange_requested WS message to every device on the user's
// account. The retrying device itself is the natural listener target.
//
// The bearer (a second device on the same account) connects FIRST, before
// any public key is registered, so the on-connect "pending key exchanges"
// auto-broadcast finds nothing — guaranteeing the message we receive is
// the one produced by /auth/key-bundle/retry, not the on-connect sweep.
func TestKeyBundleRetry_BroadcastsToUser(t *testing.T) {
	ts, store, _ := keyExchangeTestServer(t)

	// Bearer device — owns the user_key, will be the WS listener.
	bearerToken, _, _ := keyExchangeLogin(t, ts, "host-bearer")
	wsURL := strings.Replace(ts.URL, "http://", "ws://", 1) + "/ws?token=" + bearerToken
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer conn.Close()

	// No pre-broadcast drain: the bearer connected with no pending key
	// exchanges, so the on-connect sweep writes nothing. Adding a
	// deadline-bounded "drain" read would put gorilla's conn into an
	// indeterminate state after timing out and corrupt subsequent reads.

	// Newcomer device — registers a public key and asks for a re-broadcast.
	newcomerToken, _, newcomerID := keyExchangeLogin(t, ts, "host-newcomer")
	// The two logins here both call /auth/login which currently creates a
	// fresh user per call, so the broadcast WOULD NOT reach the bearer.
	// Re-parent the newcomer onto the bearer's account by direct store edit.
	bearerUserID, err := store.DeviceOwner(deviceIDFromToken(t, store, bearerToken))
	if err != nil {
		t.Fatalf("bearer owner: %v", err)
	}
	if _, err := store.db.Exec("UPDATE devices SET user_id = ? WHERE id = ?", bearerUserID, newcomerID); err != nil {
		t.Fatalf("re-parent: %v", err)
	}
	if err := store.SetDevicePublicKey(newcomerID, "newcomer-pubkey-b64", "deadbeef"); err != nil {
		t.Fatalf("set pubkey: %v", err)
	}

	// Verify reparenting actually took effect: newcomer's owner should be bearerUserID.
	if got, _ := store.DeviceOwner(newcomerID); got != bearerUserID {
		t.Fatalf("reparent failed: got %q want %q", got, bearerUserID)
	}

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/auth/key-bundle/retry", nil)
	req.Header.Set("Authorization", "Bearer "+newcomerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg protocol.WSMessage
	if err := conn.ReadJSON(&msg); err != nil {
		t.Fatalf("read ws: %v", err)
	}
	if msg.Action != protocol.ActionKeyExchangeRequested {
		t.Fatalf("expected action %q, got %q", protocol.ActionKeyExchangeRequested, msg.Action)
	}
	if msg.DeviceID != newcomerID {
		t.Fatalf("expected device %q, got %q", newcomerID, msg.DeviceID)
	}
	if msg.Hostname != "host-newcomer" {
		t.Fatalf("expected hostname %q, got %q", "host-newcomer", msg.Hostname)
	}
}

// deviceIDFromToken is a test helper that resolves a device ID from a bearer token.
func deviceIDFromToken(t *testing.T, store *Store, token string) string {
	t.Helper()
	id, _, err := store.DeviceIDByToken(token)
	if err != nil {
		t.Fatalf("DeviceIDByToken: %v", err)
	}
	return id
}

// TestKeyBundleRetry_NoPubKeyReturns400 verifies retry refuses when the
// device hasn't yet registered a public key — there is nothing for a
// key-bearer to encrypt against.
func TestKeyBundleRetry_NoPubKeyReturns400(t *testing.T) {
	ts, _, _ := keyExchangeTestServer(t)
	token, _, _ := keyExchangeLogin(t, ts, "host-a")

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/auth/key-bundle/retry", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 (no pubkey), got %d", resp.StatusCode)
	}
}
