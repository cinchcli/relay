package relay

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cinchv1 "github.com/cinchcli/cinch-core/go/cinch/v1"
	"github.com/cinchcli/relay/internal/protocol"
	"github.com/gorilla/websocket"
)

// keyExchangeTestServer mirrors buildRevokeTestServer — fresh
// store/hub/handler/test server backed by TEST_DATABASE_URL.
func keyExchangeTestServer(t *testing.T) (*httptest.Server, *Store, *Hub) {
	t.Helper()

	store := newTestStore(t)
	installTestBootstrapInvite(t, store)

	hub := NewHub()
	go hub.Run()

	handler := NewHandler(store, hub)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	return ts, store, hub
}

// keyExchangeLogin opens a fresh login and returns the per-device token, user_id and device_id.
func keyExchangeLogin(t *testing.T, ts *httptest.Server, hostname string) (token, userID, deviceID string) {
	t.Helper()

	body, _ := json.Marshal(cinchv1.LoginRequest{
		Hostname:   stringPtr(hostname),
		InviteCode: stringPtr(testBootstrapInviteCode),
	})
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
	if _, err := store.db.Exec("UPDATE devices SET user_id = $1 WHERE id = $2", bearerUserID, newcomerID); err != nil {
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

// TestRegisterDevicePublicKey_StoresAndShowsAsPending verifies POST
// /auth/device/public-key writes the key into the device row and that
// GetKeyBundle then surfaces a non-empty pending_since timestamp — proof
// that the device is now visible to ListPendingKeyExchanges sweeps.
func TestRegisterDevicePublicKey_StoresAndShowsAsPending(t *testing.T) {
	ts, _, _ := keyExchangeTestServer(t)
	token, _, _ := keyExchangeLogin(t, ts, "host-a")

	body, _ := json.Marshal(RegisterPublicKeyRequest{
		PublicKey:   "test-pubkey-b64",
		Fingerprint: "deadbeef",
	})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/auth/device/public-key", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register status %d", resp.StatusCode)
	}

	getReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth/key-bundle", nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("get key bundle: %v", err)
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 (always-200 contract), got %d", getResp.StatusCode)
	}
	var got KeyBundleResponse
	if err := json.NewDecoder(getResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.PendingSince == "" {
		t.Fatalf("expected pending_since to be set after RegisterDevicePublicKey")
	}
	if _, perr := time.Parse(time.RFC3339, got.PendingSince); perr != nil {
		t.Fatalf("pending_since not RFC3339: %v (%q)", perr, got.PendingSince)
	}
}

// TestRegisterDevicePublicKey_RequiresFields verifies the endpoint
// rejects requests missing public_key or fingerprint with 400.
func TestRegisterDevicePublicKey_RequiresFields(t *testing.T) {
	ts, _, _ := keyExchangeTestServer(t)
	token, _, _ := keyExchangeLogin(t, ts, "host-a")

	cases := []struct {
		name string
		body RegisterPublicKeyRequest
	}{
		{"missing public_key", RegisterPublicKeyRequest{Fingerprint: "deadbeef"}},
		{"missing fingerprint", RegisterPublicKeyRequest{PublicKey: "test-pubkey-b64"}},
		{"both empty", RegisterPublicKeyRequest{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.body)
			req, _ := http.NewRequest(http.MethodPost, ts.URL+"/auth/device/public-key", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("register: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", resp.StatusCode)
			}
		})
	}
}

// TestRegisterDevicePublicKey_RotationClearsStaleBundle verifies the
// re-pair regression: when a device rotates its X25519 keypair (e.g.
// `cinch auth login --force` reuses the same device row but generates a
// fresh device keypair), the relay-stored encrypted_key_bundle from the
// previous pubkey is invalidated. Without this, the next
// poll_key_bundle would return the stale ciphertext and the device
// would AEAD-fail to decrypt.
func TestRegisterDevicePublicKey_RotationClearsStaleBundle(t *testing.T) {
	ts, store, _ := keyExchangeTestServer(t)
	token, _, deviceID := keyExchangeLogin(t, ts, "host-rotating")

	if err := store.SetDevicePublicKey(deviceID, "pubkey-A", "fp-A"); err != nil {
		t.Fatalf("set pubkey A: %v", err)
	}
	if err := store.SaveKeyBundle(deviceID, "eph-pub-A", "encrypted-under-A"); err != nil {
		t.Fatalf("save bundle: %v", err)
	}

	// Pre-rotation: bundle is present.
	getReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth/key-bundle", nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	preResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("get pre-rotation: %v", err)
	}
	defer preResp.Body.Close()
	var pre KeyBundleResponse
	if err := json.NewDecoder(preResp.Body).Decode(&pre); err != nil {
		t.Fatalf("decode pre: %v", err)
	}
	if pre.EncryptedBundle != "encrypted-under-A" {
		t.Fatalf("pre: expected stored bundle, got %q", pre.EncryptedBundle)
	}

	// Re-register with a different pubkey (simulating a fresh keypair on re-pair).
	body, _ := json.Marshal(RegisterPublicKeyRequest{PublicKey: "pubkey-B", Fingerprint: "fp-B"})
	regReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/auth/device/public-key", bytes.NewReader(body))
	regReq.Header.Set("Authorization", "Bearer "+token)
	regReq.Header.Set("Content-Type", "application/json")
	regResp, err := http.DefaultClient.Do(regReq)
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	defer regResp.Body.Close()
	if regResp.StatusCode != http.StatusOK {
		t.Fatalf("re-register status %d", regResp.StatusCode)
	}

	// Post-rotation: bundle must be cleared (empty fields + non-empty pending_since).
	postReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth/key-bundle", nil)
	postReq.Header.Set("Authorization", "Bearer "+token)
	postResp, err := http.DefaultClient.Do(postReq)
	if err != nil {
		t.Fatalf("get post-rotation: %v", err)
	}
	defer postResp.Body.Close()
	var post KeyBundleResponse
	if err := json.NewDecoder(postResp.Body).Decode(&post); err != nil {
		t.Fatalf("decode post: %v", err)
	}
	if post.EncryptedBundle != "" || post.EphemeralPublicKey != "" {
		t.Fatalf("post: expected cleared bundle, got eph=%q bundle=%q",
			post.EphemeralPublicKey, post.EncryptedBundle)
	}
	if post.PendingSince == "" {
		t.Fatalf("post: expected pending_since to be set after rotation")
	}
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
