package relay

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cinchv1 "github.com/cinchcli/relay/internal/cinchv1"
	"github.com/cinchcli/relay/internal/protocol"
	"github.com/gorilla/websocket"
)

// stringPtr returns a pointer to the given string. Used for proto3 optional
// fields (cinchv1.LoginRequest.Hostname etc.) in test struct literals.
func stringPtr(s string) *string { return &s }

// buildRevokeTestServer spins up a fresh in-memory store + hub + handler + http test server.
// Returns the test server, store, and hub for direct-access assertions.
func buildRevokeTestServer(t *testing.T) (*httptest.Server, *Store, *Hub) {
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

// loginAndPair creates a user + first device row in one shot via
// POST /auth/login. After the OAuth-only migration the login response
// carries a usable per-device token directly — there is no separate
// pair step. Returns the device token, user_id and device_id.
func loginAndPair(t *testing.T, ts *httptest.Server, hostname string) (deviceToken, userID, deviceID string) {
	t.Helper()

	body, _ := json.Marshal(cinchv1.LoginRequest{
		Hostname:   &hostname,
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
	var loginResp cinchv1.LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	if loginResp.Token == "" || loginResp.UserId == "" || loginResp.DeviceId == "" {
		t.Fatalf("login response missing fields: token=%q user_id=%q device_id=%q",
			loginResp.Token, loginResp.UserId, loginResp.DeviceId)
	}
	return loginResp.Token, loginResp.UserId, loginResp.DeviceId
}

// TestRevokeDeviceAuthz — cross-user revoke returns 404 "device_not_found"
// (NOT 403 — no existence oracle per RESEARCH Pitfall 5).
func TestRevokeDeviceAuthz(t *testing.T) {
	ts, _, _ := buildRevokeTestServer(t)

	// User A pairs a device.
	_, _, deviceA := loginAndPair(t, ts, "host-a")

	// User B (different account) tries to revoke A's device.
	tokenB, _, _ := loginAndPair(t, ts, "host-b")

	reqBody, _ := json.Marshal(cinchv1.RevokeDeviceRequest{DeviceId: deviceA})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/auth/device/revoke", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tokenB)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for cross-user revoke (no existence oracle), got %d", resp.StatusCode)
	}
	var errResp cinchv1.ErrorResponse
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp.Error != "device_not_found" {
		t.Errorf("expected error=device_not_found, got %q", errResp.Error)
	}
}

// TestRevokedTokenResponse — after revoke, subsequent HTTP returns 401 "device_revoked"
// (distinct from "invalid token").
func TestRevokedTokenResponse(t *testing.T) {
	ts, _, _ := buildRevokeTestServer(t)

	token, _, deviceID := loginAndPair(t, ts, "host-victim")

	// Revoke self.
	reqBody, _ := json.Marshal(cinchv1.RevokeDeviceRequest{DeviceId: deviceID})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/auth/device/revoke", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("self-revoke expected 200, got %d", resp.StatusCode)
	}

	// Subsequent request with the same token must now 401 with error="device_revoked".
	listReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/clips", nil)
	listReq.Header.Set("Authorization", "Bearer "+token)
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer listResp.Body.Close()

	if listResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", listResp.StatusCode)
	}
	var errResp cinchv1.ErrorResponse
	if err := json.NewDecoder(listResp.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if errResp.Error != "device_revoked" {
		t.Errorf("expected error=device_revoked, got %q (message=%q)", errResp.Error, errResp.Message)
	}
}

// TestRevokeWSPush — a device with an active AgentConn receives {action:"revoked", reason:"revoked_by_user"}
// when its device_id is revoked.
func TestRevokeWSPush(t *testing.T) {
	ts, _, _ := buildRevokeTestServer(t)

	token, _, deviceID := loginAndPair(t, ts, "host-ws-victim")

	// Connect fake agent over WS.
	wsURL := strings.Replace(ts.URL, "http://", "ws://", 1) + "/ws?token=" + token
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer conn.Close()

	// Give Register() a moment to attach the conn to the hub.
	time.Sleep(50 * time.Millisecond)

	// Trigger revoke.
	reqBody, _ := json.Marshal(cinchv1.RevokeDeviceRequest{DeviceId: deviceID})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/auth/device/revoke", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke expected 200, got %d", resp.StatusCode)
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var msg protocol.WSMessage
	if err := conn.ReadJSON(&msg); err != nil {
		t.Fatalf("no revoked message received: %v", err)
	}
	if msg.Action != protocol.ActionRevoked {
		t.Errorf("expected action=%q, got %q", protocol.ActionRevoked, msg.Action)
	}
	if msg.Reason != "revoked_by_user" {
		t.Errorf("expected reason=revoked_by_user, got %q", msg.Reason)
	}
}

// TestRevokeDevice_OtherDeviceUnaffected — revoking device B keeps device A functional.
//
// The pair-token bootstrap was retired in the OAuth-only migration so we
// emulate "two devices on one account" by minting device A via /auth/login
// and adding device B directly via the store with the same user_id. Token
// uniqueness across devices is still asserted.
func TestRevokeDevice_OtherDeviceUnaffected(t *testing.T) {
	ts, store, _ := buildRevokeTestServer(t)

	tokenA, userID, deviceA := loginAndPair(t, ts, "host-a")

	// Mint a second device for the same user, directly via the store.
	deviceB := "01DEVICEBSAMEUSER000000000"
	tokenB := "device-b-token-" + deviceB
	if err := store.RegisterDeviceWithToken(userID, deviceB, "host-b", tokenB); err != nil {
		t.Fatalf("register device B: %v", err)
	}
	if tokenA == tokenB {
		t.Fatalf("device A and B returned the same token (AUTH-01 violation)")
	}
	if deviceA == deviceB {
		t.Fatalf("device A and B returned the same id: %s", deviceA)
	}

	// Revoke B.
	revokeBody, _ := json.Marshal(cinchv1.RevokeDeviceRequest{DeviceId: deviceB})
	revokeReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/auth/device/revoke", bytes.NewReader(revokeBody))
	revokeReq.Header.Set("Content-Type", "application/json")
	revokeReq.Header.Set("Authorization", "Bearer "+tokenB)
	revokeResp, err := http.DefaultClient.Do(revokeReq)
	if err != nil {
		t.Fatalf("revoke B: %v", err)
	}
	revokeResp.Body.Close()
	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke B expected 200, got %d", revokeResp.StatusCode)
	}

	// Device A should still be able to list clips.
	listReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/clips", nil)
	listReq.Header.Set("Authorization", "Bearer "+tokenA)
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("list A: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("device A should still be usable after revoking B, got %d", listResp.StatusCode)
	}

	// Device B's token must 401 with device_revoked.
	listReqB, _ := http.NewRequest(http.MethodGet, ts.URL+"/clips", nil)
	listReqB.Header.Set("Authorization", "Bearer "+tokenB)
	listRespB, err := http.DefaultClient.Do(listReqB)
	if err != nil {
		t.Fatalf("list B: %v", err)
	}
	defer listRespB.Body.Close()
	if listRespB.StatusCode != http.StatusUnauthorized {
		t.Fatalf("device B expected 401 after revoke, got %d", listRespB.StatusCode)
	}
	var errResp cinchv1.ErrorResponse
	json.NewDecoder(listRespB.Body).Decode(&errResp)
	if errResp.Error != "device_revoked" {
		t.Errorf("expected device_revoked, got %q", errResp.Error)
	}
}
