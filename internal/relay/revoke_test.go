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

// stringPtr returns a pointer to the given string. Used for proto3 optional
// fields (cinchv1.PairRequest.Hostname etc.) in test struct literals.
func stringPtr(s string) *string { return &s }

// buildRevokeTestServer spins up a fresh in-memory store + hub + handler + http test server.
// Returns the test server, store, and hub for direct-access assertions.
func buildRevokeTestServer(t *testing.T) (*httptest.Server, *Store, *Hub) {
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

// loginAndPair creates a user and pairs a device; returns the device-specific token,
// user_id, and device_id.
func loginAndPair(t *testing.T, ts *httptest.Server, hostname string) (deviceToken, userID, deviceID string) {
	t.Helper()

	// Login to get master token + pair_token.
	resp, err := http.Post(ts.URL+"/auth/login", "application/json", nil)
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

	// Pair to get a per-device token.
	reqBody, _ := json.Marshal(cinchv1.PairRequest{
		PairToken: loginResp.PairToken,
		Hostname:  &hostname,
	})
	pairResp, err := http.Post(ts.URL+"/auth/pair", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	defer pairResp.Body.Close()
	if pairResp.StatusCode != http.StatusOK {
		t.Fatalf("pair status %d", pairResp.StatusCode)
	}
	pr := &cinchv1.PairResponse{}
	if err := json.NewDecoder(pairResp.Body).Decode(pr); err != nil {
		t.Fatalf("decode pair: %v", err)
	}
	if pr.Token == "" || pr.UserId == "" || pr.DeviceId == "" {
		t.Fatalf("pair response missing fields: token=%q user_id=%q device_id=%q", pr.Token, pr.UserId, pr.DeviceId)
	}
	return pr.Token, pr.UserId, pr.DeviceId
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
func TestRevokeDevice_OtherDeviceUnaffected(t *testing.T) {
	ts, _, _ := buildRevokeTestServer(t)

	// Login once (user A master creds).
	resp, err := http.Post(ts.URL+"/auth/login", "application/json", nil)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	var loginA cinchv1.LoginResponse
	json.NewDecoder(resp.Body).Decode(&loginA)
	resp.Body.Close()

	// Pair device A using the pair token.
	pairBodyA, _ := json.Marshal(cinchv1.PairRequest{PairToken: loginA.PairToken, Hostname: stringPtr("host-a")})
	pairRespA, err := http.Post(ts.URL+"/auth/pair", "application/json", bytes.NewReader(pairBodyA))
	if err != nil {
		t.Fatalf("pair A: %v", err)
	}
	var prA cinchv1.PairResponse
	json.NewDecoder(pairRespA.Body).Decode(&prA)
	pairRespA.Body.Close()

	// Regenerate a new pair token via the new /auth/pair-token/new endpoint (using A's device token).
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/auth/pair-token/new", nil)
	req.Header.Set("Authorization", "Bearer "+prA.Token)
	regResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("regen pair token: %v", err)
	}
	if regResp.StatusCode != http.StatusOK {
		t.Fatalf("regen status %d", regResp.StatusCode)
	}
	var regOut cinchv1.RotatePairTokenResponse
	json.NewDecoder(regResp.Body).Decode(&regOut)
	regResp.Body.Close()

	// Pair device B with the new pair token.
	pairBodyB, _ := json.Marshal(cinchv1.PairRequest{PairToken: regOut.PairToken, Hostname: stringPtr("host-b")})
	pairRespB, err := http.Post(ts.URL+"/auth/pair", "application/json", bytes.NewReader(pairBodyB))
	if err != nil {
		t.Fatalf("pair B: %v", err)
	}
	var prB cinchv1.PairResponse
	json.NewDecoder(pairRespB.Body).Decode(&prB)
	pairRespB.Body.Close()

	if prA.DeviceId == prB.DeviceId {
		t.Fatalf("two pairings returned the same device_id: %s", prA.DeviceId)
	}
	if prA.Token == prB.Token {
		t.Fatalf("two pairings returned the same token (AUTH-01 violation)")
	}

	// Revoke B.
	revokeBody, _ := json.Marshal(cinchv1.RevokeDeviceRequest{DeviceId: prB.DeviceId})
	revokeReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/auth/device/revoke", bytes.NewReader(revokeBody))
	revokeReq.Header.Set("Content-Type", "application/json")
	revokeReq.Header.Set("Authorization", "Bearer "+prB.Token)
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
	listReq.Header.Set("Authorization", "Bearer "+prA.Token)
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
	listReqB.Header.Set("Authorization", "Bearer "+prB.Token)
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
