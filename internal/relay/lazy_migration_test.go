package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cinchcli/protocol"
	"github.com/gorilla/websocket"
)

// buildLazyMigrationServer is a fresh relay with an in-memory store.
func buildLazyMigrationServer(t *testing.T) (*httptest.Server, *Store) {
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
	return ts, store
}

// TestLazyMigrationWSHandshake — a pre-Phase-2 master token (no devices.token row)
// should trigger the WS upgrade handler to:
//  1. mint a new devices row with a fresh per-device token + device_id
//  2. push {action:"token_rotated", token:<new>, device_id:<id>, hostname:<derived or "unknown">}
//     as the first message the client sees.
func TestLazyMigrationWSHandshake(t *testing.T) {
	ts, store := buildLazyMigrationServer(t)

	// Emulate a pre-Phase-2 user: login normally. The migration codepath in AuthLogin
	// should register the login device, but the lazy-migration path is tested by
	// forcefully deleting the associated devices row so users.token is the only
	// valid token (the pre-Phase-2 shape).
	resp, err := http.Post(ts.URL+"/auth/login", "application/json", nil)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	var loginResp protocol.AuthLoginResponse
	json.NewDecoder(resp.Body).Decode(&loginResp)

	// Remove any devices rows + reset token_migrated_at to emulate a pre-Phase-2 DB
	// so the WS-upgrade path sees: valid users.token, DeviceIDByToken(token) == sql.ErrNoRows.
	if _, err := store.ExecForTest("DELETE FROM devices WHERE user_id = ?", loginResp.UserID); err != nil {
		t.Fatalf("reset devices: %v", err)
	}
	if _, err := store.ExecForTest("UPDATE users SET token_migrated_at = NULL WHERE id = ?", loginResp.UserID); err != nil {
		t.Fatalf("reset token_migrated_at: %v", err)
	}

	// Dial WS with the legacy master token, with hostname query param for derivation.
	wsURL := strings.Replace(ts.URL, "http://", "ws://", 1) + "/ws?token=" + loginResp.Token + "&hostname=legacy-host"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var msg protocol.WSMessage
	if err := conn.ReadJSON(&msg); err != nil {
		t.Fatalf("reading first WS message: %v", err)
	}

	if msg.Action != protocol.ActionTokenRotated {
		t.Fatalf("expected first message action=%q, got %q", protocol.ActionTokenRotated, msg.Action)
	}
	if msg.Token == "" {
		t.Error("token_rotated payload missing Token")
	}
	if msg.Token == loginResp.Token {
		t.Error("token_rotated returned the old master token — should be a fresh per-device token")
	}
	if msg.DeviceID == "" {
		t.Error("token_rotated payload missing DeviceID")
	}
	if msg.Hostname == "" {
		t.Error("token_rotated payload missing Hostname (should be UA-derived or query param or 'unknown')")
	}

	// Verify the devices row was created with the new token.
	var dbToken string
	var dbDeviceID string
	err = store.db.QueryRow(`SELECT id, token FROM devices WHERE user_id = ?`, loginResp.UserID).Scan(&dbDeviceID, &dbToken)
	if err != nil {
		t.Fatalf("devices row not created: %v", err)
	}
	if dbToken != msg.Token {
		t.Errorf("DB token %q != rotated token %q", dbToken, msg.Token)
	}
	if dbDeviceID != msg.DeviceID {
		t.Errorf("DB device_id %q != rotated device_id %q", dbDeviceID, msg.DeviceID)
	}

	// users.token_migrated_at must now be non-null (grace-window bookkeeping).
	var migratedAt string
	if err := store.db.QueryRow("SELECT COALESCE(token_migrated_at,'') FROM users WHERE id = ?", loginResp.UserID).Scan(&migratedAt); err != nil {
		t.Fatalf("querying token_migrated_at: %v", err)
	}
	if migratedAt == "" {
		t.Error("users.token_migrated_at not stamped after lazy migration")
	}
}

// TestGraceSweeper — SweepMigratedMasterTokens invalidates users.token rows where
// token_migrated_at < cutoff. Returns the count of invalidated rows. Idempotent.
// 7-day constant comes from the plan's graceWindow (7 * 24 * time.Hour).
func TestGraceSweeper(t *testing.T) {
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer store.Close()

	// Insert a user with token_migrated_at = now-8d (stale).
	token := "stale-master-token"
	if err := store.CreateUser("01STALEUSER00000000000000", token, ""); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := store.ExecForTest(
		`UPDATE users SET token_migrated_at = datetime('now', '-8 days') WHERE id = ?`,
		"01STALEUSER00000000000000",
	); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	// Insert a user with token_migrated_at = now-1d (fresh — not swept).
	if err := store.CreateUser("01FRESHUSER00000000000000", "fresh-token", ""); err != nil {
		t.Fatalf("create fresh: %v", err)
	}
	if _, err := store.ExecForTest(
		`UPDATE users SET token_migrated_at = datetime('now', '-1 day') WHERE id = ?`,
		"01FRESHUSER00000000000000",
	); err != nil {
		t.Fatalf("fresh timestamp: %v", err)
	}

	// Insert a user never migrated (token_migrated_at NULL) — not swept.
	if err := store.CreateUser("01NEVERMIG000000000000000", "never-mig-token", ""); err != nil {
		t.Fatalf("create never: %v", err)
	}

	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	count, err := store.SweepMigratedMasterTokens(cutoff)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 row swept, got %d", count)
	}

	// Stale user's token must be NULL.
	var staleToken interface{}
	store.db.QueryRow("SELECT token FROM users WHERE id = ?", "01STALEUSER00000000000000").Scan(&staleToken)
	if staleToken != nil {
		t.Errorf("stale user token not NULLed: %v", staleToken)
	}

	// Fresh user's token must still be present.
	var freshToken string
	store.db.QueryRow("SELECT token FROM users WHERE id = ?", "01FRESHUSER00000000000000").Scan(&freshToken)
	if freshToken != "fresh-token" {
		t.Errorf("fresh user token disturbed: %q", freshToken)
	}

	// Idempotent second call returns 0.
	count2, err := store.SweepMigratedMasterTokens(cutoff)
	if err != nil {
		t.Fatalf("sweep 2: %v", err)
	}
	if count2 != 0 {
		t.Errorf("idempotent sweep expected 0, got %d", count2)
	}
}
