package relay

import (
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	cinchv1 "github.com/cinchcli/relay/internal/gen/cinch/v1"
	"github.com/cinchcli/relay/internal/protocol"
	"github.com/gorilla/websocket"
)

func TestEventSub_ReceivesServerEventDirectly(t *testing.T) {
	h := NewHub()

	ch := h.RegisterEventSub("user1", "device1")

	want := &cinchv1.ServerEvent{
		Event: &cinchv1.ServerEvent_NewClip{
			NewClip: &cinchv1.NewClipEvent{
				Clip: &cinchv1.Clip{ClipId: "c1", Content: "hello"},
			},
		},
	}
	h.sendToEventSub("user1", "device1", want)

	select {
	case got := <-ch:
		if got != want {
			t.Fatalf("got %v, want %v", got, want)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout: no event received")
	}
}

func TestEventSub_SendToUser_FansOut(t *testing.T) {
	h := NewHub()

	ch1 := h.RegisterEventSub("user1", "device1")
	ch2 := h.RegisterEventSub("user1", "device2")

	event := &cinchv1.ServerEvent{
		Event: &cinchv1.ServerEvent_Revoked{
			Revoked: &cinchv1.RevokedEvent{Reason: "test"},
		},
	}
	h.SendToUser("user1", event)

	for _, ch := range []<-chan *cinchv1.ServerEvent{ch1, ch2} {
		select {
		case got := <-ch:
			if got != event {
				t.Fatalf("got %v, want %v", got, event)
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatal("timeout: no event received on one of the channels")
		}
	}
}

func TestEventSub_UnregisterClosesChannel(t *testing.T) {
	h := NewHub()
	ch := h.RegisterEventSub("user1", "device1")
	h.UnregisterEventSub("user1", "device1")

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected channel to be closed")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout: channel not closed after unregister")
	}
}

// TestBroadcastWSToUser_ReachesAllUserDevices verifies the generic
// WS fan-out method delivers a pre-built WSMessage to every device
// connected for the given userID. Mirrors TestKeyBundleRetry_BroadcastsToUser's
// re-parent pattern to put two devices on the same user account.
func TestBroadcastWSToUser_ReachesAllUserDevices(t *testing.T) {
	ts, store, hub := keyExchangeTestServer(t)

	// First device — establishes the target user.
	tokA, _, devA := keyExchangeLogin(t, ts, "host-a")
	userA, err := store.DeviceOwner(devA)
	if err != nil {
		t.Fatalf("device owner A: %v", err)
	}

	// Second device — keyExchangeLogin currently creates a fresh user per
	// call, so re-parent onto userA so both devices share the account.
	tokB, _, devB := keyExchangeLogin(t, ts, "host-b")
	if _, err := store.db.Exec("UPDATE devices SET user_id = $1 WHERE id = $2", userA, devB); err != nil {
		t.Fatalf("re-parent: %v", err)
	}

	dial := func(token string) *websocket.Conn {
		t.Helper()
		wsURL := strings.Replace(ts.URL, "http://", "ws://", 1) + "/ws?token=" + token
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			t.Fatalf("ws dial: %v", err)
		}
		return conn
	}

	connA := dial(tokA)
	defer connA.Close()
	connB := dial(tokB)
	defer connB.Close()

	// Give the hub a moment to register both connections before broadcasting.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		hub.mu.RLock()
		n := len(hub.conns[userA])
		hub.mu.RUnlock()
		if n == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	hub.BroadcastWSToUser(userA, &protocol.WSMessage{
		Action:       protocol.ActionDeviceCodePending,
		UserCode:     "ABCD-1234",
		Hostname:     "remote-box",
		RequestedAt:  1234567890,
		SourceRegion: "us-west-1",
	})

	for i, conn := range []*websocket.Conn{connA, connB} {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var msg protocol.WSMessage
		if err := conn.ReadJSON(&msg); err != nil {
			t.Fatalf("conn %d: read ws: %v", i, err)
		}
		if msg.Action != protocol.ActionDeviceCodePending {
			t.Fatalf("conn %d: expected action %q, got %q", i, protocol.ActionDeviceCodePending, msg.Action)
		}
		if msg.UserCode != "ABCD-1234" {
			t.Fatalf("conn %d: expected user_code ABCD-1234, got %q", i, msg.UserCode)
		}
		if msg.Hostname != "remote-box" {
			t.Fatalf("conn %d: expected hostname remote-box, got %q", i, msg.Hostname)
		}
		if msg.RequestedAt != 1234567890 {
			t.Fatalf("conn %d: expected requested_at 1234567890, got %d", i, msg.RequestedAt)
		}
		if msg.SourceRegion != "us-west-1" {
			t.Fatalf("conn %d: expected source_region us-west-1, got %q", i, msg.SourceRegion)
		}
	}
}

// TestDeviceCodeStart_BroadcastsPendingToHintedUser verifies the
// happy path: when DeviceCodeStart receives a user_hint matching a
// verified-email OAuth user, every WS-connected device of that user
// receives a device_code_pending frame populated from the request.
func TestDeviceCodeStart_BroadcastsPendingToHintedUser(t *testing.T) {
	ts, store, hub := keyExchangeTestServer(t)

	// Seed verified-email user "alice" and capture her user_id so we can
	// re-parent the WS-connected device onto her account.
	aliceID, _, _, err := store.UpsertOAuthUser("google", "sub-1", "alice@example.com", true, "alice-mbp", "machine-1")
	if err != nil {
		t.Fatalf("seed alice: %v", err)
	}

	tokA, _, devA := keyExchangeLogin(t, ts, "alice-cli")
	// Re-parent the freshly-logged-in anonymous device onto alice so the
	// broadcast (which targets alice's user_id) reaches a live connection.
	if _, err := store.db.Exec("UPDATE devices SET user_id = $1 WHERE id = $2", aliceID, devA); err != nil {
		t.Fatalf("re-parent: %v", err)
	}

	wsURL := strings.Replace(ts.URL, "http://", "ws://", 1) + "/ws?token=" + tokA
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer conn.Close()

	// Wait for the hub to register the connection under aliceID.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		hub.mu.RLock()
		n := len(hub.conns[aliceID])
		hub.mu.RUnlock()
		if n == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	srv := &connectAuthServer{h: NewHandler(store, hub)}
	hostname := "remote-dev-box"
	userHint := "alice@example.com"
	req := connect.NewRequest(&cinchv1.DeviceCodeStartRequest{
		Hostname: &hostname,
		UserHint: &userHint,
	})
	req.Header().Set("X-Forwarded-For", "203.0.113.10, 10.0.0.1")

	resp, err := srv.DeviceCodeStart(context.Background(), req)
	if err != nil {
		t.Fatalf("DeviceCodeStart: %v", err)
	}
	wantUserCode := resp.Msg.UserCode
	if wantUserCode == "" {
		t.Fatal("empty UserCode in response")
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg protocol.WSMessage
	if err := conn.ReadJSON(&msg); err != nil {
		t.Fatalf("read ws: %v", err)
	}
	if msg.Action != protocol.ActionDeviceCodePending {
		t.Fatalf("expected action %q, got %q", protocol.ActionDeviceCodePending, msg.Action)
	}
	if msg.UserCode != wantUserCode {
		t.Fatalf("expected user_code %q, got %q", wantUserCode, msg.UserCode)
	}
	if msg.Hostname != hostname {
		t.Fatalf("expected hostname %q, got %q", hostname, msg.Hostname)
	}
	if msg.RequestedAt == 0 {
		t.Fatal("expected requested_at to be set")
	}
}

// TestDeviceCodeStart_UnknownHintSilent verifies that DeviceCodeStart
// with a user_hint that does not match any verified-email user does
// NOT broadcast a device_code_pending frame to any connected device.
func TestDeviceCodeStart_UnknownHintSilent(t *testing.T) {
	ts, store, hub := keyExchangeTestServer(t)

	// Connect a device for some user — it must NOT receive a frame.
	tokA, _, devA := keyExchangeLogin(t, ts, "host-a")
	userA, err := store.DeviceOwner(devA)
	if err != nil {
		t.Fatalf("device owner: %v", err)
	}

	wsURL := strings.Replace(ts.URL, "http://", "ws://", 1) + "/ws?token=" + tokA
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		hub.mu.RLock()
		n := len(hub.conns[userA])
		hub.mu.RUnlock()
		if n == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	srv := &connectAuthServer{h: NewHandler(store, hub)}
	hostname := "remote-dev-box"
	userHint := "nobody@nowhere.com"
	req := connect.NewRequest(&cinchv1.DeviceCodeStartRequest{
		Hostname: &hostname,
		UserHint: &userHint,
	})

	if _, err := srv.DeviceCodeStart(context.Background(), req); err != nil {
		t.Fatalf("DeviceCodeStart: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	var msg protocol.WSMessage
	if err := conn.ReadJSON(&msg); err == nil {
		t.Fatalf("expected timeout, but received frame: %+v", msg)
	}
}

// TestDeviceCodeStart_PerUserRateLimit_DropsExcessBroadcast verifies the
// per-pending-user rate limiter: after 5 device_code_pending broadcasts
// in the rolling minute window, additional DeviceCodeStart calls still
// succeed (HTTP 200) but the WS frame is dropped. The RPC response must
// not change so callers cannot enumerate which emails match real users.
func TestDeviceCodeStart_PerUserRateLimit_DropsExcessBroadcast(t *testing.T) {
	ts, store, hub := keyExchangeTestServer(t)

	aliceID, _, _, err := store.UpsertOAuthUser("google", "sub-1", "alice@example.com", true, "alice-mbp", "machine-1")
	if err != nil {
		t.Fatalf("seed alice: %v", err)
	}

	tokA, _, devA := keyExchangeLogin(t, ts, "alice-cli")
	if _, err := store.db.Exec("UPDATE devices SET user_id = $1 WHERE id = $2", aliceID, devA); err != nil {
		t.Fatalf("re-parent: %v", err)
	}

	wsURL := strings.Replace(ts.URL, "http://", "ws://", 1) + "/ws?token=" + tokA
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer conn.Close()

	// Wait for hub to register the connection under aliceID.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		hub.mu.RLock()
		n := len(hub.conns[aliceID])
		hub.mu.RUnlock()
		if n == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Share the Handler so the rate limiter state persists across calls.
	h := NewHandler(store, hub)
	srv := &connectAuthServer{h: h}

	strPtr := func(s string) *string { return &s }

	for i := 0; i < 5; i++ {
		req := connect.NewRequest(&cinchv1.DeviceCodeStartRequest{
			Hostname: strPtr("dev-box-3"),
			UserHint: strPtr("alice@example.com"),
		})
		if _, err := srv.DeviceCodeStart(context.Background(), req); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var msg protocol.WSMessage
		if err := conn.ReadJSON(&msg); err != nil {
			t.Fatalf("attempt %d frame: %v", i, err)
		}
		if msg.Action != protocol.ActionDeviceCodePending {
			t.Fatalf("attempt %d: expected action %q, got %q", i, protocol.ActionDeviceCodePending, msg.Action)
		}
	}

	// 6th call: must still return success (no error) — only the broadcast is dropped.
	req6 := connect.NewRequest(&cinchv1.DeviceCodeStartRequest{
		Hostname: strPtr("dev-box-3"),
		UserHint: strPtr("alice@example.com"),
	})
	if _, err := srv.DeviceCodeStart(context.Background(), req6); err != nil {
		t.Fatalf("6th call should still succeed: %v", err)
	}

	// No frame arrives on the WS connection.
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	var msg protocol.WSMessage
	if err := conn.ReadJSON(&msg); err == nil {
		t.Errorf("expected no frame on rate-limited 6th call, got %+v", msg)
	}
}

// TestExtractRequesterIP_PrefersXFFFirstHop verifies the helper picks
// the leftmost IP from X-Forwarded-For chains, falls back to X-Real-IP,
// and trims whitespace.
func TestExtractRequesterIP_PrefersXFFFirstHop(t *testing.T) {
	cases := []struct {
		name string
		xff  string
		real string
		want string
	}{
		{"xff single", "203.0.113.10", "", "203.0.113.10"},
		{"xff chain", "203.0.113.10, 10.0.0.1, 172.16.0.1", "", "203.0.113.10"},
		{"xff whitespace", "  203.0.113.10  ", "", "203.0.113.10"},
		{"real ip fallback", "", "198.51.100.7", "198.51.100.7"},
		{"xff wins over real", "203.0.113.10", "198.51.100.7", "203.0.113.10"},
		{"empty", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := make(map[string][]string)
			if tc.xff != "" {
				h["X-Forwarded-For"] = []string{tc.xff}
			}
			if tc.real != "" {
				h["X-Real-Ip"] = []string{tc.real}
			}
			got := extractRequesterIP(h)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
