package relay

import (
	"strings"
	"testing"
	"time"

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
