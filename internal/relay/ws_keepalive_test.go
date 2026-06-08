package relay

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestWebSocketKeepalive_ProtocolPingKeepsIdleBearerRegistered is the
// regression guard for the `cinch auth retry-key` "broadcasts to nobody" bug.
//
// The relay reaps a connection that stays silent past its read deadline. Real
// clients drop the relay's app-level "ping" message (it carries no reply
// frame), so the only thing keeping an idle-but-alive bearer in the hub is the
// relay's protocol-level Ping plus a read-loop pong handler that refreshes the
// deadline when the client's automatic protocol Pong arrives. Without that
// handler, an idle desktop / `cinch pull --watch` is silently evicted after the
// read deadline and a subsequent retry broadcast reaches no one.
//
// This test drives only the read pump (so gorilla auto-replies to protocol
// Pings with protocol Pongs and sends NO app-level frames) and asserts the
// connection survives well past a deliberately short read deadline.
func TestWebSocketKeepalive_ProtocolPingKeepsIdleBearerRegistered(t *testing.T) {
	store := newTestStore(t)
	installTestBootstrapInvite(t, store)

	hub := NewHub()
	hub.HeartbeatInterval = 100 * time.Millisecond
	go hub.Run()

	handler := NewHandler(store, hub)
	// Deliberately short so the test is fast, but with generous slack over the
	// 100ms heartbeat (≈5 pongs per deadline window) so a loaded CI runner can
	// only ever false-FAIL, never false-PASS.
	handler.WSReadDeadline = 500 * time.Millisecond
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	token, userID, _ := keyExchangeLogin(t, ts, "host-idle")
	wsURL := strings.Replace(ts.URL, "http://", "ws://", 1) + "/ws?token=" + token
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer conn.Close()

	// Read pump: gorilla's default ping handler answers the relay's protocol
	// Pings with protocol Pongs during ReadMessage. The client never sends an
	// app-level frame, so the ONLY client->relay traffic is the protocol Pong —
	// isolating the protocol-ping + pong-handler keepalive path.
	go func() {
		for {
			if _, _, rerr := conn.ReadMessage(); rerr != nil {
				return
			}
		}
	}()

	// Sleep well past the 300ms read deadline and several 100ms heartbeats.
	time.Sleep(1 * time.Second)

	if !hub.IsOnline(userID) {
		t.Fatalf("idle-but-alive client was reaped despite the protocol-ping keepalive")
	}
}
