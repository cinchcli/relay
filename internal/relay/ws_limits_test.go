package relay_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/cinchcli/relay/internal/protocol"
	relay "github.com/cinchcli/relay/internal/relay"
)

// newWSTestServer builds a relay whose WebSocket limits can be tightened so the
// read-limit / read-deadline guards can be exercised quickly.
func newWSTestServer(t *testing.T, configure func(*relay.Handler)) *httptest.Server {
	t.Helper()
	store := relay.NewTestStore(t)
	installBootstrapInvite(t, store)
	hub := relay.NewHub()
	go hub.Run()
	h := relay.NewHandler(store, hub)
	if configure != nil {
		configure(h)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func dialWSWithToken(t *testing.T, baseURL, token string) *websocket.Conn {
	t.Helper()
	wsURL := strings.Replace(baseURL, "http://", "ws://", 1) + "/ws?token=" + token
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	return conn
}

// An inbound frame larger than the read limit must make the server tear the
// connection down (gorilla SetReadLimit), not buffer it. Without the limit the
// server would accept the (valid-JSON) frame and keep the connection open.
func TestWebSocket_ClosesConnectionOnOversizeInboundFrame(t *testing.T) {
	ts := newWSTestServer(t, func(h *relay.Handler) { h.WSReadLimitBytes = 256 })
	token, _, _ := login(t, ts.URL)
	conn := dialWSWithToken(t, ts.URL, token)
	defer conn.Close()

	// Valid JSON, but far over the 256-byte read limit.
	oversize := protocol.WSMessage{Action: protocol.ActionPong, Hostname: strings.Repeat("x", 4096)}
	if err := conn.WriteJSON(oversize); err != nil {
		t.Fatalf("write: %v", err)
	}

	start := time.Now()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _, err := conn.ReadMessage()
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected the server to close the connection after an oversize frame")
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("server did not promptly close on oversize frame (%v) — read limit not enforced", elapsed)
	}
}

// An idle connection that never sends must be reaped once the server read
// deadline elapses, so silent sockets cannot pin goroutines/FDs forever.
func TestWebSocket_ClosesIdleConnectionPastReadDeadline(t *testing.T) {
	ts := newWSTestServer(t, func(h *relay.Handler) { h.WSReadDeadline = 200 * time.Millisecond })
	token, _, _ := login(t, ts.URL)
	conn := dialWSWithToken(t, ts.URL, token)
	defer conn.Close()

	// Stay completely silent. The server's read deadline must fire.
	start := time.Now()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _, err := conn.ReadMessage()
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected the server to close the idle connection")
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("server did not close idle connection promptly (%v) — read deadline not enforced", elapsed)
	}
}
