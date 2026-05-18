package relay

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cinchcli/relay/internal/protocol"
	"github.com/gorilla/websocket"
)

// TestHub_ClientHello_PersistsVersion verifies that a client_hello WS
// message coming from an authenticated device is dispatched into the
// store via UpdateDeviceVersion. The dispatch is asynchronous (the read
// loop must not block on the DB), so the test polls GetDeviceVersion
// until the row lands or the deadline fires.
//
// Skips when TEST_DATABASE_URL is unset (keyExchangeTestServer →
// newTestStore handles the skip).
func TestHub_ClientHello_PersistsVersion(t *testing.T) {
	ts, store, _ := keyExchangeTestServer(t)
	token, _, deviceID := keyExchangeLogin(t, ts, "host-hello")

	wsURL := strings.Replace(ts.URL, "http://", "ws://", 1) + "/ws?token=" + token
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer conn.Close()

	hello := protocol.WSMessage{
		Action: protocol.ActionClientHello,
		ClientHello: &protocol.ClientHelloPayload{
			Version: "0.1.8",
			Type:    "cli",
		},
	}
	if err := conn.WriteJSON(hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}

	// Allow async persistence — poll until the version row lands.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		v, ty, _, getErr := store.GetDeviceVersion(context.Background(), deviceID)
		if getErr == nil && v == "0.1.8" && ty == "cli" {
			return // success
		}
		time.Sleep(20 * time.Millisecond)
	}

	v, ty, _, _ := store.GetDeviceVersion(context.Background(), deviceID)
	t.Fatalf("device %s version not persisted in time (got version=%q type=%q)", deviceID, v, ty)
}

// TestHub_ClientHello_NilPayload_NoCrash verifies that a malformed
// client_hello message (Action set but payload nil) is silently
// ignored rather than panicking or persisting garbage. The WS read
// loop must keep running afterward; we assert that by sending a
// follow-up well-formed hello and checking it lands.
func TestHub_ClientHello_NilPayload_NoCrash(t *testing.T) {
	ts, store, _ := keyExchangeTestServer(t)
	token, _, deviceID := keyExchangeLogin(t, ts, "host-hello-nil")

	wsURL := strings.Replace(ts.URL, "http://", "ws://", 1) + "/ws?token=" + token
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer conn.Close()

	// Malformed: action present, payload missing.
	if err := conn.WriteJSON(protocol.WSMessage{Action: protocol.ActionClientHello}); err != nil {
		t.Fatalf("write malformed hello: %v", err)
	}

	// Well-formed follow-up — proves the loop is still reading.
	if err := conn.WriteJSON(protocol.WSMessage{
		Action: protocol.ActionClientHello,
		ClientHello: &protocol.ClientHelloPayload{
			Version: "0.1.9",
			Type:    "desktop",
		},
	}); err != nil {
		t.Fatalf("write good hello: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		v, ty, _, getErr := store.GetDeviceVersion(context.Background(), deviceID)
		if getErr == nil && v == "0.1.9" && ty == "desktop" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("follow-up hello not persisted after malformed message")
}
