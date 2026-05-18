package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWSMessage_ClientHello_RoundTrip(t *testing.T) {
	src := WSMessage{
		Action: "client_hello",
		ClientHello: &ClientHelloPayload{
			Version: "0.1.8",
			Type:    "cli",
			OS:      "linux",
		},
	}
	b, err := json.Marshal(src)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got WSMessage
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Action != "client_hello" {
		t.Errorf("action = %q", got.Action)
	}
	if got.ClientHello == nil {
		t.Fatal("client_hello nil after round-trip")
	}
	if got.ClientHello.Version != "0.1.8" || got.ClientHello.Type != "cli" || got.ClientHello.OS != "linux" {
		t.Errorf("payload = %+v", got.ClientHello)
	}
}

func TestWSMessage_ClientHello_OmittedWhenNil(t *testing.T) {
	src := WSMessage{Action: "ping"}
	b, err := json.Marshal(src)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "client_hello") {
		t.Errorf("client_hello should be omitted when nil, got %s", string(b))
	}
}
