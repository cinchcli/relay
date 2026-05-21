// Cross-language wire-format gate for the hand-written WSMessage envelope.
//
// The generated cinch.v1 messages are round-tripped in wire_vectors_test.go
// against the locally-generated types at internal/cinchv1 (synced from the
// github.com/cinchcli/cinch monorepo). WSMessage stays hand-written in
// internal/protocol/ because the WebSocket envelope's "action + 8 optional
// siblings" shape doesn't map cleanly onto a proto oneof. Co-locating both
// round-trips here keeps the embedded fixture in one place and avoids the
// import cycle the original layout had to dodge (protocol → cinchv1, so a
// test in cinchv1 couldn't import protocol).
//
// The Rust mirror lives in the cinch monorepo at
// `crates/client-core/tests/wire_vectors.rs` and round-trips the same
// vectors through `client_core::protocol::WSMessage`.

package wire_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/cinchcli/relay/internal/protocol"
)

// TestWSMessageVectorsRoundTrip round-trips every "WSMessage" vector
// through encoding/json and asserts byte-equal output (modulo key order).
func TestWSMessageVectorsRoundTrip(t *testing.T) {
	root := loadVectors(t)
	raw, ok := root["WSMessage"]
	if !ok {
		t.Fatal("missing vector group: WSMessage")
	}
	group, ok := raw.(map[string]any)
	if !ok {
		t.Fatal("vector group WSMessage is not an object")
	}
	for name, vecRaw := range group {
		vec, ok := vecRaw.(map[string]any)
		if !ok {
			t.Fatalf("WSMessage::%s is not an object", name)
		}
		label := fmt.Sprintf("WSMessage::%s", name)

		inputBytes, err := json.Marshal(vec)
		if err != nil {
			t.Fatalf("%s: marshal input: %v", label, err)
		}
		var msg protocol.WSMessage
		if err := json.Unmarshal(inputBytes, &msg); err != nil {
			t.Fatalf("%s: decode failed: %v (input: %s)", label, err, inputBytes)
		}
		outputBytes, err := json.Marshal(&msg)
		if err != nil {
			t.Fatalf("%s: encode failed: %v", label, err)
		}

		var inputParsed, outputParsed any
		if err := json.Unmarshal(inputBytes, &inputParsed); err != nil {
			t.Fatalf("%s: re-parse input: %v", label, err)
		}
		if err := json.Unmarshal(outputBytes, &outputParsed); err != nil {
			t.Fatalf("%s: parse output: %v", label, err)
		}
		if !reflect.DeepEqual(inputParsed, outputParsed) {
			t.Fatalf("%s: round-trip mismatch\n  input:    %s\n  output:   %s", label, inputBytes, outputBytes)
		}
	}
}
