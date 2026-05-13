// Cross-language wire-format gate for the hand-written WSMessage envelope.
//
// The generated cinch.v1 messages have their own round-trip test in
// internal/gen/cinch/v1/wire_vectors_test.go, but WSMessage lives here in
// internal/protocol/ (it is hand-written, not generated from proto). To
// avoid an import cycle with internal/gen/cinch/v1, the WSMessage entries
// in testdata/wire-vectors.json are round-tripped here.
//
// The Rust mirror lives at cinch/crates/client-core/tests/wire_vectors.rs
// and round-trips the same vectors through client_core::protocol::WSMessage.

package protocol

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const wsFixtureRel = "../../testdata/wire-vectors.json"

func loadWSVectors(t *testing.T) map[string]any {
	t.Helper()
	abs, err := filepath.Abs(wsFixtureRel)
	if err != nil {
		t.Fatalf("resolve fixture path: %v", err)
	}
	bytes, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("read %s: %v", abs, err)
	}
	var root map[string]any
	if err := json.Unmarshal(bytes, &root); err != nil {
		t.Fatalf("parse %s: %v", abs, err)
	}
	return root
}

// TestWSMessageVectorsRoundTrip round-trips every "WSMessage" vector
// through encoding/json and asserts byte-equal output (modulo key order).
func TestWSMessageVectorsRoundTrip(t *testing.T) {
	root := loadWSVectors(t)
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
		var msg WSMessage
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
