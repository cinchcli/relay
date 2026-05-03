// Cross-language wire-format gate.
//
// Loads relay/testdata/wire-vectors.json and round-trips every named vector
// through the protoc-gen-go types. The Rust CLI runs an equivalent test
// against an identical fixture in the cinch repo. If both pass, the wire
// format is shape-equivalent across languages.
//
// Round-trip: input JSON -> typed unmarshal -> re-marshal -> compare both
// sides parsed as map[string]any so JSON object key ordering is irrelevant.

package cinchv1

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const fixtureRel = "../../../../testdata/wire-vectors.json"

func loadVectors(t *testing.T) map[string]any {
	t.Helper()
	abs, err := filepath.Abs(fixtureRel)
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

// vectorsFor pulls the named message group out of the root document and
// returns the inner name->vector map. Skips the top-level "_doc" key and
// fails loudly if the requested message is missing.
func vectorsFor(t *testing.T, root map[string]any, message string) map[string]any {
	t.Helper()
	raw, ok := root[message]
	if !ok {
		t.Fatalf("missing vector group: %s", message)
	}
	group, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("vector group %s is not an object", message)
	}
	return group
}

// roundTrip marshals the input vector with encoding/json, decodes it into
// `target` (must be a non-nil pointer to a generated message), re-marshals
// the typed value, then compares input and output as parsed JSON values.
// reflect.DeepEqual on map[string]any ignores key ordering.
func roundTrip(t *testing.T, label string, input map[string]any, target any) {
	t.Helper()
	inputBytes, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("%s: marshal input: %v", label, err)
	}
	if err := json.Unmarshal(inputBytes, target); err != nil {
		t.Fatalf("%s: decode failed: %v (input: %s)", label, err, inputBytes)
	}
	outputBytes, err := json.Marshal(target)
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

// runGroup iterates a group's named vectors and invokes `factory` for each
// to produce a fresh empty target pointer to round-trip through.
func runGroup(t *testing.T, root map[string]any, message string, factory func() any) {
	t.Helper()
	for name, raw := range vectorsFor(t, root, message) {
		vec, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("%s::%s is not an object", message, name)
		}
		roundTrip(t, fmt.Sprintf("%s::%s", message, name), vec, factory())
	}
}

func TestClipVectorsRoundTrip(t *testing.T) {
	root := loadVectors(t)
	runGroup(t, root, "Clip", func() any { return &Clip{} })
}

func TestPushClipRequestVectorsRoundTrip(t *testing.T) {
	root := loadVectors(t)
	runGroup(t, root, "PushClipRequest", func() any { return &PushClipRequest{} })
}

func TestPushClipResponseVectorsRoundTrip(t *testing.T) {
	root := loadVectors(t)
	runGroup(t, root, "PushClipResponse", func() any { return &PushClipResponse{} })
}

func TestPullResponseVectorsRoundTrip(t *testing.T) {
	root := loadVectors(t)
	runGroup(t, root, "PullResponse", func() any { return &PullResponse{} })
}

func TestDeviceCodeStartResponseVectorsRoundTrip(t *testing.T) {
	root := loadVectors(t)
	runGroup(t, root, "DeviceCodeStartResponse", func() any { return &DeviceCodeStartResponse{} })
}

func TestDeviceCodePollResponseVectorsRoundTrip(t *testing.T) {
	root := loadVectors(t)
	runGroup(t, root, "DeviceCodePollResponse", func() any { return &DeviceCodePollResponse{} })
}

func TestLoginResponseVectorsRoundTrip(t *testing.T) {
	root := loadVectors(t)
	runGroup(t, root, "LoginResponse", func() any { return &LoginResponse{} })
}

// PairResponse / RotatePairTokenResponse round-trip tests removed —
// the underlying proto messages were dropped in the OAuth-only
// migration. Task 7 cleans up testdata/wire-vectors.json.

func TestErrorResponseVectorsRoundTrip(t *testing.T) {
	root := loadVectors(t)
	runGroup(t, root, "ErrorResponse", func() any { return &ErrorResponse{} })
}

func TestDeviceVectorsRoundTrip(t *testing.T) {
	root := loadVectors(t)
	runGroup(t, root, "Device", func() any { return &Device{} })
}
