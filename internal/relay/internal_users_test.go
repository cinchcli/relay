package relay_test

import (
	"strings"
	"testing"
	"time"

	relay "github.com/cinchcli/relay/internal/relay"
)

func TestInternalCursor_RoundTrip(t *testing.T) {
	in := relay.InternalCursorPayload{
		CreatedAt: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
		UserID:    "01HXYZ123",
	}
	s := relay.EncodeInternalCursor(in)
	if s == "" {
		t.Fatal("EncodeInternalCursor returned empty string")
	}
	if strings.ContainsAny(s, "+/=") {
		t.Fatalf("cursor should be base64-RawURL (no +/=), got %q", s)
	}
	out, err := relay.DecodeInternalCursor(s)
	if err != nil {
		t.Fatalf("DecodeInternalCursor: %v", err)
	}
	if !out.CreatedAt.Equal(in.CreatedAt) || out.UserID != in.UserID {
		t.Fatalf("round-trip mismatch: in=%+v out=%+v", in, out)
	}
}

func TestInternalCursor_RejectsGarbage(t *testing.T) {
	cases := []string{
		"!!!not-base64!!!",
		"e30",          // valid base64 → "{}"; missing id field
		"eyJpZCI6IiJ9", // valid base64 → '{"id":""}'; empty id
	}
	for _, s := range cases {
		if _, err := relay.DecodeInternalCursor(s); err == nil {
			t.Fatalf("expected error for cursor %q", s)
		}
	}
}
