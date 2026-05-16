package relay

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateInviteCode_PrefixAndLength(t *testing.T) {
	c, err := GenerateInviteCode()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c, "cinch_inv_") {
		t.Fatalf("missing prefix: %q", c)
	}
	body := strings.TrimPrefix(c, "cinch_inv_")
	if got := len(body); got != 39 {
		t.Fatalf("body length = %d, want 39", got)
	}
	for _, r := range body {
		if !(('a' <= r && r <= 'z') || ('2' <= r && r <= '7')) {
			t.Fatalf("non-base32 char in body: %q", r)
		}
	}
}

func TestGenerateInviteCode_Unique(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 100; i++ {
		c, err := GenerateInviteCode()
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[c]; dup {
			t.Fatal("duplicate invite code generated")
		}
		seen[c] = struct{}{}
	}
}

func TestHashInviteCode_DeterministicHex64(t *testing.T) {
	h := HashInviteCode("cinch_inv_abcdef")
	if len(h) != 64 {
		t.Fatalf("hash length = %d, want 64", len(h))
	}
	if _, err := hex.DecodeString(h); err != nil {
		t.Fatalf("hash is not hex: %v", err)
	}
	if HashInviteCode("cinch_inv_abcdef") != h {
		t.Fatal("hash is not deterministic")
	}
	if HashInviteCode("cinch_inv_xyz") == h {
		t.Fatal("different inputs produced same hash")
	}
}
