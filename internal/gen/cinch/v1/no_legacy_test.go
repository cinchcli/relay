package cinchv1

import (
	"os"
	"strings"
	"testing"
)

// TestNoLegacyAuthSymbols guards against accidental re-introduction of
// the pair-token / master-token paths after the OAuth-only migration.
// Reads the generated Go file and ensures the forbidden identifiers do
// not appear anywhere in it.
func TestNoLegacyAuthSymbols(t *testing.T) {
	data, err := os.ReadFile("auth.pb.go")
	if err != nil {
		t.Fatalf("read auth.pb.go: %v", err)
	}
	source := string(data)
	forbidden := []string{
		"PairRequest",
		"PairResponse",
		"RotatePairTokenRequest",
		"RotatePairTokenResponse",
		"PairToken", // catches the LoginResponse field too
	}
	for _, sym := range forbidden {
		if strings.Contains(source, sym) {
			t.Errorf("forbidden symbol %q still present in auth.pb.go", sym)
		}
	}
}
