package relay

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// randomHex returns n cryptographically-random bytes, hex-encoded (2n chars).
//
// A crypto/rand failure means the OS CSPRNG is unavailable — an unrecoverable
// condition — so this panics rather than return a predictable, attacker-
// guessable token. This is the single fail-safe token source for the relay
// (device tokens, store tokens, WebSocket tickets); callers must not roll their
// own rand.Read and silently ignore its error.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b)
}
