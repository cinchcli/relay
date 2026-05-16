package relay

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"
)

const InvitePrefix = "cinch_inv_"

// GenerateInviteCode returns a fresh single-use invite code in the form
// "cinch_inv_<base32-of-24-random-bytes>". The unprefixed body is 39 chars.
func GenerateInviteCode() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	body := enc.EncodeToString(b[:])
	// StdEncoding is uppercase; switch to lowercase for friendlier URLs.
	body = strings.ToLower(body)
	return InvitePrefix + body, nil
}

// HashInviteCode returns the lowercase hex SHA-256 of the full code.
// This is what gets stored in invites.code_hash.
func HashInviteCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}
