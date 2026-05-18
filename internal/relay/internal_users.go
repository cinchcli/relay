package relay

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// InternalCursorPayload is the decoded form of the opaque cursor used by
// GET /internal/users. Pagination is keyset on (created_at, user_id).
type InternalCursorPayload struct {
	CreatedAt time.Time `json:"created_at"`
	UserID    string    `json:"id"`
}

// EncodeInternalCursor serialises a cursor payload as base64-RawURL JSON.
// The result is opaque to callers; only the relay decodes it.
func EncodeInternalCursor(c InternalCursorPayload) string {
	b, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeInternalCursor parses a cursor produced by EncodeInternalCursor.
// Returns an error if the string is not base64-RawURL, not valid JSON, or
// is missing the required id field.
func DecodeInternalCursor(s string) (InternalCursorPayload, error) {
	var out InternalCursorPayload
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("cursor base64: %w", err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return out, fmt.Errorf("cursor json: %w", err)
	}
	if out.UserID == "" {
		return out, fmt.Errorf("cursor missing id")
	}
	return out, nil
}
