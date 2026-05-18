package relay

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
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

type internalUsersListResponseUser struct {
	UserID            string                              `json:"user_id"`
	CreatedAt         time.Time                           `json:"created_at"`
	IsDemo            bool                                `json:"is_demo"`
	DeviceCount       int                                 `json:"device_count"`
	ActiveDeviceCount int                                 `json:"active_device_count"`
	LastActiveAt      *time.Time                          `json:"last_active_at,omitempty"`
	Capabilities      *internalUsersListResponseCapsBlock `json:"capabilities"`
}

type internalUsersListResponseCapsBlock struct {
	DeviceLimit    int        `json:"device_limit"`
	RetentionDays  int        `json:"retention_days"`
	RateLimit      int        `json:"rate_limit"`
	GraceExpiresAt *time.Time `json:"grace_expires_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type internalUsersListResponse struct {
	Users      []internalUsersListResponseUser `json:"users"`
	NextCursor string                          `json:"next_cursor,omitempty"`
}

// ListInternalUsers handles GET /internal/users.
// Returns paginated user rows with device aggregates and capability echoes
// so the biz Cloudflare Worker can render the SaaS admin dashboard.
// Protected by INTERNAL_SERVICE_SECRET bearer (same secret as POST /internal/quota).
// Returns 503 when the secret is unset so self-hosters get the endpoint disabled
// by default.
func (h *Handler) ListInternalUsers(w http.ResponseWriter, r *http.Request) {
	if h.internalServiceSecret == "" {
		writeError(w, http.StatusServiceUnavailable, "not_configured",
			"Internal users endpoint is not configured on this relay", "")
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(token), []byte(h.internalServiceSecret)) != 1 {
		writeError(w, http.StatusForbidden, "forbidden", "Invalid service secret", "")
		return
	}

	f := InternalUsersFilter{Limit: 100}
	q := r.URL.Query()

	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			writeError(w, http.StatusBadRequest, "invalid_limit", "limit must be an integer between 1 and 1000", "")
			return
		}
		f.Limit = n
	}
	if v := q.Get("cursor"); v != "" {
		c, err := DecodeInternalCursor(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_cursor", "Cursor could not be decoded", "")
			return
		}
		f.Cursor = &c
	}
	if v := q.Get("updated_since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_updated_since", "updated_since must be RFC 3339", "")
			return
		}
		f.UpdatedSince = &t
	}
	if v := q.Get("include_demo"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_include_demo", "include_demo must be a boolean (true/false/1/0)", "")
			return
		}
		f.IncludeDemo = b
	}

	page, err := h.store.ListInternalUserAggregates(f)
	if err != nil {
		writeInternalError(w, "query", "list internal users", err)
		return
	}

	resp := internalUsersListResponse{
		Users:      make([]internalUsersListResponseUser, 0, len(page.Rows)),
		NextCursor: page.NextCursor,
	}
	for _, row := range page.Rows {
		u := internalUsersListResponseUser{
			UserID:            row.UserID,
			CreatedAt:         row.CreatedAt,
			IsDemo:            row.IsDemo,
			DeviceCount:       row.DeviceCount,
			ActiveDeviceCount: row.ActiveDeviceCount,
			LastActiveAt:      row.LastActiveAt,
		}
		if row.Capabilities != nil {
			u.Capabilities = &internalUsersListResponseCapsBlock{
				DeviceLimit:    row.Capabilities.DeviceLimit,
				RetentionDays:  row.Capabilities.RetentionDays,
				RateLimit:      row.Capabilities.RateLimit,
				GraceExpiresAt: row.Capabilities.GraceExpiresAt,
				UpdatedAt:      row.Capabilities.UpdatedAt,
			}
		}
		resp.Users = append(resp.Users, u)
	}
	writeJSON(w, http.StatusOK, resp)
}
