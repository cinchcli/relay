package relay

import (
	"encoding/json"
	"net/http"
	"time"
)

type createInviteReq struct {
	Label         string `json:"label,omitempty"`
	MaxUses       int    `json:"max_uses,omitempty"`
	ExpiresInDays int    `json:"expires_in_days,omitempty"`
}

type createInviteResp struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AdminCreateInvite handles POST /admin/invites.
// It generates a fresh invite code, stores its hash, and returns the
// plaintext code exactly once. Defaults: max_uses=1, expires_in_days=7.
func (h *Handler) AdminCreateInvite(w http.ResponseWriter, r *http.Request) {
	var req createInviteReq
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	if req.MaxUses <= 0 {
		req.MaxUses = 1
	}
	if req.ExpiresInDays <= 0 {
		req.ExpiresInDays = 7
	}

	code, err := GenerateInviteCode()
	if err != nil {
		writeInternalError(w, "generate", "invite code generation", err)
		return
	}
	exp := time.Now().Add(time.Duration(req.ExpiresInDays) * 24 * time.Hour)
	creator := r.Header.Get("X-User-ID")
	if err := h.store.CreateInvite(HashInviteCode(code), &creator, req.Label, req.MaxUses, exp); err != nil {
		writeInternalError(w, "store", "insert invite", err)
		return
	}
	writeJSON(w, http.StatusOK, createInviteResp{Code: code, ExpiresAt: exp})
}

type listInviteRow struct {
	CodeHash  string     `json:"code_hash"`
	Label     string     `json:"label"`
	MaxUses   int        `json:"max_uses"`
	UsedCount int        `json:"used_count"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// AdminListInvites handles GET /admin/invites.
// Returns all invite rows with the code hash (never the plaintext code).
func (h *Handler) AdminListInvites(w http.ResponseWriter, r *http.Request) {
	list, err := h.store.ListInvites()
	if err != nil {
		writeInternalError(w, "list", "list invites", err)
		return
	}
	out := make([]listInviteRow, 0, len(list))
	for _, inv := range list {
		out = append(out, listInviteRow{
			CodeHash:  inv.CodeHash,
			Label:     inv.Label,
			MaxUses:   inv.MaxUses,
			UsedCount: inv.UsedCount,
			CreatedAt: inv.CreatedAt,
			ExpiresAt: inv.ExpiresAt,
			RevokedAt: inv.RevokedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"invites": out})
}

// AdminRevokeInvite handles DELETE /admin/invites/{hash}.
// Sets revoked_at on the invite row, preventing further redemptions.
func (h *Handler) AdminRevokeInvite(w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("hash")
	if hash == "" {
		writeError(w, http.StatusBadRequest, "missing_hash", "Hash path parameter is required.", "")
		return
	}
	if err := h.store.RevokeInvite(hash); err != nil {
		writeInternalError(w, "revoke", "revoke invite", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

type adminUserRow struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"display_name"`
	IsAdmin     bool      `json:"is_admin"`
	CreatedAt   time.Time `json:"created_at"`
}

// AdminListUsers handles GET /admin/users.
// Returns all user rows (no tokens or secrets exposed).
func (h *Handler) AdminListUsers(w http.ResponseWriter, r *http.Request) {
	list, err := h.store.ListUsers()
	if err != nil {
		writeInternalError(w, "list", "list users", err)
		return
	}
	out := make([]adminUserRow, 0, len(list))
	for _, u := range list {
		out = append(out, adminUserRow(u))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"users": out})
}

// AdminDeleteUser handles DELETE /admin/users/{id}.
// Refuses to delete the calling admin's own account (self_delete error).
func (h *Handler) AdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("id")
	if uid == "" {
		writeError(w, http.StatusBadRequest, "missing_id", "User ID path parameter is required.", "")
		return
	}
	if uid == r.Header.Get("X-User-ID") {
		writeError(w, http.StatusBadRequest, "self_delete",
			"Refusing to delete your own admin account.", "Promote another user first.")
		return
	}
	if err := h.store.DeleteUser(uid); err != nil {
		writeInternalError(w, "delete", "delete user", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}
