package relay_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	relay "github.com/cinchcli/relay/internal/relay"
)

// adminLogin creates a user, promotes it to admin, and returns
// (serverURL, adminToken, adminUserID). The store must already have
// a redeemable bootstrap invite from setupTestServerWithStore.
func adminLogin(t *testing.T, baseURL string, store *relay.Store) (token, userID string) {
	t.Helper()
	token, _, userID = login(t, baseURL)
	if err := store.SetUserAdmin(userID, true); err != nil {
		t.Fatalf("promote to admin: %v", err)
	}
	return token, userID
}

// ── Task 2.9: RequireAdmin middleware ─────────────────────────────────────────

// TestRequireAdmin_RejectsNonAdmin verifies that a non-admin user gets 403.
func TestRequireAdmin_RejectsNonAdmin(t *testing.T) {
	ts, _, store := setupTestServerWithStore(t)

	// Create a non-admin user directly in the store (bypasses AuthLogin's
	// first-user-is-admin logic, which would otherwise auto-promote user #1).
	// We pre-create an admin first so CountUsers > 0 at non-admin insert time.
	adminUID := "test-admin-prereq-" + t.Name()
	if err := store.CreateUser(adminUID); err != nil {
		t.Fatalf("create prereq admin: %v", err)
	}
	if err := store.SetUserAdmin(adminUID, true); err != nil {
		t.Fatalf("promote prereq admin: %v", err)
	}

	nonAdminUID := "test-nonadmin-" + t.Name()
	nonAdminTok := "tok-nonadmin-" + t.Name()
	if err := store.CreateUser(nonAdminUID); err != nil {
		t.Fatalf("create non-admin user: %v", err)
	}
	if err := store.RegisterDeviceWithToken(nonAdminUID, "dev-"+t.Name(), "host", nonAdminTok); err != nil {
		t.Fatalf("register device: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin/invites", nil)
	req.Header.Set("Authorization", "Bearer "+nonAdminTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "admin_required" {
		t.Fatalf("error field = %v, want admin_required", body["error"])
	}
}

// TestRequireAdmin_AllowsAdmin verifies that an admin user can reach the route.
func TestRequireAdmin_AllowsAdmin(t *testing.T) {
	ts, _, store := setupTestServerWithStore(t)

	tok, _ := adminLogin(t, ts.URL, store)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin/invites", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// TestRequireAdmin_RejectsNoToken verifies that unauthenticated requests get 401.
func TestRequireAdmin_RejectsNoToken(t *testing.T) {
	ts, _, _ := setupTestServerWithStore(t)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin/invites", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// ── Task 2.10: /admin/* endpoint tests ───────────────────────────────────────

// TestAdminCreateInvite_HappyPath verifies that POST /admin/invites returns
// a plaintext code with the cinch_inv_ prefix and an expires_at timestamp.
func TestAdminCreateInvite_HappyPath(t *testing.T) {
	ts, _, store := setupTestServerWithStore(t)
	tok, _ := adminLogin(t, ts.URL, store)

	body := strings.NewReader(`{"label":"test-invite","max_uses":3,"expires_in_days":14}`)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/invites", body)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	code, ok := result["code"].(string)
	if !ok || code == "" {
		t.Fatalf("code field missing or empty: %v", result)
	}
	if !strings.HasPrefix(code, "cinch_inv_") {
		t.Fatalf("code %q does not have cinch_inv_ prefix", code)
	}
	if _, ok := result["expires_at"]; !ok {
		t.Fatal("expires_at field missing")
	}
}

// TestAdminListInvites_HappyPath verifies GET /admin/invites returns the
// created invite with code_hash (not plaintext code).
func TestAdminListInvites_HappyPath(t *testing.T) {
	ts, _, store := setupTestServerWithStore(t)
	tok, adminUID := adminLogin(t, ts.URL, store)

	// Create one invite via the API.
	createBody := strings.NewReader(`{"label":"list-test"}`)
	createReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/invites", createBody)
	createReq.Header.Set("Authorization", "Bearer "+tok)
	createReq.Header.Set("Content-Type", "application/json")
	createResp, err := http.DefaultClient.Do(createReq)
	if err != nil {
		t.Fatalf("create invite request failed: %v", err)
	}
	defer createResp.Body.Close()

	var createResult map[string]interface{}
	json.NewDecoder(createResp.Body).Decode(&createResult)
	plaintextCode, _ := createResult["code"].(string)

	// List invites.
	listReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin/invites", nil)
	listReq.Header.Set("Authorization", "Bearer "+tok)
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("list request failed: %v", err)
	}
	defer listResp.Body.Close()

	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", listResp.StatusCode)
	}

	var listResult map[string]interface{}
	json.NewDecoder(listResp.Body).Decode(&listResult)

	invites, ok := listResult["invites"].([]interface{})
	if !ok || len(invites) == 0 {
		t.Fatalf("invites list empty or missing: %v", listResult)
	}

	// Find our created invite.
	found := false
	expectedHash := relay.HashInviteCode(plaintextCode)
	for _, iv := range invites {
		row, _ := iv.(map[string]interface{})
		if row["code_hash"] == expectedHash {
			found = true
			// Verify plaintext is not present.
			if _, hasCode := row["code"]; hasCode {
				t.Fatal("plaintext code should not appear in list response")
			}
			if row["label"] != "list-test" {
				t.Fatalf("label = %v, want list-test", row["label"])
			}
			break
		}
	}
	if !found {
		t.Fatalf("created invite not found in list (expected hash %s); admin=%s invites=%v", expectedHash, adminUID, invites)
	}
}

// TestAdminRevokeInvite_HappyPath verifies DELETE /admin/invites/{hash} revokes
// the invite and prevents redemption.
func TestAdminRevokeInvite_HappyPath(t *testing.T) {
	ts, _, store := setupTestServerWithStore(t)
	tok, _ := adminLogin(t, ts.URL, store)

	// Create an invite via the API.
	createBody := strings.NewReader(`{"label":"to-revoke","max_uses":5}`)
	createReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/invites", createBody)
	createReq.Header.Set("Authorization", "Bearer "+tok)
	createReq.Header.Set("Content-Type", "application/json")
	createResp, err := http.DefaultClient.Do(createReq)
	if err != nil {
		t.Fatalf("create invite request failed: %v", err)
	}
	defer createResp.Body.Close()

	var createResult map[string]interface{}
	json.NewDecoder(createResp.Body).Decode(&createResult)
	code, _ := createResult["code"].(string)
	hash := relay.HashInviteCode(code)

	// Revoke it.
	revokeReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/admin/invites/"+hash, nil)
	revokeReq.Header.Set("Authorization", "Bearer "+tok)
	revokeResp, err := http.DefaultClient.Do(revokeReq)
	if err != nil {
		t.Fatalf("revoke request failed: %v", err)
	}
	defer revokeResp.Body.Close()

	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", revokeResp.StatusCode)
	}
	var revokeResult map[string]interface{}
	json.NewDecoder(revokeResp.Body).Decode(&revokeResult)
	if revokeResult["ok"] != true {
		t.Fatalf("ok field = %v, want true", revokeResult["ok"])
	}

	// Attempt to redeem the revoked invite — must fail.
	if err := store.RedeemInvite(hash); err == nil {
		t.Fatal("redeeming a revoked invite should fail")
	}
}

// TestAdminListUsers_HappyPath verifies GET /admin/users returns the admin's row.
func TestAdminListUsers_HappyPath(t *testing.T) {
	ts, _, store := setupTestServerWithStore(t)
	tok, adminUID := adminLogin(t, ts.URL, store)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	users, ok := result["users"].([]interface{})
	if !ok || len(users) == 0 {
		t.Fatalf("users list empty or missing: %v", result)
	}

	// Find the admin user.
	found := false
	for _, u := range users {
		row, _ := u.(map[string]interface{})
		if row["id"] == adminUID {
			found = true
			if row["is_admin"] != true {
				t.Fatalf("admin user row has is_admin=%v, want true", row["is_admin"])
			}
			break
		}
	}
	if !found {
		t.Fatalf("admin user %s not found in users list", adminUID)
	}
}

// TestAdminDeleteUser_HappyPath verifies DELETE /admin/users/{id} removes
// a second user, confirmed by a subsequent ListUsers call.
func TestAdminDeleteUser_HappyPath(t *testing.T) {
	ts, _, store := setupTestServerWithStore(t)
	tok, adminUID := adminLogin(t, ts.URL, store)

	// Create a second user directly in the store.
	secondUID := "test-second-user-" + time.Now().Format("150405.000")
	if err := store.CreateUser(secondUID); err != nil {
		t.Fatalf("create second user: %v", err)
	}

	// Delete the second user via the API.
	delReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/admin/users/"+secondUID, nil)
	delReq.Header.Set("Authorization", "Bearer "+tok)
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("delete request failed: %v", err)
	}
	defer delResp.Body.Close()

	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", delResp.StatusCode)
	}

	// Confirm via ListUsers that the second user is gone.
	users, err := store.ListUsers()
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	for _, u := range users {
		if u.ID == secondUID {
			t.Fatalf("second user %s still present after delete", secondUID)
		}
	}
	_ = adminUID
}

// TestAdminDeleteUser_SelfProtection verifies that deleting the caller's own
// account returns 400 with error "self_delete".
func TestAdminDeleteUser_SelfProtection(t *testing.T) {
	ts, _, store := setupTestServerWithStore(t)
	tok, adminUID := adminLogin(t, ts.URL, store)

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/admin/users/"+adminUID, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "self_delete" {
		t.Fatalf("error field = %v, want self_delete", body["error"])
	}
}

// TestAdminEndpoints_NonAdminGets403 verifies that a non-admin token hitting
// any /admin/* route returns 403 admin_required.
func TestAdminEndpoints_NonAdminGets403(t *testing.T) {
	ts, _, store := setupTestServerWithStore(t)

	// Pre-create an admin user so CountUsers > 0; then create a non-admin user
	// directly in the store (bypasses AuthLogin's first-user-is-admin logic).
	adminUID := "test-admin-prereq-403-" + t.Name()
	if err := store.CreateUser(adminUID); err != nil {
		t.Fatalf("create prereq admin: %v", err)
	}
	if err := store.SetUserAdmin(adminUID, true); err != nil {
		t.Fatalf("promote prereq admin: %v", err)
	}

	nonAdminUID := "test-nonadmin-403-" + t.Name()
	tok := "tok-nonadmin-403-" + t.Name()
	if err := store.CreateUser(nonAdminUID); err != nil {
		t.Fatalf("create non-admin user: %v", err)
	}
	if err := store.RegisterDeviceWithToken(nonAdminUID, "dev-403-"+t.Name(), "host", tok); err != nil {
		t.Fatalf("register device: %v", err)
	}

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/admin/invites"},
		{http.MethodPost, "/admin/invites"},
		{http.MethodGet, "/admin/users"},
		{http.MethodDelete, "/admin/users/some-id"},
		{http.MethodDelete, "/admin/invites/some-hash"},
	}

	for _, ep := range endpoints {
		req, _ := http.NewRequest(ep.method, ts.URL+ep.path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: request failed: %v", ep.method, ep.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s %s: status = %d, want 403", ep.method, ep.path, resp.StatusCode)
		}
	}
}
