package relay_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	cinchv1 "github.com/cinchcli/relay/internal/gen/cinch/v1"
	relay "github.com/cinchcli/relay/internal/relay"
)

func TestIssueDeviceCode_Success(t *testing.T) {
	ts, _ := setupTestServer(t)

	body := `{"hostname":"test-cli"}`
	resp, err := http.Post(ts.URL+"/auth/device-code", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var dcResp cinchv1.DeviceCodeStartResponse
	if err := json.NewDecoder(resp.Body).Decode(&dcResp); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if dcResp.DeviceCode == "" {
		t.Error("device_code is empty")
	}
	if dcResp.UserCode == "" {
		t.Error("user_code is empty")
	}
	// User code format: XXXX-XXXX
	if len(dcResp.UserCode) != 9 || dcResp.UserCode[4] != '-' {
		t.Errorf("user_code format invalid: %q", dcResp.UserCode)
	}
	if dcResp.VerificationUri == "" {
		t.Error("verification_uri is empty")
	}
	if !strings.Contains(dcResp.VerificationUri, "/auth/browser?device_code=") {
		t.Errorf("verification_uri missing expected path: %s", dcResp.VerificationUri)
	}
	if dcResp.ExpiresIn != 300 {
		t.Errorf("expected expires_in=300, got %d", dcResp.ExpiresIn)
	}
	if dcResp.Interval != 3 {
		t.Errorf("expected interval=3, got %d", dcResp.Interval)
	}
}

func TestPollDeviceCode_Pending(t *testing.T) {
	ts, _ := setupTestServer(t)

	// Issue a device code
	body := `{"hostname":"test-cli"}`
	resp, err := http.Post(ts.URL+"/auth/device-code", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("issue request failed: %v", err)
	}
	defer resp.Body.Close()

	var dcResp cinchv1.DeviceCodeStartResponse
	json.NewDecoder(resp.Body).Decode(&dcResp)

	// Poll immediately — should be pending
	pollResp, err := http.Get(ts.URL + "/auth/device-code/poll?code=" + dcResp.DeviceCode)
	if err != nil {
		t.Fatalf("poll request failed: %v", err)
	}
	defer pollResp.Body.Close()

	if pollResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", pollResp.StatusCode)
	}

	var pollResult cinchv1.DeviceCodePollResponse
	json.NewDecoder(pollResp.Body).Decode(&pollResult)

	if pollResult.Status != "pending" {
		t.Errorf("expected status=pending, got %q", pollResult.Status)
	}
}

func TestPollDeviceCode_Complete(t *testing.T) {
	ts, _ := setupTestServer(t)

	// Issue a device code
	body := `{"hostname":"test-cli"}`
	resp, err := http.Post(ts.URL+"/auth/device-code", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("issue request failed: %v", err)
	}
	defer resp.Body.Close()

	var dcResp cinchv1.DeviceCodeStartResponse
	json.NewDecoder(resp.Body).Decode(&dcResp)

	// Login to get credentials
	token, _, userID := login(t, ts.URL)

	// Complete the device code via the authenticated endpoint
	completeBody, _ := json.Marshal(map[string]string{
		"user_code": dcResp.UserCode,
		"user_id":   userID,
		"device_id": "test-device-123",
		"token":     token,
	})
	req, _ := http.NewRequest("POST", ts.URL+"/auth/device-code/complete", bytes.NewReader(completeBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	completeResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("complete request failed: %v", err)
	}
	defer completeResp.Body.Close()
	if completeResp.StatusCode != http.StatusOK {
		t.Fatalf("complete returned %d", completeResp.StatusCode)
	}

	// Poll — should be complete
	pollResp, err := http.Get(ts.URL + "/auth/device-code/poll?code=" + dcResp.DeviceCode)
	if err != nil {
		t.Fatalf("poll request failed: %v", err)
	}
	defer pollResp.Body.Close()

	var pollResult cinchv1.DeviceCodePollResponse
	json.NewDecoder(pollResp.Body).Decode(&pollResult)

	if pollResult.Status != "complete" {
		t.Errorf("expected status=complete, got %q", pollResult.Status)
	}
	if pollResult.Token == nil || *pollResult.Token == "" {
		t.Error("expected token in complete response")
	}
	if pollResult.UserId == nil || *pollResult.UserId == "" {
		t.Error("expected user_id in complete response")
	}
	if pollResult.DeviceId == nil || *pollResult.DeviceId == "" {
		t.Error("expected device_id in complete response")
	}
}

func TestPollDeviceCode_Expired(t *testing.T) {
	ts, _ := setupTestServer(t)

	// Create a store directly to access ExecForTest
	store, err := relay.NewStore(":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	hub := relay.NewHub()
	go hub.Run()
	handler := relay.NewHandler(store, hub)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Use a separate test server with this store
	_ = ts // keep the original for reference

	// Issue a device code, then manually expire it
	dcResp, err := store.CreateDeviceCode("test-cli", "")
	if err != nil {
		t.Fatalf("create device code failed: %v", err)
	}

	// Manually set expires_at to the past
	_, err = store.ExecForTest(
		"UPDATE device_codes SET expires_at = datetime('now', '-10 minutes') WHERE device_code = ?",
		dcResp.DeviceCode,
	)
	if err != nil {
		t.Fatalf("expire update failed: %v", err)
	}

	// Poll via the handler's store
	pollResult, err := store.PollDeviceCode(dcResp.DeviceCode)
	if err != nil {
		t.Fatalf("poll failed: %v", err)
	}

	if pollResult.Status != "expired" {
		t.Errorf("expected status=expired, got %q", pollResult.Status)
	}
}

func TestAuthBrowser_ServesHTML(t *testing.T) {
	ts, _ := setupTestServer(t)

	resp, err := http.Get(ts.URL + "/auth/browser")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected Content-Type text/html, got %q", ct)
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	if !strings.Contains(body, "Sign in to Cinch") {
		t.Error("HTML body missing 'Sign in to Cinch'")
	}
	if !strings.Contains(body, "#07080a") {
		t.Error("HTML body missing Cinch brand color #07080a")
	}
	if !strings.Contains(body, "#4FB3A9") {
		t.Error("HTML body missing Cinch accent color #4FB3A9")
	}
}
