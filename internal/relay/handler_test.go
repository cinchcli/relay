package relay_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	cinchv1 "github.com/cinchcli/cinch-core/go/cinch/v1"
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
	token, _, _ := login(t, ts.URL)

	// Complete the device code via the authenticated endpoint
	completeBody, _ := json.Marshal(map[string]string{
		"user_code": dcResp.UserCode,
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
	store := relay.NewTestStore(t)

	hub := relay.NewHub()
	go hub.Run()
	handler := relay.NewHandler(store, hub)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Use a separate test server with this store
	_ = ts // keep the original for reference

	// Issue a device code, then manually expire it
	dcResp, _, err := store.CreateDeviceCode("test-cli", "", "", "")
	if err != nil {
		t.Fatalf("create device code failed: %v", err)
	}

	// Manually set expires_at to the past
	_, err = store.ExecForTest(
		"UPDATE device_codes SET expires_at = NOW() - INTERVAL '10 minutes' WHERE device_code = $1",
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

// TestAuthBrowser_SelfHost_ShowsInviteFields verifies that GET /auth/browser on a
// self-hosted relay (no OAuth providers) includes the invite-code and display-name
// inputs, and that an OAuth-configured relay does NOT render those fields.
func TestAuthBrowser_SelfHost_ShowsInviteFields(t *testing.T) {
	t.Run("self-host shows invite and display fields", func(t *testing.T) {
		ts, _ := setupTestServer(t) // no OAuth configured
		resp, err := http.Get(ts.URL + "/auth/browser?device_code=AAAA-BBBB")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		body := string(bodyBytes)
		if !strings.Contains(body, `id="invite"`) {
			t.Error("self-host browser page missing invite-code input")
		}
		if !strings.Contains(body, `id="display"`) {
			t.Error("self-host browser page missing display-name input")
		}
	})

	t.Run("oauth mode omits invite and display fields", func(t *testing.T) {
		ts, _ := setupOAuthTestServer(t, "some-subject", true) // both providers → picker page, no auto-redirect
		resp, err := http.Get(ts.URL + "/auth/browser")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		body := string(bodyBytes)
		if strings.Contains(body, `id="invite"`) {
			t.Error("OAuth browser page must not render invite-code input")
		}
		if strings.Contains(body, `id="display"`) {
			t.Error("OAuth browser page must not render display-name input")
		}
	})
}

func TestCompleteDeviceCode_IssuesFreshCredentials(t *testing.T) {
	ts, _ := setupTestServer(t)

	// Issue a device code for a new CLI session
	dcBody := `{"hostname":"victim-cli"}`
	resp, _ := http.Post(ts.URL+"/auth/device-code", "application/json", strings.NewReader(dcBody))
	var dcResp cinchv1.DeviceCodeStartResponse
	json.NewDecoder(resp.Body).Decode(&dcResp)
	resp.Body.Close()

	// Approver logs in with their own credentials
	attackerToken, _, _ := login(t, ts.URL)

	// Fetch the approver's real device_id — the new CLI must NOT receive this
	devReq, _ := http.NewRequest("GET", ts.URL+"/devices", nil)
	devReq.Header.Set("Authorization", "Bearer "+attackerToken)
	devResp, err := http.DefaultClient.Do(devReq)
	if err != nil {
		t.Fatalf("devices request failed: %v", err)
	}
	var devList []struct {
		ID string `json:"id"`
	}
	json.NewDecoder(devResp.Body).Decode(&devList)
	devResp.Body.Close()
	if len(devList) == 0 {
		t.Fatalf("expected at least one device for approver, got none")
	}
	approverDeviceID := devList[0].ID

	// Approver completes the device code, also including a fake device_id in the
	// body to confirm body credentials are ignored entirely
	fakeDeviceID := "attacker-device-FAKE"
	completeBody, _ := json.Marshal(map[string]string{
		"user_code": dcResp.UserCode,
		"device_id": fakeDeviceID, // must be ignored
	})
	req, _ := http.NewRequest("POST", ts.URL+"/auth/device-code/complete", bytes.NewReader(completeBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+attackerToken)
	completeResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("complete request failed: %v", err)
	}
	defer completeResp.Body.Close()
	if completeResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(completeResp.Body)
		t.Fatalf("complete returned %d: %s", completeResp.StatusCode, body)
	}

	// Poll — new CLI must receive fresh credentials, not the approver's
	pollResp, _ := http.Get(ts.URL + "/auth/device-code/poll?code=" + dcResp.DeviceCode)
	var pollResult cinchv1.DeviceCodePollResponse
	json.NewDecoder(pollResp.Body).Decode(&pollResult)
	pollResp.Body.Close()

	if pollResult.Status != "complete" {
		t.Fatalf("expected status=complete, got %q", pollResult.Status)
	}
	if pollResult.DeviceId == nil {
		t.Fatal("expected device_id in poll response, got nil")
	}
	if pollResult.Token == nil || *pollResult.Token == "" {
		t.Fatal("expected token in poll response, got nil/empty")
	}
	// Fresh device_id — must not be the approver's device nor the fake body value
	if *pollResult.DeviceId == fakeDeviceID {
		t.Errorf("SECURITY: body device_id was stored — credential isolation is broken")
	}
	if *pollResult.DeviceId == approverDeviceID {
		t.Errorf("SECURITY: approver's device_id was forwarded — new CLI shares device with approver")
	}
	// Fresh token — must not be the approver's bearer token
	if *pollResult.Token == attackerToken {
		t.Errorf("SECURITY: approver's token was forwarded — new CLI can impersonate approver")
	}
}

func TestCompleteDeviceCode_AlreadyUsedFails(t *testing.T) {
	ts, _ := setupTestServer(t)

	resp, _ := http.Post(ts.URL+"/auth/device-code", "application/json", strings.NewReader(`{"hostname":"remote"}`))
	var dc cinchv1.DeviceCodeStartResponse
	json.NewDecoder(resp.Body).Decode(&dc)
	resp.Body.Close()

	token, _, _ := login(t, ts.URL)
	body, _ := json.Marshal(map[string]string{"user_code": dc.UserCode})
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/auth/device-code/complete", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		completeResp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("complete request %d failed: %v", i, err)
		}
		if i == 0 && completeResp.StatusCode != http.StatusOK {
			t.Fatalf("first complete returned %d", completeResp.StatusCode)
		}
		if i == 1 && completeResp.StatusCode != http.StatusBadRequest {
			t.Fatalf("second complete returned %d, want 400", completeResp.StatusCode)
		}
		completeResp.Body.Close()
	}
}

func TestCompleteDeviceCode_InvalidCodeFails(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	body, _ := json.Marshal(map[string]string{"user_code": "NOPE-NOPE"})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/auth/device-code/complete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("complete request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("complete returned %d, want 400", resp.StatusCode)
	}
}

// TestIssueWsTicket_RequiresAuth verifies that POST /ws/ticket returns 401
// when called without an auth token.
func TestIssueWsTicket_RequiresAuth(t *testing.T) {
	ts, _ := setupTestServer(t)
	resp, err := http.Post(ts.URL+"/ws/ticket", "application/json", nil)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", resp.StatusCode)
	}
}

// TestIssueWsTicket_ReturnsTicket verifies that an authenticated POST /ws/ticket
// returns a 32-char hex ticket with a ttl field.
func TestIssueWsTicket_ReturnsTicket(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)
	req, _ := http.NewRequest("POST", ts.URL+"/ws/ticket", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	ticket, ok := body["ticket"].(string)
	if !ok || len(ticket) != 32 {
		t.Errorf("expected 32-char hex ticket, got %v", body["ticket"])
	}
	if body["ttl"] == nil {
		t.Errorf("expected ttl in response")
	}
}

// TestWsTicket_SingleUse verifies that a ticket can be consumed exactly once.
func TestWsTicket_SingleUse(t *testing.T) {
	userID := "user-ticket-test"
	deviceID := "dev-ticket-test"
	ticket := relay.IssueWsTicketForTest(userID, deviceID)

	uid, did, ok := relay.ConsumeWsTicketForTest(ticket)
	if !ok || uid != userID || did != deviceID {
		t.Errorf("first consume failed: ok=%v uid=%v did=%v", ok, uid, did)
	}
	_, _, ok2 := relay.ConsumeWsTicketForTest(ticket)
	if ok2 {
		t.Errorf("second consume should fail (single-use)")
	}
}

// ─── REST /clips filter tests ────────────────────────────────────────────────

func httpPushClip(t *testing.T, baseURL, token, content, contentType, source string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{
		"content":      content,
		"content_type": contentType,
		"source":       source,
		"byte_size":    int64(len(content)),
		// Relay enforces E2EE on plaintext push. We do not actually encrypt
		// the body here — the tests only assert routing/filter behaviour, and
		// the source/content_type/byte_size fields are what the filters key on.
		// Setting encrypted=true bypasses the 422 gate; the stored content
		// stays as-is for assertion purposes.
		"encrypted": true,
	})
	req, _ := http.NewRequest("POST", baseURL+"/clips", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("push status %d: %s", resp.StatusCode, b)
	}
	var out struct {
		ClipID string `json:"clip_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out.ClipID
}

func httpGetClips(t *testing.T, baseURL, token, pathAndQuery string) []*cinchv1.Clip {
	t.Helper()
	req, _ := http.NewRequest("GET", baseURL+pathAndQuery, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", pathAndQuery, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var clips []*cinchv1.Clip
	if err := json.NewDecoder(resp.Body).Decode(&clips); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return clips
}

func httpGetLatestClip(t *testing.T, baseURL, token, pathAndQuery string) *cinchv1.Clip {
	t.Helper()
	req, _ := http.NewRequest("GET", baseURL+pathAndQuery, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", pathAndQuery, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var clip cinchv1.Clip
	if err := json.NewDecoder(resp.Body).Decode(&clip); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return &clip
}

func TestGETClips_SourceFilter(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	httpPushClip(t, ts.URL, token, "hello", "text", "remote:desktop")
	httpPushClip(t, ts.URL, token, "world", "text", "remote:phone")

	clips := httpGetClips(t, ts.URL, token, "/clips?source=remote:phone&limit=50")
	if len(clips) != 1 {
		t.Fatalf("want 1 clip, got %d: %+v", len(clips), clips)
	}
	if clips[0].Source != "remote:phone" {
		t.Fatalf("want source remote:phone, got %s", clips[0].Source)
	}
}

func TestGETClips_ExcludeSource(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	httpPushClip(t, ts.URL, token, "hello", "text", "remote:desktop")
	httpPushClip(t, ts.URL, token, "world", "text", "remote:phone")

	clips := httpGetClips(t, ts.URL, token, "/clips?exclude_source=remote:phone&limit=50")
	if len(clips) != 1 || clips[0].Source != "remote:desktop" {
		t.Fatalf("want only remote:desktop clip, got %+v", clips)
	}
}

func TestGETClipsLatest_ExcludeSource(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	httpPushClip(t, ts.URL, token, "from-desktop", "text", "remote:desktop")
	httpPushClip(t, ts.URL, token, "from-phone", "text", "remote:phone")

	clip := httpGetLatestClip(t, ts.URL, token, "/clips/latest?exclude_source=remote:phone")
	if clip.Content != "from-desktop" {
		t.Fatalf("want from-desktop, got %+v", clip)
	}
}

func TestGETClipsLatest_RejectsSourceAndExcludeSourceTogether(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	req, _ := http.NewRequest("GET", ts.URL+"/clips/latest?source=remote:desktop&exclude_source=remote:phone", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}

// TestRemovedEndpoints guards against accidental re-introduction of the
// pair-token routes. Both must return 404 from the mux — the handlers
// themselves were deleted in the OAuth-only migration.
func TestRemovedEndpoints(t *testing.T) {
	ts, _ := setupTestServer(t)

	for _, route := range []struct {
		method, path string
	}{
		{"POST", "/auth/pair"},
		{"POST", "/auth/pair-token/new"},
	} {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			req, _ := http.NewRequest(route.method, ts.URL+route.path, nil)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("expected 404 for removed route, got %d", resp.StatusCode)
			}
		})
	}
}
