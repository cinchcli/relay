package relay_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	relay "github.com/cinchcli/relay/internal/relay"
	"golang.org/x/oauth2"
)

const testClientSecret = "test-secret-abc123"

// setupOAuthTestServer builds a relay handler with a fake OAuth provider wired up.
// fakeSubject is what the injected subjectFetcher returns.
// Returns the relay test server and the fake OAuth token endpoint server.
func setupOAuthTestServer(t *testing.T, fakeSubject string) (ts *httptest.Server, tokenServer *httptest.Server) {
	t.Helper()

	// Fake token endpoint: accepts any code and returns a stub access token.
	tokenServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fake-access-token",
			"token_type":   "Bearer",
		})
	}))
	t.Cleanup(tokenServer.Close)

	store, err := relay.NewStore(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	hub := relay.NewHub()
	go hub.Run()

	handler := relay.NewHandler(store, hub)

	// Injected subjectFetcher returns the caller-supplied fakeSubject,
	// bypassing real GitHub/Google HTTP calls.
	fetcher := func(_ string, _ *oauth2.Config, _ *oauth2.Token) (string, error) {
		return fakeSubject, nil
	}

	// Wire up a Google provider pointing at the fake token server.
	// The redirectURL will be filled in after ts is created.
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	ts = httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	provider := relay.NewTestOAuthProvider(
		testClientSecret,
		tokenServer.URL+"/token",
		ts.URL+"/auth/oauth/google/callback",
		fetcher,
	)
	handler.OAuth = &relay.OAuthProviders{Google: provider}
	handler.BaseURL = ts.URL

	return ts, tokenServer
}

// buildCallbackURL constructs /auth/oauth/google/callback?code=X&state=Y.
func buildCallbackURL(base, userCode, clientSecret string) string {
	state := relay.EncodeStateForTest(userCode, clientSecret)
	v := url.Values{
		"code":  {"fake-oauth-code"},
		"state": {state},
	}
	return base + "/auth/oauth/google/callback?" + v.Encode()
}

// ── Desktop flow ────────────────────────────────────────────────────────────

// TestOAuthCallback_Desktop_RedirectsToCinch verifies that when no device_code
// is present (userCode == ""), OAuthCallback redirects to cinch://auth/callback
// with token, device_id, user_id, and relay_url query params.
func TestOAuthCallback_Desktop_RedirectsToCinch(t *testing.T) {
	ts, _ := setupOAuthTestServer(t, "github-subject-123")

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse // capture the redirect, don't follow
	}}

	resp, err := client.Get(buildCallbackURL(ts.URL, "", testClientSecret))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 302 redirect, got %d: %s", resp.StatusCode, body)
	}

	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "cinch://auth/callback") {
		t.Fatalf("expected cinch:// redirect, got %q", loc)
	}

	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("invalid redirect URL: %v", err)
	}
	q := parsed.Query()

	if q.Get("token") == "" {
		t.Error("redirect URL missing token param")
	}
	if len(q.Get("token")) != 64 {
		t.Errorf("token should be 64 hex chars, got %d: %q", len(q.Get("token")), q.Get("token"))
	}
	if q.Get("device_id") == "" {
		t.Error("redirect URL missing device_id param")
	}
	if q.Get("user_id") == "" {
		t.Error("redirect URL missing user_id param")
	}
	if q.Get("relay_url") == "" {
		t.Error("redirect URL missing relay_url param")
	}
	if !strings.Contains(q.Get("relay_url"), ts.URL) {
		t.Errorf("relay_url %q should contain relay base %q", q.Get("relay_url"), ts.URL)
	}
}

// TestOAuthCallback_Desktop_SecondLogin_ReusesSameUser verifies that calling the
// desktop OAuth flow twice with the same OAuth subject provisions the same user ID.
func TestOAuthCallback_Desktop_SecondLogin_ReusesSameUser(t *testing.T) {
	ts, _ := setupOAuthTestServer(t, "stable-subject-xyz")

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	extractUserID := func() string {
		resp, err := client.Get(buildCallbackURL(ts.URL, "", testClientSecret))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		loc := resp.Header.Get("Location")
		u, _ := url.Parse(loc)
		return u.Query().Get("user_id")
	}

	first := extractUserID()
	second := extractUserID()

	if first == "" || second == "" {
		t.Fatal("user_id should not be empty")
	}
	if first != second {
		t.Errorf("same OAuth subject should map to same user_id: %q vs %q", first, second)
	}
}

// ── CLI flow ────────────────────────────────────────────────────────────────

// TestOAuthCallback_CLI_ShowsSuccessHTML verifies that when a device_code is
// present (CLI flow), the response is the HTML success page (not a redirect).
func TestOAuthCallback_CLI_ShowsSuccessHTML(t *testing.T) {
	ts, _ := setupOAuthTestServer(t, "cli-subject-456")

	// Issue a real device code so CompleteDeviceCode has a row to update.
	dcResp, err := http.Post(ts.URL+"/auth/device-code", "application/json",
		strings.NewReader(`{"hostname":"test-cli"}`))
	if err != nil {
		t.Fatalf("device code request failed: %v", err)
	}
	defer dcResp.Body.Close()
	var dc struct {
		UserCode string `json:"user_code"`
	}
	json.NewDecoder(dcResp.Body).Decode(&dc)
	if dc.UserCode == "" {
		t.Fatal("user_code is empty")
	}

	resp, err := http.Get(buildCallbackURL(ts.URL, dc.UserCode, testClientSecret))
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("expected text/html content type, got %q", ct)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Signed in") {
		t.Errorf("expected success HTML with 'Signed in', got: %.200s", body)
	}
}

// TestOAuthCallback_CLI_CompletesDeviceCode verifies that the CLI flow marks the
// device code as complete so that poll returns the credentials.
func TestOAuthCallback_CLI_CompletesDeviceCode(t *testing.T) {
	ts, _ := setupOAuthTestServer(t, "cli-subject-poll")

	// Issue device code.
	dcResp, _ := http.Post(ts.URL+"/auth/device-code", "application/json",
		strings.NewReader(`{"hostname":"poll-test"}`))
	var dc struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	json.NewDecoder(dcResp.Body).Decode(&dc)
	dcResp.Body.Close()

	// Poll before callback — should be pending.
	pollResp, _ := http.Get(ts.URL + "/auth/device-code/poll?code=" + dc.DeviceCode)
	var pending struct{ Status string }
	json.NewDecoder(pollResp.Body).Decode(&pending)
	pollResp.Body.Close()
	if pending.Status != "pending" {
		t.Fatalf("expected pending before callback, got %q", pending.Status)
	}

	// Trigger CLI OAuth callback.
	cbResp, err := http.Get(buildCallbackURL(ts.URL, dc.UserCode, testClientSecret))
	if err != nil {
		t.Fatalf("callback failed: %v", err)
	}
	cbResp.Body.Close()

	// Poll after callback — should be complete with credentials.
	pollResp2, _ := http.Get(ts.URL + "/auth/device-code/poll?code=" + dc.DeviceCode)
	var complete struct {
		Status   string `json:"status"`
		Token    string `json:"token"`
		UserID   string `json:"user_id"`
		DeviceID string `json:"device_id"`
	}
	json.NewDecoder(pollResp2.Body).Decode(&complete)
	pollResp2.Body.Close()

	if complete.Status != "complete" {
		t.Errorf("expected status=complete after callback, got %q", complete.Status)
	}
	if complete.Token == "" {
		t.Error("token should not be empty after completion")
	}
	if complete.UserID == "" {
		t.Error("user_id should not be empty after completion")
	}
}

// ── Error cases ──────────────────────────────────────────────────────────────

// TestOAuthCallback_InvalidState_Returns400 verifies that a tampered state
// parameter is rejected with 400.
func TestOAuthCallback_InvalidState_Returns400(t *testing.T) {
	ts, _ := setupOAuthTestServer(t, "any-subject")

	v := url.Values{
		"code":  {"some-code"},
		"state": {"tampered.invalidsig"},
	}
	resp, err := http.Get(ts.URL + "/auth/oauth/google/callback?" + v.Encode())
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid state, got %d", resp.StatusCode)
	}
}

// TestOAuthCallback_MissingCode_Returns400 verifies that a missing OAuth code
// is rejected with 400.
func TestOAuthCallback_MissingCode_Returns400(t *testing.T) {
	ts, _ := setupOAuthTestServer(t, "any-subject")

	state := relay.EncodeStateForTest("", testClientSecret)
	v := url.Values{"state": {state}} // no code param
	resp, err := http.Get(ts.URL + "/auth/oauth/google/callback?" + v.Encode())
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for missing code, got %d", resp.StatusCode)
	}
}

// TestOAuthCallback_OAuthNotConfigured_Returns501 verifies that the callback
// returns 501 when no OAuth providers are configured.
func TestOAuthCallback_OAuthNotConfigured_Returns501(t *testing.T) {
	ts, _ := setupTestServer(t) // plain setup — no OAuth

	resp, err := http.Get(ts.URL + "/auth/oauth/google/callback?code=x&state=y")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("expected 501 when OAuth not configured, got %d", resp.StatusCode)
	}
}

// ── OAuthStart ───────────────────────────────────────────────────────────────

// TestOAuthStart_RedirectsToProvider verifies that /auth/oauth/google/start
// redirects to the provider's authorization URL.
func TestOAuthStart_RedirectsToProvider(t *testing.T) {
	ts, _ := setupOAuthTestServer(t, "any")

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(ts.URL + "/auth/oauth/google/start?device_code=ABCD-1234")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected 302, got %d", resp.StatusCode)
	}

	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatal("no Location header in redirect")
	}
	// State should encode the device_code.
	if !strings.Contains(loc, "state=") {
		t.Errorf("redirect URL missing state param: %q", loc)
	}
}

// TestOAuthStart_OAuthNotConfigured_Returns501 verifies that /start returns 501
// when no OAuth providers are configured.
func TestOAuthStart_OAuthNotConfigured_Returns501(t *testing.T) {
	ts, _ := setupTestServer(t)

	resp, err := http.Get(ts.URL + "/auth/oauth/google/start?device_code=TEST")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("expected 501, got %d", resp.StatusCode)
	}
}

// TestOAuthCallback_ReauthAfterRevoke_ClearsRevocation verifies that a previously
// revoked device can re-authenticate via OAuth and get a valid (non-revoked) token.
// Regression test for: UpsertOAuthUser ON CONFLICT not clearing revoked_at.
func TestOAuthCallback_ReauthAfterRevoke_ClearsRevocation(t *testing.T) {
	ts, _ := setupOAuthTestServer(t, "reauth-subject-789")

	// Helper: run the full device-code OAuth flow and return the device token.
	doOAuthFlow := func() (token, deviceID string) {
		dcResp, err := http.Post(ts.URL+"/auth/device-code", "application/json",
			strings.NewReader(`{"hostname":"reauth-host"}`))
		if err != nil {
			t.Fatalf("device code request failed: %v", err)
		}
		var dc struct {
			DeviceCode string `json:"device_code"`
			UserCode   string `json:"user_code"`
		}
		json.NewDecoder(dcResp.Body).Decode(&dc)
		dcResp.Body.Close()

		cbResp, err := http.Get(buildCallbackURL(ts.URL, dc.UserCode, testClientSecret))
		if err != nil {
			t.Fatalf("oauth callback failed: %v", err)
		}
		cbResp.Body.Close()

		pollResp, err := http.Get(ts.URL + "/auth/device-code/poll?code=" + dc.DeviceCode)
		if err != nil {
			t.Fatalf("poll failed: %v", err)
		}
		var result struct {
			Status   string `json:"status"`
			Token    string `json:"token"`
			DeviceID string `json:"device_id"`
		}
		json.NewDecoder(pollResp.Body).Decode(&result)
		pollResp.Body.Close()

		if result.Status != "complete" {
			t.Fatalf("expected complete, got %q", result.Status)
		}
		return result.Token, result.DeviceID
	}

	// First sign-in.
	token1, deviceID1 := doOAuthFlow()
	if token1 == "" {
		t.Fatal("first sign-in: token should not be empty")
	}

	// Revoke the device via the API.
	revokeBody := strings.NewReader(`{"device_id":"` + deviceID1 + `"}`)
	req, _ := http.NewRequest("POST", ts.URL+"/auth/device/revoke", revokeBody)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token1)
	revokeResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("revoke request failed: %v", err)
	}
	revokeResp.Body.Close()
	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: expected 200, got %d", revokeResp.StatusCode)
	}

	// Confirm the old token is revoked: /devices should return 401.
	req2, _ := http.NewRequest("GET", ts.URL+"/devices", nil)
	req2.Header.Set("Authorization", "Bearer "+token1)
	resp, _ := http.DefaultClient.Do(req2)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after revoke: expected 401 with old token, got %d", resp.StatusCode)
	}

	// Re-authenticate via OAuth (same GitHub subject → same user, same device hostname).
	token2, _ := doOAuthFlow()
	if token2 == "" {
		t.Fatal("second sign-in: token should not be empty")
	}
	if token2 == token1 {
		t.Fatal("second sign-in should issue a new token")
	}

	// New token must NOT be rejected as revoked.
	req3, _ := http.NewRequest("GET", ts.URL+"/devices", nil)
	req3.Header.Set("Authorization", "Bearer "+token2)
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("devices request failed: %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("after re-auth: expected 200, got %d (re-auth token was rejected as revoked)", resp3.StatusCode)
	}
}

// ── GetProviders ─────────────────────────────────────────────────────────────

// TestGetProviders_NoOAuth returns an empty providers list when OAuth is not configured.
func TestGetProviders_NoOAuth(t *testing.T) {
	ts, _ := setupTestServer(t)

	resp, err := http.Get(ts.URL + "/auth/providers")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body struct {
		Providers []string `json:"providers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(body.Providers) != 0 {
		t.Errorf("expected empty providers, got %v", body.Providers)
	}
}

// setupBothProvidersTestServer builds a relay handler with both GitHub and
// Google OAuth configured. This forces AuthBrowser to render the picker page
// (no auto-redirect fires when both providers are present), which is the code
// path that interpolates device_code into href attributes.
func setupBothProvidersTestServer(t *testing.T) *httptest.Server {
	t.Helper()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fake-access-token",
			"token_type":   "Bearer",
		})
	}))
	t.Cleanup(tokenServer.Close)

	store, err := relay.NewStore(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	hub := relay.NewHub()
	go hub.Run()

	handler := relay.NewHandler(store, hub)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	fetcher := func(_ string, _ *oauth2.Config, _ *oauth2.Token) (string, error) {
		return "test-subject", nil
	}

	ghProvider := relay.NewTestOAuthProvider(
		testClientSecret,
		tokenServer.URL+"/token",
		ts.URL+"/auth/oauth/github/callback",
		fetcher,
	)
	gProvider := relay.NewTestOAuthProvider(
		testClientSecret,
		tokenServer.URL+"/token",
		ts.URL+"/auth/oauth/google/callback",
		fetcher,
	)
	handler.OAuth = &relay.OAuthProviders{GitHub: ghProvider, Google: gProvider}
	handler.BaseURL = ts.URL

	return ts
}

// TestAuthBrowser_XSSPrevention verifies that a crafted device_code containing
// HTML/script injection is not reflected verbatim in the response body.
// A payload of `x"><script>alert(1)</script>` must never appear as a literal
// <script> tag in the HTML output. The server must either escape it or reject
// the request with 400.
func TestAuthBrowser_XSSPrevention(t *testing.T) {
	ts := setupBothProvidersTestServer(t)

	// URL-encoded form of: x"><script>alert(1)</script>
	xssPayload := `x"><script>alert(1)</script>`
	resp, err := http.Get(ts.URL + "/auth/browser?device_code=x%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	bodyStr := string(body)

	// Either 400 (rejected) or 200 with the payload escaped — both are fine.
	// What is NOT acceptable: the literal payload in the output.
	if strings.Contains(strings.ToLower(bodyStr), "<script>") {
		t.Errorf("XSS payload reflected in response body (status %d); got %q", resp.StatusCode, bodyStr)
	}

	// If 400, we're done — the server rejected it cleanly.
	if resp.StatusCode == http.StatusBadRequest {
		return
	}

	// If 200, verify the raw payload string is not present verbatim.
	if strings.Contains(bodyStr, xssPayload) {
		t.Errorf("raw XSS payload %q reflected verbatim in 200 response", xssPayload)
	}
}

// TestAuthBrowser_ValidDeviceCode verifies that a well-formed device_code
// (XXXX-XXXX uppercase alphanumeric) renders the picker page successfully.
func TestAuthBrowser_ValidDeviceCode(t *testing.T) {
	ts := setupBothProvidersTestServer(t)

	resp, err := http.Get(ts.URL + "/auth/browser?device_code=ABCD-1234")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 for valid device_code, got %d: %s", resp.StatusCode, body)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	bodyStr := string(body)

	// The OAuth picker page should contain both provider buttons.
	if !strings.Contains(bodyStr, "github") {
		t.Error("expected GitHub button in picker page")
	}
	if !strings.Contains(bodyStr, "google") {
		t.Error("expected Google button in picker page")
	}
}

// TestGetProviders_WithOAuth returns the configured provider names.
func TestGetProviders_WithOAuth(t *testing.T) {
	ts, _ := setupOAuthTestServer(t, "any")

	resp, err := http.Get(ts.URL + "/auth/providers")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body struct {
		Providers []string `json:"providers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(body.Providers) != 1 || body.Providers[0] != "google" {
		t.Errorf("expected [google] (only Google wired in setupOAuthTestServer), got %v", body.Providers)
	}
}
