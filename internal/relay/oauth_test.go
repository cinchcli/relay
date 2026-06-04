package relay_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	relay "github.com/cinchcli/relay/internal/relay"
	"golang.org/x/oauth2"
)

const testClientSecret = "test-secret-abc123"

// testNonce is a fixed 128-bit hex nonce used to mint signed states and the
// matching nonce cookie in CLI-flow tests.
const testNonce = "0123456789abcdef0123456789abcdef"

// setupOAuthTestServer builds a relay handler with fake OAuth provider(s) wired up.
// fakeSubject is what the injected subjectFetcher returns.
// When bothProviders is true, both GitHub and Google are configured (forces the
// AuthBrowser picker page). When false, only Google is configured.
// Returns the relay test server and the fake OAuth token endpoint server.
func setupOAuthTestServer(t *testing.T, fakeSubject string, bothProviders bool) (ts *httptest.Server, tokenServer *httptest.Server) {
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

	store := relay.NewTestStore(t)

	hub := relay.NewHub()
	go hub.Run()

	handler := relay.NewHandler(store, hub)

	// Injected identityFetcher returns the caller-supplied fakeSubject,
	// bypassing real GitHub/Google HTTP calls.
	fetcher := func(_ string, _ *oauth2.Config, _ *oauth2.Token) (string, string, bool, error) {
		return fakeSubject, "", false, nil
	}

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	ts = httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	gProvider := relay.NewTestOAuthProvider(
		testClientSecret,
		tokenServer.URL+"/token",
		ts.URL+"/auth/oauth/google/callback",
		fetcher,
	)
	providers := &relay.OAuthProviders{Google: gProvider}
	if bothProviders {
		ghProvider := relay.NewTestOAuthProvider(
			testClientSecret,
			tokenServer.URL+"/token",
			ts.URL+"/auth/oauth/github/callback",
			fetcher,
		)
		providers.GitHub = ghProvider
	}
	handler.OAuth = providers
	handler.BaseURL = ts.URL

	return ts, tokenServer
}

// buildCallbackURL constructs /auth/oauth/google/callback?code=X&state=Y. The
// state carries testNonce; for the CLI flow (non-empty user_code) the request
// still needs the matching nonce cookie — use cliCallback for that.
func buildCallbackURL(base, userCode, clientSecret string) string {
	state := relay.EncodeStateForTest(userCode, testNonce, clientSecret)
	v := url.Values{
		"code":  {"fake-oauth-code"},
		"state": {state},
	}
	return base + "/auth/oauth/google/callback?" + v.Encode()
}

// testDeviceCode is the subset of the device-code response the tests need.
type testDeviceCode struct {
	DeviceCode string `json:"device_code"`
	UserCode   string `json:"user_code"`
}

// issueDeviceCode starts a real device-code flow so CompleteDeviceCode has a
// row to update, returning both the device_code and user_code.
func issueDeviceCode(t *testing.T, base, hostname string) testDeviceCode {
	t.Helper()
	resp, err := http.Post(base+"/auth/device-code", "application/json",
		strings.NewReader(`{"hostname":"`+hostname+`"}`))
	if err != nil {
		t.Fatalf("device code request failed: %v", err)
	}
	defer resp.Body.Close()
	var dc testDeviceCode
	if err := json.NewDecoder(resp.Body).Decode(&dc); err != nil {
		t.Fatalf("decode device code: %v", err)
	}
	if dc.UserCode == "" {
		t.Fatal("user_code is empty")
	}
	return dc
}

// cliCallback performs the CLI OAuth callback with the per-flow nonce cookie
// set, exactly as the browser that ran OAuthStart would send it. The returned
// response body is still open.
func cliCallback(t *testing.T, base, userCode, clientSecret string) *http.Response {
	t.Helper()
	state := relay.EncodeStateForTest(userCode, testNonce, clientSecret)
	u := base + "/auth/oauth/google/callback?" + url.Values{
		"code":  {"fake-oauth-code"},
		"state": {state},
	}.Encode()
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		t.Fatalf("build callback request: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: relay.OAuthStateCookieName(), Value: testNonce})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	return resp
}

// ticketField extracts the hidden ticket value from the confirm page HTML.
var ticketField = regexp.MustCompile(`name="ticket" value="([^"]+)"`)

func extractTicket(t *testing.T, html string) string {
	t.Helper()
	m := ticketField.FindStringSubmatch(html)
	if len(m) != 2 {
		t.Fatalf("confirm page missing ticket field; body: %.300s", html)
	}
	return m[1]
}

// confirmTicket POSTs the ticket to /auth/oauth/confirm, completing the flow.
func confirmTicket(t *testing.T, base, ticket string) *http.Response {
	t.Helper()
	resp, err := http.PostForm(base+"/auth/oauth/confirm", url.Values{"ticket": {ticket}})
	if err != nil {
		t.Fatalf("confirm POST failed: %v", err)
	}
	return resp
}

// ── Desktop flow ────────────────────────────────────────────────────────────

// TestOAuthCallback_Desktop_RedirectsToCinch verifies that when no device_code
// is present (userCode == ""), OAuthCallback redirects to cinch://auth/callback
// with token, device_id, user_id, and relay_url query params.
func TestOAuthCallback_Desktop_RedirectsToCinch(t *testing.T) {
	ts, _ := setupOAuthTestServer(t, "github-subject-123", false)

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
	ts, _ := setupOAuthTestServer(t, "stable-subject-xyz", false)

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

// TestOAuthCallback_CLI_ShowsConfirmPage verifies that when a device_code is
// present (CLI flow), the callback renders a confirmation page that displays the
// user_code and posts to /auth/oauth/confirm — it must NOT auto-complete the
// device-code flow (RFC 8628 user_code confirmation, device-code phishing
// defense).
func TestOAuthCallback_CLI_ShowsConfirmPage(t *testing.T) {
	ts, _ := setupOAuthTestServer(t, "cli-subject-456", false)

	dc := issueDeviceCode(t, ts.URL, "test-cli")

	resp := cliCallback(t, ts.URL, dc.UserCode, testClientSecret)
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
	// The confirm page must surface the user_code so the human can check it
	// matches the code their terminal printed before confirming.
	if !strings.Contains(string(body), dc.UserCode) {
		t.Errorf("confirm page should display user_code %q; body: %.300s", dc.UserCode, body)
	}
	// It must post to the confirm endpoint rather than show "Signed in".
	if !strings.Contains(string(body), "/auth/oauth/confirm") {
		t.Errorf("confirm page should post to /auth/oauth/confirm; body: %.300s", body)
	}
	if strings.Contains(string(body), "Signed in") {
		t.Errorf("callback must not auto-complete (no success page yet); body: %.300s", body)
	}
}

// TestOAuthCallback_CLI_CompletesDeviceCode verifies the full CLI flow: the
// callback alone leaves the device-code pending; only the confirm POST marks it
// complete so poll returns the credentials.
func TestOAuthCallback_CLI_CompletesDeviceCode(t *testing.T) {
	ts, _ := setupOAuthTestServer(t, "cli-subject-poll", false)

	dc := issueDeviceCode(t, ts.URL, "poll-test")

	pollStatus := func() (status, token, userID string) {
		resp, _ := http.Get(ts.URL + "/auth/device-code/poll?code=" + dc.DeviceCode)
		var p struct {
			Status string `json:"status"`
			Token  string `json:"token"`
			UserID string `json:"user_id"`
		}
		json.NewDecoder(resp.Body).Decode(&p)
		resp.Body.Close()
		return p.Status, p.Token, p.UserID
	}

	// Poll before callback — pending.
	if status, _, _ := pollStatus(); status != "pending" {
		t.Fatalf("expected pending before callback, got %q", status)
	}

	// CLI OAuth callback renders the confirm page; it does not complete yet.
	cbResp := cliCallback(t, ts.URL, dc.UserCode, testClientSecret)
	body, _ := io.ReadAll(cbResp.Body)
	cbResp.Body.Close()

	// Still pending until the user confirms.
	if status, _, _ := pollStatus(); status != "pending" {
		t.Fatalf("expected still pending before confirm, got %q", status)
	}

	// Confirm with the ticket embedded in the page.
	ticket := extractTicket(t, string(body))
	confResp := confirmTicket(t, ts.URL, ticket)
	confBody, _ := io.ReadAll(confResp.Body)
	confResp.Body.Close()
	if confResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from confirm, got %d: %s", confResp.StatusCode, confBody)
	}
	if !strings.Contains(string(confBody), "Signed in") {
		t.Errorf("expected success HTML after confirm, got: %.200s", confBody)
	}

	// Poll after confirm — complete with credentials.
	status, token, userID := pollStatus()
	if status != "complete" {
		t.Errorf("expected status=complete after confirm, got %q", status)
	}
	if token == "" {
		t.Error("token should not be empty after completion")
	}
	if userID == "" {
		t.Error("user_id should not be empty after completion")
	}
}

// TestOAuthCallback_CLI_MissingNonceCookie_Returns400 verifies that a CLI-flow
// callback without the per-flow nonce cookie set by OAuthStart is rejected. This
// blocks cross-browser state replay / login-CSRF.
func TestOAuthCallback_CLI_MissingNonceCookie_Returns400(t *testing.T) {
	ts, _ := setupOAuthTestServer(t, "cli-subject-nocookie", false)
	dc := issueDeviceCode(t, ts.URL, "nocookie-host")

	// buildCallbackURL does not attach the nonce cookie; with a non-empty
	// user_code this is the CLI flow, so the cookie is required.
	resp, err := http.Get(buildCallbackURL(ts.URL, dc.UserCode, testClientSecret))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 when nonce cookie missing, got %d", resp.StatusCode)
	}
}

// TestOAuthConfirm_InvalidTicket_Returns400 verifies an unknown/forged confirm
// ticket is rejected without completing any flow.
func TestOAuthConfirm_InvalidTicket_Returns400(t *testing.T) {
	ts, _ := setupOAuthTestServer(t, "any", false)

	resp := confirmTicket(t, ts.URL, "not-a-real-ticket")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid ticket, got %d", resp.StatusCode)
	}
}

// ── Error cases ──────────────────────────────────────────────────────────────

// TestOAuthCallback_InvalidState_Returns400 verifies that a tampered state
// parameter is rejected with 400.
func TestOAuthCallback_InvalidState_Returns400(t *testing.T) {
	ts, _ := setupOAuthTestServer(t, "any-subject", false)

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
	ts, _ := setupOAuthTestServer(t, "any-subject", false)

	state := relay.EncodeStateForTest("", testNonce, testClientSecret)
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
	ts, _ := setupOAuthTestServer(t, "any", false)

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
	ts, _ := setupOAuthTestServer(t, "reauth-subject-789", false)

	// Helper: run the full device-code OAuth flow (callback + confirm) and
	// return the device token.
	doOAuthFlow := func() (token, deviceID string) {
		dc := issueDeviceCode(t, ts.URL, "reauth-host")

		cbResp := cliCallback(t, ts.URL, dc.UserCode, testClientSecret)
		cbBody, _ := io.ReadAll(cbResp.Body)
		cbResp.Body.Close()

		confResp := confirmTicket(t, ts.URL, extractTicket(t, string(cbBody)))
		confResp.Body.Close()

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

// TestAuthBrowser_XSSPrevention verifies that a crafted device_code containing
// HTML/script injection is rejected with 400. The regex guard fires before any
// HTML is rendered, so the payload must never appear in the response body.
func TestAuthBrowser_XSSPrevention(t *testing.T) {
	ts, _ := setupOAuthTestServer(t, "test-subject", true)

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

	// The regex guard must reject the malformed device_code with 400.
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for XSS payload, got %d", resp.StatusCode)
	}

	// Extra sanity: the 400 response body must not contain a script tag.
	if strings.Contains(strings.ToLower(bodyStr), "<script>") {
		t.Errorf("XSS payload reflected in 400 response body: %q", bodyStr)
	}
}

// TestAuthBrowser_ValidDeviceCode verifies that a well-formed device_code
// (XXXX-XXXX uppercase alphanumeric) renders the picker page successfully.
func TestAuthBrowser_ValidDeviceCode(t *testing.T) {
	ts, _ := setupOAuthTestServer(t, "test-subject", true)

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

	// The GitHub href must carry the device_code so the CLI flow completes.
	if !strings.Contains(bodyStr, "/auth/oauth/github/start?device_code=ABCD-1234") {
		t.Errorf("expected GitHub href with device code, got: %s", bodyStr)
	}
}

// TestFetchOAuthIdentity_DisplayName verifies that fetchOAuthIdentity returns the
// correct display name for each provider according to documented fallback rules.
//
// The function uses cfg.Client(ctx, tok) to build an HTTP client. By placing a
// custom http.Client (with a host-rewriting transport) into the context via
// oauth2.WithClient, we redirect provider API calls to a local httptest.Server
// without modifying the production code beyond accepting a context.Context.
func TestFetchOAuthIdentity_DisplayName(t *testing.T) {
	cases := []struct {
		name     string
		provider string
		userBody string
		wantName string
	}{
		{
			name:     "github_uses_name_when_set",
			provider: "github",
			userBody: `{"id":42,"login":"jinmu-io","name":"Jinmu Lee"}`,
			wantName: "Jinmu Lee",
		},
		{
			name:     "github_falls_back_to_login_when_name_missing",
			provider: "github",
			userBody: `{"id":42,"login":"jinmu-io"}`,
			wantName: "jinmu-io",
		},
		{
			name:     "github_falls_back_to_login_when_name_blank",
			provider: "github",
			userBody: `{"id":42,"login":"jinmu-io","name":""}`,
			wantName: "jinmu-io",
		},
		{
			name:     "google_uses_name",
			provider: "google",
			userBody: `{"sub":"123","email":"a@b.com","email_verified":true,"name":"Alice Example"}`,
			wantName: "Alice Example",
		},
		{
			name:     "google_blank_name_returns_empty",
			provider: "google",
			userBody: `{"sub":"123","email":"a@b.com","email_verified":true}`,
			wantName: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()

			switch tc.provider {
			case "github":
				userBody := tc.userBody
				mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(userBody)) //nolint:errcheck
				})
				mux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(`[]`)) //nolint:errcheck
				})
			case "google":
				userBody := tc.userBody
				mux.HandleFunc("/v1/userinfo", func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(userBody)) //nolint:errcheck
				})
			}

			srv := httptest.NewServer(mux)
			defer srv.Close()

			// Determine which provider host fetchOAuthIdentity calls.
			var providerHost string
			switch tc.provider {
			case "github":
				providerHost = "api.github.com"
			case "google":
				providerHost = "openidconnect.googleapis.com"
			}

			// Build a host-rewriting transport that redirects provider API calls to srv.
			// cfg.Client(ctx, tok) calls internal.ContextClient(ctx) to get the base
			// http.Client and wraps its Transport in an oauth2.Transport (which attaches
			// the Bearer token). So we inject a plain http.Client here; the oauth2
			// package adds the token layer on top.
			rt := &hostRewriteTransport{
				base:    http.DefaultTransport,
				oldHost: providerHost,
				newHost: srv.Listener.Addr().String(),
			}
			httpClient := &http.Client{Transport: rt}
			tok := &oauth2.Token{AccessToken: "test-token"}

			// Inject the custom client via context so cfg.Client(ctx, tok) uses it as
			// the base transport. oauth2.HTTPClient is the context key recognized by
			// internal.ContextClient inside the oauth2 package.
			ctx := context.WithValue(t.Context(), oauth2.HTTPClient, httpClient)

			// cfg.Endpoint is irrelevant because we supply a static token; the token URL
			// is never called. We still provide a dummy endpoint to satisfy oauth2.Config.
			cfg := &oauth2.Config{
				ClientID:     "test-id",
				ClientSecret: "test-secret",
				Endpoint: oauth2.Endpoint{
					AuthURL:   srv.URL + "/auth",
					TokenURL:  srv.URL + "/token",
					AuthStyle: oauth2.AuthStyleInParams,
				},
			}

			_, _, gotName, _, err := relay.FetchOAuthIdentityForTest(ctx, tc.provider, cfg, tok)
			if err != nil {
				t.Fatalf("fetchOAuthIdentity returned error: %v", err)
			}
			if gotName != tc.wantName {
				t.Errorf("displayName = %q, want %q", gotName, tc.wantName)
			}
		})
	}
}

// hostRewriteTransport is an http.RoundTripper that rewrites the request host
// from oldHost to newHost, redirecting provider API calls to a local httptest.Server.
type hostRewriteTransport struct {
	base    http.RoundTripper
	oldHost string
	newHost string
}

func (rt *hostRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == rt.oldHost {
		clone := req.Clone(req.Context())
		clone.URL.Host = rt.newHost
		clone.URL.Scheme = "http"
		clone.Host = rt.newHost
		return rt.base.RoundTrip(clone)
	}
	return rt.base.RoundTrip(req)
}

// TestGetProviders_WithOAuth returns the configured provider names.
func TestGetProviders_WithOAuth(t *testing.T) {
	ts, _ := setupOAuthTestServer(t, "any", false)

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
