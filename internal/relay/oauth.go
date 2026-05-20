package relay

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

// OAuthProvider holds credentials and config for one OAuth provider.
type OAuthProvider struct {
	clientSecret string
	cfg          *oauth2.Config
	// identityFetcher resolves stable identity info from the provider token.
	// nil falls back to fetchOAuthIdentity. Replaceable in tests.
	identityFetcher func(providerName string, cfg *oauth2.Config, tok *oauth2.Token) (subject, email string, emailVerified bool, err error)
}

// OAuthProviders bundles the configured providers. A nil entry means that
// provider is not configured (client ID / secret env vars are missing).
type OAuthProviders struct {
	GitHub *OAuthProvider
	Google *OAuthProvider
}

// NewOAuthProviders builds provider configs from env var values.
// baseURL must be the public HTTPS root of the relay (e.g. https://api.cinchcli.com).
func NewOAuthProviders(baseURL, ghID, ghSecret, gID, gSecret string) *OAuthProviders {
	p := &OAuthProviders{}
	if ghID != "" && ghSecret != "" {
		p.GitHub = &OAuthProvider{
			clientSecret: ghSecret,
			cfg: &oauth2.Config{
				ClientID:     ghID,
				ClientSecret: ghSecret,
				Endpoint:     github.Endpoint,
				RedirectURL:  baseURL + "/auth/oauth/github/callback",
				Scopes:       []string{"user:email"},
			},
		}
	}
	if gID != "" && gSecret != "" {
		p.Google = &OAuthProvider{
			clientSecret: gSecret,
			cfg: &oauth2.Config{
				ClientID:     gID,
				ClientSecret: gSecret,
				Endpoint:     google.Endpoint,
				RedirectURL:  baseURL + "/auth/oauth/google/callback",
				Scopes:       []string{"openid", "email"},
			},
		}
	}
	return p
}

// providerFor returns the OAuthProvider for the given name ("github" or "google").
func (p *OAuthProviders) providerFor(name string) *OAuthProvider {
	switch name {
	case "github":
		return p.GitHub
	case "google":
		return p.Google
	default:
		return nil
	}
}

// signState returns HMAC-SHA256(userCode, clientSecret)[:16] so that the
// callback can verify the state was issued by this server.
func signState(userCode, clientSecret string) string {
	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(userCode))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

// encodeState encodes user_code and its HMAC into a single state string.
func encodeState(userCode, clientSecret string) string {
	return userCode + "." + signState(userCode, clientSecret)
}

// decodeState extracts and verifies the user_code from the state string.
func decodeState(state, clientSecret string) (string, error) {
	dot := strings.LastIndex(state, ".")
	if dot < 0 {
		return "", fmt.Errorf("invalid state format")
	}
	userCode := state[:dot]
	sig := state[dot+1:]
	if !hmac.Equal([]byte(sig), []byte(signState(userCode, clientSecret))) {
		return "", fmt.Errorf("state signature mismatch")
	}
	return userCode, nil
}

// GetProviders returns which OAuth providers are configured on this relay.
// GET /auth/providers — no auth required; safe to call before sign-in.
// Response: { "providers": ["github", "google"] }  (empty array if none configured)
func (h *Handler) GetProviders(w http.ResponseWriter, r *http.Request) {
	providers := []string{}
	if h.OAuth != nil {
		if h.OAuth.GitHub != nil {
			providers = append(providers, "github")
		}
		if h.OAuth.Google != nil {
			providers = append(providers, "google")
		}
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, map[string][]string{"providers": providers})
}

// OAuthStart redirects the browser to the OAuth provider for authorization.
// GET /auth/oauth/{provider}/start?device_code=<user_code>
func (h *Handler) OAuthStart(providerName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.OAuth == nil {
			http.Error(w, "OAuth not configured", http.StatusNotImplemented)
			return
		}
		prov := h.OAuth.providerFor(providerName)
		if prov == nil {
			http.Error(w, "OAuth provider not configured", http.StatusNotImplemented)
			return
		}

		userCode := r.URL.Query().Get("device_code")
		if userCode == "" {
			http.Error(w, "device_code is required", http.StatusBadRequest)
			return
		}

		state := encodeState(userCode, prov.clientSecret)
		url := prov.cfg.AuthCodeURL(state, oauth2.AccessTypeOnline)
		http.Redirect(w, r, url, http.StatusFound)
	}
}

// OAuthCallback exchanges the OAuth code for a user profile, upserts the user,
// and marks the device-code flow as complete.
// GET /auth/oauth/{provider}/callback?code=...&state=...
func (h *Handler) OAuthCallback(providerName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.OAuth == nil {
			http.Error(w, "OAuth not configured", http.StatusNotImplemented)
			return
		}
		prov := h.OAuth.providerFor(providerName)
		if prov == nil {
			http.Error(w, "OAuth provider not configured", http.StatusNotImplemented)
			return
		}

		// Verify state / extract user_code.
		userCode, err := decodeState(r.URL.Query().Get("state"), prov.clientSecret)
		if err != nil {
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Authorization code missing", http.StatusBadRequest)
			return
		}

		// Exchange code for access token.
		tok, err := prov.cfg.Exchange(context.Background(), code)
		if err != nil {
			slog.Error("oauth callback token exchange failed", "provider", providerName, "err", err)
			http.Error(w, "Token exchange failed", http.StatusBadGateway)
			return
		}

		// Fetch the user's stable subject ID + email from the provider.
		fetcher := prov.identityFetcher
		if fetcher == nil {
			fetcher = fetchOAuthIdentity
		}
		subject, email, emailVerified, err := fetcher(providerName, prov.cfg, tok)
		if err != nil {
			slog.Error("oauth callback profile fetch failed", "provider", providerName, "err", err)
			http.Error(w, "Failed to fetch profile", http.StatusBadGateway)
			return
		}

		// Resolve the device hostname + machine_id from the device_codes table
		// (best-effort). machine_id deduplicates same-Mac CLI/desktop sign-ins
		// onto a single device row.
		hostname, machineID, _ := h.store.DeviceCodeContext(userCode)

		// Upsert user + device.
		userID, deviceID, deviceToken, err := h.store.UpsertOAuthUser(providerName, subject, email, emailVerified, hostname, machineID)
		if err != nil {
			slog.Error("oauth callback upsert failed", "err", err)
			http.Error(w, "Account provisioning failed", http.StatusInternalServerError)
			return
		}

		// If userCode is empty, the request came from the desktop app (no device-code
		// flow). Redirect to cinch://auth/callback so the Tauri deep-link handler
		// can complete authentication without polling.
		if userCode == "" {
			baseURL := h.BaseURL
			if baseURL == "" {
				baseURL = deriveRelayURL(r)
			}
			callbackURL := fmt.Sprintf("cinch://auth/callback?token=%s&device_id=%s&user_id=%s&relay_url=%s",
				url.QueryEscape(deviceToken),
				url.QueryEscape(deviceID),
				url.QueryEscape(userID),
				url.QueryEscape(baseURL),
			)
			http.Redirect(w, r, callbackURL, http.StatusFound)
			return
		}

		// Mark the device-code flow complete so the CLI poll picks it up.
		if err := h.store.CompleteDeviceCode(userCode, userID, deviceID, deviceToken); err != nil {
			slog.Error("oauth callback CompleteDeviceCode failed", "err", err)
			// Don't error out — credentials were created; user can re-auth if needed.
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, oauthSuccessHTML, providerName)
	}
}

// fetchOAuthIdentity calls the provider's userinfo/email endpoints and returns
// the stable subject identifier, the user's email, and whether the email is
// verified. Email is used as a cross-provider linking pivot when verified.
func fetchOAuthIdentity(providerName string, cfg *oauth2.Config, tok *oauth2.Token) (subject, email string, emailVerified bool, err error) {
	client := cfg.Client(context.Background(), tok)
	switch providerName {
	case "github":
		resp, err := client.Get("https://api.github.com/user")
		if err != nil {
			return "", "", false, err
		}
		defer resp.Body.Close()
		var profile struct {
			ID int64 `json:"id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
			return "", "", false, err
		}
		if profile.ID == 0 {
			return "", "", false, fmt.Errorf("github user ID is zero")
		}
		subject = fmt.Sprintf("%d", profile.ID)

		// Fetch verified primary email (requires user:email scope).
		emailResp, err := client.Get("https://api.github.com/user/emails")
		if err == nil {
			defer emailResp.Body.Close()
			var emails []struct {
				Email    string `json:"email"`
				Primary  bool   `json:"primary"`
				Verified bool   `json:"verified"`
			}
			if json.NewDecoder(emailResp.Body).Decode(&emails) == nil {
				for _, e := range emails {
					if e.Primary && e.Verified {
						email = e.Email
						emailVerified = true
						break
					}
				}
			}
		}
		return subject, email, emailVerified, nil

	case "google":
		resp, err := client.Get("https://openidconnect.googleapis.com/v1/userinfo")
		if err != nil {
			return "", "", false, err
		}
		defer resp.Body.Close()
		var profile struct {
			Sub           string `json:"sub"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
			return "", "", false, err
		}
		if profile.Sub == "" {
			return "", "", false, fmt.Errorf("google sub is empty")
		}
		return profile.Sub, profile.Email, profile.EmailVerified, nil

	default:
		return "", "", false, fmt.Errorf("unknown provider: %s", providerName)
	}
}

const oauthSuccessHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Signed in — Cinch</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#07080a;color:#F0EBE0;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#0f1114;border:1px solid #1a1d23;border-radius:12px;padding:2.5rem;text-align:center;max-width:380px}
h1{font-size:1.1rem;font-weight:600;margin-bottom:.5rem}
p{color:#8a8a8a;font-size:.875rem}
.check{font-size:2rem;margin-bottom:1rem;color:#4FB3A9}
</style>
</head>
<body>
<div class="card">
  <div class="check">✓</div>
  <h1>Signed in via %s</h1>
  <p>You can close this window. Your terminal should show "Signed in." within a few seconds.</p>
</div>
</body>
</html>`
