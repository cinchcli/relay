package relay

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

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
	identityFetcher func(ctx context.Context, providerName string, cfg *oauth2.Config, tok *oauth2.Token) (subject, email, displayName string, emailVerified bool, err error)
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
				// Two scopes, two endpoints: read:user lets /user return the
				// profile "name" field (we fall back to "login" when it is
				// unset), and user:email lets /user/emails return the verified
				// primary email. Neither alone is sufficient for both.
				Scopes: []string{"read:user", "user:email"},
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
				// "profile" is required for the userinfo endpoint to return the
				// "name" field; "openid email" alone yields only sub + email.
				Scopes: []string{"openid", "email", "profile"},
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

// oauthStateCookie holds the per-flow nonce that binds the browser which
// started the OAuth flow (OAuthStart) to the one that completes it (callback).
const oauthStateCookie = "cinch_oauth_state"

// signState returns the full HMAC-SHA256 of payload keyed by clientSecret, hex
// encoded (256-bit). The previous 64-bit truncation was below the recommended
// minimum; the clientSecret key means only this server can mint a valid state.
func signState(payload, clientSecret string) string {
	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// newOAuthNonce returns a random 128-bit hex nonce for state/cookie binding.
func newOAuthNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// encodeState packs the device user_code and a per-flow random nonce into a
// signed state: "<userCode>.<nonce>.<hmac>". OAuthStart also sets the nonce as
// an HttpOnly cookie and the callback re-checks it, so a state cannot be
// replayed from a different browser session.
func encodeState(userCode, nonce, clientSecret string) string {
	payload := userCode + "." + nonce
	return payload + "." + signState(payload, clientSecret)
}

// decodeState verifies the state HMAC and returns the embedded user_code and
// nonce. Neither value contains ".", so a valid state splits into exactly three
// parts.
func decodeState(state, clientSecret string) (userCode, nonce string, err error) {
	parts := strings.Split(state, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid state format")
	}
	userCode, nonce = parts[0], parts[1]
	payload := userCode + "." + nonce
	if !hmac.Equal([]byte(parts[2]), []byte(signState(payload, clientSecret))) {
		return "", "", fmt.Errorf("state signature mismatch")
	}
	return userCode, nonce, nil
}

// ── Pending OAuth confirmations (device-code phishing defense) ───────────────
//
// For the CLI device-code flow the callback no longer completes the device-code
// immediately. It stashes the freshly-minted credentials under a single-use
// ticket and renders a page asking the user to confirm the user_code matches
// the one their terminal printed (RFC 8628). Only the confirm POST completes
// the flow, so an attacker who phishes a victim into authenticating cannot graft
// the victim's identity onto the attacker's device-code without the victim
// knowingly confirming an unfamiliar code.

type pendingOAuthConfirm struct {
	userCode    string
	userID      string
	deviceID    string
	deviceToken string
	provider    string
	expiresAt   time.Time
}

const oauthConfirmTTL = 5 * time.Minute

var (
	pendingConfirmsMu sync.Mutex
	pendingConfirms   = map[string]pendingOAuthConfirm{}
)

func storePendingOAuthConfirm(c pendingOAuthConfirm) string {
	ticket := newOAuthNonce() + newOAuthNonce() // 256-bit, unguessable
	pendingConfirmsMu.Lock()
	pendingConfirms[ticket] = c
	pendingConfirmsMu.Unlock()
	return ticket
}

func consumePendingOAuthConfirm(ticket string) (pendingOAuthConfirm, bool) {
	pendingConfirmsMu.Lock()
	defer pendingConfirmsMu.Unlock()
	c, ok := pendingConfirms[ticket]
	if !ok {
		return pendingOAuthConfirm{}, false
	}
	delete(pendingConfirms, ticket)
	if time.Now().After(c.expiresAt) {
		return pendingOAuthConfirm{}, false
	}
	return c, true
}

// reapExpiredOAuthConfirms drops timed-out confirmations so abandoned flows do
// not leak memory. Driven by StartWSTicketReaper.
func reapExpiredOAuthConfirms(now time.Time) {
	pendingConfirmsMu.Lock()
	defer pendingConfirmsMu.Unlock()
	for k, c := range pendingConfirms {
		if now.After(c.expiresAt) {
			delete(pendingConfirms, k)
		}
	}
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

		// Bind this flow to the initiating browser: a fresh nonce goes into both
		// the signed state and an HttpOnly cookie that the callback re-checks.
		nonce := newOAuthNonce()
		http.SetCookie(w, &http.Cookie{
			Name:     oauthStateCookie,
			Value:    nonce,
			Path:     "/auth/oauth",
			HttpOnly: true,
			Secure:   requestIsHTTPS(r),
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(oauthConfirmTTL / time.Second),
		})
		state := encodeState(userCode, nonce, prov.clientSecret)
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

		// Verify state / extract user_code + nonce.
		userCode, nonce, err := decodeState(r.URL.Query().Get("state"), prov.clientSecret)
		if err != nil {
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
			return
		}

		// CLI device-code flow: require the browser that started the flow. The
		// nonce cookie set by OAuthStart must match the state nonce (login-CSRF).
		// The desktop deep-link flow (userCode == "") does not go through
		// OAuthStart and is exempt.
		if userCode != "" {
			c, cerr := r.Cookie(oauthStateCookie)
			if cerr != nil || c.Value == "" || !hmac.Equal([]byte(c.Value), []byte(nonce)) {
				http.Error(w, "Invalid state parameter", http.StatusBadRequest)
				return
			}
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
		subject, email, displayName, emailVerified, err := fetcher(r.Context(), providerName, prov.cfg, tok)
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
		userID, deviceID, deviceToken, err := h.store.UpsertOAuthUser(providerName, subject, email, emailVerified, displayName, hostname, machineID)
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

		// CLI device-code flow: do NOT complete the device-code yet. Stash the
		// credentials under a single-use ticket and render a page asking the user
		// to confirm the user_code matches what their terminal printed (RFC 8628).
		// Only the confirm POST (OAuthConfirm) completes the flow — this stops a
		// phisher who lures a victim through OAuth from grafting the victim's
		// identity onto the attacker's device-code without the victim knowingly
		// approving an unfamiliar code.
		ticket := storePendingOAuthConfirm(pendingOAuthConfirm{
			userCode:    userCode,
			userID:      userID,
			deviceID:    deviceID,
			deviceToken: deviceToken,
			provider:    providerName,
			expiresAt:   time.Now().Add(oauthConfirmTTL),
		})

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := oauthConfirmTmpl.Execute(w, oauthConfirmData{
			UserCode: userCode,
			Provider: providerName,
			Ticket:   ticket,
		}); err != nil {
			slog.Error("oauth confirm page render failed", "err", err)
		}
	}
}

// OAuthConfirm completes a CLI device-code flow after the user has visually
// confirmed the user_code on the confirmation page. POST /auth/oauth/confirm
// with form field "ticket". The ticket is the single-use, unguessable handle
// minted by OAuthCallback; consuming it both authorizes the completion and
// serves as the CSRF token (an attacker cannot know it).
func (h *Handler) OAuthConfirm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	ticket := r.PostForm.Get("ticket")
	if ticket == "" {
		http.Error(w, "Missing confirmation ticket", http.StatusBadRequest)
		return
	}
	pending, ok := consumePendingOAuthConfirm(ticket)
	if !ok {
		http.Error(w, "Confirmation expired or already used", http.StatusBadRequest)
		return
	}

	// Mark the device-code flow complete so the CLI poll picks it up.
	if err := h.store.CompleteDeviceCode(pending.userCode, pending.userID, pending.deviceID, pending.deviceToken); err != nil {
		slog.Error("oauth confirm CompleteDeviceCode failed", "err", err)
		// Don't error out — credentials were created; user can re-auth if needed.
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, oauthSuccessHTML, pending.provider)
}

// fetchOAuthIdentity calls the provider's userinfo/email endpoints and returns
// the stable subject identifier, the user's email, the provider-supplied display
// name, and whether the email is verified. Email is used as a cross-provider
// linking pivot when verified.
//
// ctx may carry a custom http.Client (via oauth2.WithClient) to redirect provider
// API calls in tests.
func fetchOAuthIdentity(ctx context.Context, providerName string, cfg *oauth2.Config, tok *oauth2.Token) (subject, email, displayName string, emailVerified bool, err error) {
	client := cfg.Client(ctx, tok)
	switch providerName {
	case "github":
		resp, err := client.Get("https://api.github.com/user")
		if err != nil {
			return "", "", "", false, err
		}
		defer resp.Body.Close()
		var profile struct {
			ID    int64  `json:"id"`
			Login string `json:"login"`
			Name  string `json:"name"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
			return "", "", "", false, err
		}
		if profile.ID == 0 {
			return "", "", "", false, fmt.Errorf("github user ID is zero")
		}
		subject = fmt.Sprintf("%d", profile.ID)

		// Resolve display name: prefer trimmed Name, fall back to Login as-is.
		if strings.TrimSpace(profile.Name) != "" {
			displayName = strings.TrimSpace(profile.Name)
		} else {
			displayName = profile.Login
		}

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
		return subject, email, displayName, emailVerified, nil

	case "google":
		resp, err := client.Get("https://openidconnect.googleapis.com/v1/userinfo")
		if err != nil {
			return "", "", "", false, err
		}
		defer resp.Body.Close()
		var profile struct {
			Sub           string `json:"sub"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			Name          string `json:"name"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
			return "", "", "", false, err
		}
		if profile.Sub == "" {
			return "", "", "", false, fmt.Errorf("google sub is empty")
		}
		return profile.Sub, profile.Email, strings.TrimSpace(profile.Name), profile.EmailVerified, nil

	default:
		return "", "", "", false, fmt.Errorf("unknown provider: %s", providerName)
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

// oauthConfirmData feeds the confirmation page. html/template escapes every
// field, so the user_code and ticket are safe to interpolate.
type oauthConfirmData struct {
	UserCode string
	Provider string
	Ticket   string
}

// oauthConfirmTmpl is the RFC 8628 user_code confirmation page. The user must
// check that the displayed code matches the one their terminal printed before
// pressing Confirm; only then does the device-code flow complete. This is the
// human-in-the-loop defense against device-code phishing.
var oauthConfirmTmpl = template.Must(template.New("oauth-confirm").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Confirm sign-in — Cinch</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#07080a;color:#F0EBE0;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:1rem}
.card{background:#0f1114;border:1px solid #1a1d23;border-radius:12px;padding:2.5rem;text-align:center;max-width:420px}
h1{font-size:1.1rem;font-weight:600;margin-bottom:1rem}
p{color:#8a8a8a;font-size:.875rem;margin-bottom:1rem;line-height:1.5}
.code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:1.6rem;font-weight:700;letter-spacing:.15em;color:#F0EBE0;background:#07080a;border:1px solid #1a1d23;border-radius:8px;padding:.75rem 1rem;margin:1rem 0;display:inline-block}
.warn{color:#d98a4f;font-size:.8rem;margin-bottom:1.25rem}
button{background:#4FB3A9;color:#07080a;border:0;border-radius:8px;padding:.7rem 1.5rem;font-size:.95rem;font-weight:600;cursor:pointer}
button:hover{background:#5fc7bd}
</style>
</head>
<body>
<div class="card">
  <h1>Confirm sign-in via {{.Provider}}</h1>
  <p>Your terminal showed a code when you ran <code>cinch auth login</code>. Confirm it matches the one below:</p>
  <div class="code">{{.UserCode}}</div>
  <p class="warn">If this code does not match your terminal — or you didn't start a sign-in — close this window. Do not confirm.</p>
  <form method="POST" action="/auth/oauth/confirm">
    <input type="hidden" name="ticket" value="{{.Ticket}}">
    <button type="submit">Confirm sign-in</button>
  </form>
</div>
</body>
</html>`))
