// Package relay implements the cinch relay server: HTTP handlers, WebSocket
// hub, and Postgres-backed clip storage.
package relay

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	cinchv1 "github.com/cinchcli/relay/internal/cinchv1"
	"github.com/cinchcli/relay/internal/internalauth"
	"github.com/cinchcli/relay/internal/media"
	"github.com/cinchcli/relay/internal/protocol"
	"github.com/gorilla/websocket"
	"github.com/oklog/ulid/v2"
)

// Demo constraints — keep in sync with landing page display.
const (
	demoMaxClips     = 5
	demoMaxBytes     = 1024
	demoTTL          = 10 * time.Minute
	demoAllowOrigin  = "https://cinchcli.com"
	demoAllowOriginL = "http://localhost:4321" // astro dev server
)

// loginRateWindow is the minimum interval between anonymous account creations
// from the same IP. One new account per minute is generous for legitimate use
// (smoke tests, demos) while blocking trivial DB-bloat attacks.
const loginRateWindow = 1 * time.Minute

// wsAllowedOrigin returns true for origins permitted to open a WebSocket.
// Empty Origin is allowed: native clients (cinch CLI, desktop's Rust ws.rs,
// curl) do not set this header, while browsers always do for cross-origin
// requests. WS auth is bearer ticket/token via URL params, so the cookie-CSRF
// concern that motivates strict origin checks on cookie-auth WS does not
// directly apply here — but locking the allowlist is cheap defense-in-depth.
func (h *Handler) wsAllowedOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	if origin == demoAllowOrigin || origin == demoAllowOriginL {
		return true
	}
	// Tauri v2 webview origins: tauri://localhost on macOS/Linux,
	// http://tauri.localhost on Windows. The desktop's WS client is in
	// Rust (not the webview), so this matters only for hypothetical
	// browser-side use — but we permit them for consistency with HTTP.
	if origin == "tauri://localhost" || origin == "http://tauri.localhost" {
		return true
	}
	for _, o := range h.CORSOrigins {
		if o == origin {
			return true
		}
	}
	return false
}

func (h *Handler) wsUpgrader() websocket.Upgrader {
	return websocket.Upgrader{CheckOrigin: h.wsAllowedOrigin}
}

// shouldLogWSClose reports whether the read-loop error from a WebSocket
// connection deserves an Info-level log line. Routine disconnects —
// normal closure, going-away, and abnormal closure (1006: proxy idle
// timeouts, NAT resets, client process death) — are silenced; other
// close codes (e.g. 1002 protocol error, 1011 internal server error)
// are logged so server bugs aren't lost.
func shouldLogWSClose(err error) bool {
	return websocket.IsUnexpectedCloseError(err,
		websocket.CloseGoingAway,
		websocket.CloseNormalClosure,
		websocket.CloseAbnormalClosure,
	)
}

// wsTicket holds the identity bound to a short-lived WebSocket auth ticket.
type wsTicket struct {
	userID    string
	deviceID  string
	expiresAt time.Time
}

var (
	wsTicketsMu sync.Mutex
	wsTickets   = map[string]wsTicket{}
)

// issueWsTicket mints a 30-second single-use ticket for WebSocket auth.
// The ticket is a 16-byte random value encoded as a 32-char hex string.
func issueWsTicket(userID, deviceID string) string {
	ticket := randomHex(16)
	wsTicketsMu.Lock()
	wsTickets[ticket] = wsTicket{
		userID:    userID,
		deviceID:  deviceID,
		expiresAt: time.Now().Add(30 * time.Second),
	}
	wsTicketsMu.Unlock()
	return ticket
}

// consumeWsTicket validates and atomically removes a ticket.
// Returns the bound identifiers and ok=true on success; ok=false on any failure
// (unknown ticket, already used, or expired).
func consumeWsTicket(ticket string) (userID, deviceID string, ok bool) {
	wsTicketsMu.Lock()
	defer wsTicketsMu.Unlock()
	t, exists := wsTickets[ticket]
	if !exists || time.Now().After(t.expiresAt) {
		delete(wsTickets, ticket)
		return "", "", false
	}
	delete(wsTickets, ticket) // single-use: remove immediately
	return t.userID, t.deviceID, true
}

// reapExpiredWsTickets deletes all tickets whose deadline has passed.
// Tickets are normally removed on consumption, but a ticket that is issued
// and never consumed (network failure, abuse) would otherwise leak forever —
// this sweep bounds wsTickets to roughly one reap interval of unconsumed
// tickets.
func reapExpiredWsTickets(now time.Time) {
	wsTicketsMu.Lock()
	defer wsTicketsMu.Unlock()
	for ticket, t := range wsTickets {
		if now.After(t.expiresAt) {
			delete(wsTickets, ticket)
		}
	}
}

// StartWSTicketReaper runs a background sweep that evicts expired WebSocket
// auth tickets every minute until ctx is cancelled. Mirrors hub.Run()'s
// ticker pattern. Call once at server init.
func StartWSTicketReaper(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				reapExpiredWsTickets(now)
				reapExpiredOAuthConfirms(now)
			}
		}
	}()
}

// StartRateLimitReaper periodically evicts fully-expired keys from the
// in-process rate limiters. The limiters otherwise only prune a key's slice
// when that exact key is seen again, so attacker-chosen keys on the
// unauthenticated routes (telemetry by CF-Connecting-IP, device-code by
// X-Forwarded-For) would accumulate permanent map entries. Mirrors
// StartWSTicketReaper.
func (h *Handler) StartRateLimitReaper(ctx context.Context) {
	limiters := []*slidingWindowLimiter{
		h.telemetryLimiter, h.loginLimiter, h.pendingLimit, h.deviceCodeIPLimit,
	}
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				for _, l := range limiters {
					if l != nil {
						l.reap(now)
					}
				}
			}
		}
	}()
}

type Handler struct {
	store       *Store
	hub         *Hub
	media       media.Store     // nil means binary upload disabled
	BaseURL     string          // public base URL of the relay (for verification URIs)
	OAuth       *OAuthProviders // nil = OAuth not configured; self-host falls back to username form
	CORSOrigins []string        // extra allowed origins beyond the hardcoded landing page defaults

	// ConnectReadMaxBytes caps the decoded size of any single Connect-RPC
	// request message. 0 (the zero value) means "use defaultConnectReadMaxBytes"
	// — never unlimited. connect-go's own default is 0 = unlimited, so this must
	// be wired explicitly on every service handler (see connectReadMax).
	ConnectReadMaxBytes int

	// WSReadLimitBytes caps a single inbound WebSocket frame; WSReadDeadline
	// bounds how long a connection may stay silent before it is reaped. 0 means
	// "use the default" (see wsReadLimit / wsReadDeadlineDur). Agents only ever
	// send tiny pong frames, so the read limit is small.
	WSReadLimitBytes int64
	WSReadDeadline   time.Duration

	TelemetryURL    string // e.g. https://telemetry.jinmu.me
	TelemetryAPIKey string // X-API-Key sent to telemetry backend

	// Observability product-event emission (see metrics.go). URL + token + salt
	// must all be set or every emit is a no-op; MetricsDisabled is a kill switch.
	// activeUsers dedups DAU to one event per anon_id per UTC day; clipEvents dedups
	// clip_send/clip_read to one per clip (send) or per (clip, reader device) (read)
	// per UTC day, backing the loop-completion metric.
	MetricsIngestURL   string
	MetricsIngestToken string
	MetricsAnonSalt    string
	MetricsDisabled    bool
	activeUsers        *dailySeenSet
	clipEvents         *dailySeenSet

	// Version is the relay build version (main.version), used in the telemetry
	// User-Agent so the ingest edge can identify the client.
	Version string

	// All rate limiting uses the one slidingWindowLimiter type (ratelimit.go).
	// telemetryLimiter: 5 events/IP/hour. loginLimiter: 1 anonymous account
	// creation per IP per loginRateWindow.
	telemetryLimiter *slidingWindowLimiter
	loginLimiter     *slidingWindowLimiter

	internalServiceSecret string // protects POST /internal/quota; empty = endpoint disabled
	// internalQuotaWriteSecret authorizes POST /internal/quota; internalReadSecret
	// authorizes GET /internal/users. Either falls back to internalServiceSecret.
	// Each may be comma-separated for zero-downtime rotation.
	internalQuotaWriteSecret string
	internalReadSecret       string

	// DeviceCodeStart rate limits.
	// pendingLimit caps notification spam per pending user (5/min) — when
	// exceeded, the WS broadcast is dropped but the RPC still succeeds so
	// the response does not leak whether the hint matched a user.
	// deviceCodeIPLimit caps abuse per requester IP (30/min) — when exceeded,
	// the RPC returns CodeResourceExhausted (HTTP 429).
	pendingLimit      *slidingWindowLimiter
	deviceCodeIPLimit *slidingWindowLimiter
}

func NewHandler(store *Store, hub *Hub) *Handler {
	return &Handler{
		store:             store,
		hub:               hub,
		telemetryLimiter:  newSlidingWindowLimiter(5, time.Hour),
		loginLimiter:      newSlidingWindowLimiter(1, loginRateWindow),
		pendingLimit:      newSlidingWindowLimiter(5, time.Minute),
		deviceCodeIPLimit: newSlidingWindowLimiter(30, time.Minute),
		activeUsers:       newDailySeenSet(),
		clipEvents:        newDailySeenSet(),
	}
}

// SetMediaStore attaches a media backend to the handler.
func (h *Handler) SetMediaStore(s media.Store) { h.media = s }

// SetInternalServiceSecret configures the bearer secret for POST /internal/quota.
// When empty, the endpoint returns 503 (not silently open).
func (h *Handler) SetInternalServiceSecret(s string) { h.internalServiceSecret = s }

// SetInternalQuotaWriteSecret sets the write-scoped secret for POST /internal/quota.
func (h *Handler) SetInternalQuotaWriteSecret(s string) { h.internalQuotaWriteSecret = s }

// SetInternalReadSecret sets the read-scoped secret for GET /internal/users.
func (h *Handler) SetInternalReadSecret(s string) { h.internalReadSecret = s }

// RequireAdmin wraps RequireAuth and additionally checks that the
// authenticated user has is_admin = TRUE.
func (h *Handler) RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return h.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		isAdmin := r.Header.Get("X-Is-Admin") == "true"
		if !isAdmin {
			writeError(w, http.StatusForbidden, "admin_required",
				"This endpoint requires an admin account.", "")
			return
		}
		next(w, r)
	})
}

// identityHeaders are the trusted identity headers the server derives from a
// verified bearer token. They must never be honored from inbound requests — a
// client that sets X-User-ID/X-Is-Admin itself must not be able to impersonate
// another user or escalate to admin — so stripClientIdentityHeaders clears them
// before auth populates the authentic values.
var identityHeaders = []string{"X-User-ID", "X-Device-ID", "X-Is-Admin", "X-Is-Demo"}

// stripClientIdentityHeaders removes any client-supplied identity headers so
// only the server-set values (post token verification) are ever observed by
// downstream handlers.
func stripClientIdentityHeaders(h http.Header) {
	for _, k := range identityHeaders {
		h.Del(k)
	}
}

// RequireAuth wraps a handler with token authentication.
// After the OAuth-only migration every active token lives on devices.token;
// the legacy master-token (users.token) lookup has been removed.
func (h *Handler) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Defense in depth: never trust inbound identity headers; the server
		// sets them below only after verifying the bearer token.
		stripClientIdentityHeaders(r.Header)

		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			writeError(w, http.StatusUnauthorized, "not authenticated", "No auth token provided", "Run: cinch auth login")
			return
		}

		ctx, err := h.store.GetAuthContext(token)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeError(w, http.StatusUnauthorized, "invalid token", "Token is invalid or expired", "Run: cinch auth login")
				return
			}
			if errors.Is(err, ErrDeviceRevoked) {
				writeError(w, http.StatusUnauthorized, "device_revoked", "This device was revoked", "Run: cinch auth login")
				return
			}
			if errors.Is(err, ErrDemoExpired) {
				writeError(w, http.StatusUnauthorized, "demo expired", "Demo session expired", "Refresh the page for a new session")
				return
			}
			slog.Error("GetAuthContext error", "err", err)
			writeError(w, http.StatusUnauthorized, "invalid token", "Token is invalid or expired", "Run: cinch auth login")
			return
		}

		r.Header.Set("X-Device-ID", ctx.DeviceID)
		r.Header.Set("X-User-ID", ctx.UserID)
		if ctx.IsAdmin {
			r.Header.Set("X-Is-Admin", "true")
		}
		if ctx.IsDemo {
			r.Header.Set("X-Is-Demo", "true")
		}
		// Product event for DAU (fire-and-forget, daily-deduped, demo-excluded).
		h.emitUserActive(ctx.UserID, ctx.IsDemo)
		next(w, r)
	}
}

// AuthLogin creates an anonymous user account + first device row and
// returns the device token. After the OAuth-only migration the user
// table no longer carries a master token, so login auth is identical
// to a freshly OAuth'd device.
//
// Used by the smoke test and the demo HTML page; production clients
// always go through device-code OAuth.
func (h *Handler) AuthLogin(w http.ResponseWriter, r *http.Request) {
	// Reject direct account creation when OAuth is configured. All accounts on
	// an OAuth-enabled relay must be created through the OAuth flow to preserve
	// the identity audit trail (security finding 3).
	if h.OAuth != nil && (h.OAuth.GitHub != nil || h.OAuth.Google != nil) {
		writeError(w, http.StatusForbidden, "oauth_required",
			"Direct login is disabled. Use OAuth to authenticate.", "")
		return
	}

	ip := clientIP(r.RemoteAddr, r.Header)
	if h.checkLoginRateLimit(ip) {
		writeError(w, http.StatusTooManyRequests, "rate_limited",
			"Too many login attempts. Try again in a minute.", "")
		return
	}

	var req cinchv1.LoginRequest
	if r.Body != nil && r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	// Invite gate: required when OAuth is off.
	if req.InviteCode == nil || *req.InviteCode == "" {
		writeError(w, http.StatusForbidden, "invite_required",
			"An invite code is required to create an account on this relay.",
			"Ask the operator for an invite code.")
		return
	}
	hash := HashInviteCode(*req.InviteCode)
	if err := h.store.RedeemInvite(hash); err != nil {
		writeError(w, http.StatusForbidden, "invite_invalid",
			"Invite code is invalid, expired, revoked, or used up.", "")
		return
	}

	hostname := "unknown"
	if req.Hostname != nil && *req.Hostname != "" {
		hostname = *req.Hostname
	}

	userID := ulid.Make().String()
	if err := h.store.CreateUser(userID); err != nil {
		writeInternalError(w, "account creation failed", "create account", err)
		return
	}
	if req.DisplayName != nil && *req.DisplayName != "" {
		if err := h.store.SetUserDisplayName(userID, *req.DisplayName); err != nil {
			slog.Error("set display name failed", "user", userID, "err", err)
		}
	}

	// First user on the relay becomes admin automatically. CountUsers is
	// called after the insert, so the freshly-created user is included.
	if n, err := h.store.CountUsers(); err == nil && n == 1 {
		if err := h.store.SetUserAdmin(userID, true); err != nil {
			slog.Error("promote first user to admin failed", "user", userID, "err", err)
		}
	}

	deviceID := ulid.Make().String()
	deviceToken := generateToken()
	if err := h.store.RegisterDeviceWithToken(userID, deviceID, hostname, deviceToken); err != nil {
		writeInternalError(w, "device creation failed", "create device", err)
		return
	}

	writeJSON(w, http.StatusOK, cinchv1.LoginResponse{
		Token:    deviceToken,
		UserId:   userID,
		DeviceId: deviceID,
		// PairToken intentionally absent — field reserved in proto.
	})
}

// KeyBundleRequest is the body for POST /auth/key-bundle.
type KeyBundleRequest struct {
	DeviceID           string `json:"device_id"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	EncryptedBundle    string `json:"encrypted_bundle"`
}

// KeyBundleResponse is returned by GET /auth/key-bundle.
type KeyBundleResponse struct {
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	EncryptedBundle    string `json:"encrypted_bundle"`
	// RFC3339 timestamp of when this device first registered its public
	// key without yet receiving a bundle. Empty when the bundle is
	// already present.
	PendingSince string `json:"pending_since,omitempty"`
}

// PostKeyBundle stores an ECDH key bundle for a target device.
// The caller must own the same account as the target device.
// The bundle is AES-GCM ciphertext of the user_key — relay stores ciphertext only.
func (h *Handler) PostKeyBundle(w http.ResponseWriter, r *http.Request) {
	var req KeyBundleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request", "Could not parse request body", "")
		return
	}
	if req.DeviceID == "" || req.EphemeralPublicKey == "" || req.EncryptedBundle == "" {
		writeError(w, http.StatusBadRequest, "missing fields", "device_id, ephemeral_public_key, encrypted_bundle are required", "")
		return
	}
	// Verify caller owns a device on the same account as the target device.
	callerUserID := r.Header.Get("X-User-ID")
	targetOwner, err := h.store.DeviceOwner(req.DeviceID)
	if err != nil {
		writeError(w, http.StatusNotFound, "device not found", "Target device does not exist", "")
		return
	}
	if callerUserID != targetOwner {
		writeError(w, http.StatusForbidden, "forbidden", "Cannot set key bundle for another user's device", "")
		return
	}
	if err := h.store.SaveKeyBundle(req.DeviceID, req.EphemeralPublicKey, req.EncryptedBundle); err != nil {
		writeError(w, http.StatusInternalServerError, "store error", "Failed to save key bundle", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// GetKeyBundle retrieves the ECDH key bundle for the caller's own device.
// Always returns 200; an absent bundle is signalled by empty ephemeral
// and bundle fields plus a non-empty pending_since timestamp so the
// caller can distinguish "no key yet" from "device unknown" without a
// 404 round trip.
func (h *Handler) GetKeyBundle(w http.ResponseWriter, r *http.Request) {
	deviceID := r.Header.Get("X-Device-ID")
	if deviceID == "" {
		writeError(w, http.StatusBadRequest, "missing device", "X-Device-ID not set", "")
		return
	}
	eph, bundle, err := h.store.GetKeyBundle(deviceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store error", "Failed to read key bundle", "")
		return
	}
	pendingSince := ""
	if eph == "" || bundle == "" {
		ts, _ := h.store.GetKeyBundlePendingSince(deviceID)
		if !ts.IsZero() {
			pendingSince = ts.UTC().Format(time.RFC3339)
		}
	}
	writeJSON(w, http.StatusOK, KeyBundleResponse{
		EphemeralPublicKey: eph,
		EncryptedBundle:    bundle,
		PendingSince:       pendingSince,
	})
}

// RegisterPublicKeyRequest is the body for POST /auth/device/public-key.
type RegisterPublicKeyRequest struct {
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
}

// RegisterDevicePublicKey accepts the X25519 public key for the calling
// device. The relay needs this to (a) include the device in
// ListPendingKeyExchanges sweeps and (b) broadcast key_exchange_requested
// so a bearer responds immediately (no waiting for the next sweep).
// Bearer-authenticated; the device_id is taken from the auth header.
func (h *Handler) RegisterDevicePublicKey(w http.ResponseWriter, r *http.Request) {
	deviceID := r.Header.Get("X-Device-ID")
	userID := r.Header.Get("X-User-ID")
	if deviceID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing device", "")
		return
	}
	var req RegisterPublicKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request", "Could not parse body", "")
		return
	}
	if req.PublicKey == "" || req.Fingerprint == "" {
		writeError(w, http.StatusBadRequest, "missing fields", "public_key and fingerprint are required", "")
		return
	}
	if err := h.store.SetDevicePublicKey(deviceID, req.PublicKey, req.Fingerprint); err != nil {
		if err == sql.ErrNoRows {
			writeError(w, http.StatusNotFound, "device not found", "", "")
			return
		}
		writeInternalError(w, "store error", "store op", err)
		return
	}
	// Best-effort broadcast: a bearer that holds the canonical key will see
	// this and respond with an encrypted bundle within milliseconds. Without
	// this, the device would block on the 30s poll waiting for the next
	// ListPendingKeyExchanges sweep.
	if userID != "" {
		hostname, _, hostErr := h.store.GetDeviceHostnameAndPubKey(deviceID)
		if hostErr == nil {
			h.hub.SendToUser(userID, &cinchv1.ServerEvent{
				Event: &cinchv1.ServerEvent_KeyExchange{
					KeyExchange: &cinchv1.KeyExchangeEvent{
						DeviceId: deviceID,
						Hostname: hostname,
					},
				},
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// KeyBundleRetry re-broadcasts key_exchange_requested for the calling
// device. Used by `cinch auth retry-key` when the initial key handoff
// missed (no key-bearer was online). Returns 400 if the device has not
// yet registered a public key (nothing to broadcast about).
func (h *Handler) KeyBundleRetry(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	deviceID := r.Header.Get("X-Device-ID")
	if userID == "" || deviceID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing user or device", "")
		return
	}
	hostname, pubKey, err := h.store.GetDeviceHostnameAndPubKey(deviceID)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "device not found", "", "")
		return
	}
	if err != nil {
		writeInternalError(w, "store error", "store op", err)
		return
	}
	if pubKey == "" {
		writeError(w, http.StatusBadRequest, "no public key registered", "device has not registered a public key yet", "Sign in via cinch auth login first")
		return
	}
	h.hub.SendToUser(userID, &cinchv1.ServerEvent{
		Event: &cinchv1.ServerEvent_KeyExchange{
			KeyExchange: &cinchv1.KeyExchangeEvent{
				DeviceId: deviceID,
				Hostname: hostname,
			},
		},
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// PushClip receives a clip from the CLI and broadcasts to the agent.
func (h *Handler) PushClip(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB cap on text clips
	var req cinchv1.PushClipRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request", "Could not parse request body", "")
		return
	}

	if req.Content == "" {
		writeError(w, http.StatusBadRequest, "empty content", "No content to push", "Pipe content: echo 'text' | cinch push")
		return
	}

	// media_path is server-owned: only PushBinaryClip / uploadImageMedia may set
	// it, always to a freshly generated server key. Strip any client-supplied
	// value so a clip can never be made to point at another tenant's media key
	// (GetClipMedia/DeleteClip trust the stored key against the shared store).
	req.MediaPath = nil

	// E2EE is mandatory for non-demo users. Demo identities are server-side
	// ephemeral with no client-side key exchange; demo data is intentionally
	// public, capped at 1024 bytes, and TTL'd.
	isDemoUser := r.Header.Get("X-Is-Demo") == "true"
	if !isDemoUser && !req.Encrypted {
		writeError(w, http.StatusUnprocessableEntity, "encryption_required",
			"Server requires end-to-end encrypted clips. Plaintext push was rejected.",
			"Run cinch auth login to (re)generate your encryption key.")
		return
	}

	// Rate limit and storage limit check — applies to all non-demo users.
	// Fail open on DB errors so a transient blip does not block all pushes.
	if !isDemoUser {
		cap, capErr := h.store.GetUserCapabilities(userID)
		if capErr == nil {
			if cap.RateLimit > 0 {
				count, cntErr := h.store.IncrementDailyRequestCount(userID)
				if cntErr == nil && count > cap.RateLimit {
					writeError(w, http.StatusTooManyRequests, "rate_limit_exceeded",
						fmt.Sprintf("Daily push limit of %d reached", cap.RateLimit),
						"Wait until midnight UTC to reset, self-host, or contact support if you need a private relay.")
					return
				}
			}
			if cap.MaxClipSizeKb > 0 {
				if int64(len(req.Content)) > int64(cap.MaxClipSizeKb)*1024 {
					writeError(w, http.StatusBadRequest, "clip_too_large",
						fmt.Sprintf("Maximum allowed size is %d KB", cap.MaxClipSizeKb), "")
					return
				}
			}
			if cap.StorageLimitMb > 0 {
				used, usedErr := h.store.GetUserStorageUsage(userID)
				if usedErr == nil && used+int64(len(req.Content)) > int64(cap.StorageLimitMb)*1024*1024 {
					writeError(w, http.StatusTooManyRequests, "storage_quota_exceeded",
						fmt.Sprintf("Total storage limit of %d MB reached", cap.StorageLimitMb),
						"Delete old clips, self-host the relay, or contact support if you need a private relay.")
					return
				}
			}
		}
	}

	// Demo sessions are restricted to prevent abuse: text-only, 1KB, 5 clips.
	// isDemoUser was resolved above for the E2EE gate; reuse it here.
	if isDemoUser {
		if req.ContentType != "" && req.ContentType != protocol.ContentText {
			writeError(w, http.StatusBadRequest, "demo text only", "Demo sessions accept text only", "Sign up for image support")
			return
		}
		if len(req.Content) > demoMaxBytes {
			writeError(w, http.StatusRequestEntityTooLarge, "demo too large", fmt.Sprintf("Demo clips are limited to %d bytes", demoMaxBytes), "")
			return
		}
		count, _ := h.store.DemoClipCount(userID)
		if count >= demoMaxClips {
			writeError(w, http.StatusTooManyRequests, "demo limit reached", fmt.Sprintf("Demo sessions allow up to %d pushes", demoMaxClips), "Refresh the page for a new session")
			return
		}
	}

	clip, isDup, err := h.store.SaveClip(userID, &req)
	if err != nil {
		writeInternalError(w, "save failed", "save clip", err)
		return
	}

	if isDemoUser {
		if err := h.store.IncrementDemoCounter(); err != nil {
			slog.Error("demo counter increment failed", "err", err)
		}
	}

	// Update device activity stats
	if req.Source != "" {
		if err := h.store.UpdateDeviceActivity(userID, req.Source); err != nil {
			slog.Error("device activity update failed", "err", err)
		}
	}

	if !isDup {
		delivered, sendErr := h.hub.SendClip(userID, clip)
		if sendErr != nil {
			slog.Error("ws broadcast failed", "user", userID, "err", sendErr)
		}
		// Loop completion: clip_send (denominator) + clip_read for every device the
		// hub delivered to over WS at push time (the push side of the loop).
		h.emitClipSendAndDeliveries(userID, r.Header.Get("X-Device-ID"), clip.ClipId, isDemoUser, delivered)
	}

	writeJSON(w, http.StatusOK, cinchv1.PushClipResponse{
		ClipId:   clip.ClipId,
		ByteSize: clip.ByteSize,
	})
}

// ListClips returns recent clips for the authenticated user.
// Accepts optional query params: ?since=<RFC3339>, ?limit=<int>, ?source=<string>,
// ?exclude_source=<string>, ?exclude_image=true, ?exclude_text=true, and repeated ?clip_id=<id>.
func (h *Handler) ListClips(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	q := r.URL.Query()

	limit := 50
	if limitStr := q.Get("limit"); limitStr != "" {
		n, err := strconv.Atoi(limitStr)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "invalid_limit", "invalid limit parameter", "")
			return
		}
		if n > 200 {
			n = 200
		}
		if n > 0 {
			limit = n
		}
	}

	sourceFilter := q.Get("source")
	excludeSource := q.Get("exclude_source")
	excludeImage := q.Get("exclude_image") == "true"
	excludeText := q.Get("exclude_text") == "true"
	clipIDs := q["clip_id"]

	// Backwards-compat: when only `since` is set, preserve oldest-first replay semantics.
	if sinceStr := q.Get("since"); sinceStr != "" &&
		sourceFilter == "" && excludeSource == "" &&
		!excludeImage && !excludeText && len(clipIDs) == 0 {
		sinceTime, err := time.Parse(time.RFC3339, sinceStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_since", "invalid since parameter", "")
			return
		}
		clips, err := h.store.ListClipsSince(userID, sinceTime, limit)
		if err != nil {
			writeInternalError(w, "list failed", "list", err)
			return
		}
		h.emitClipReads(userID, r.Header.Get("X-Device-ID"), r.Header.Get("X-Is-Demo") == "true", clips)
		writeJSON(w, http.StatusOK, clips)
		return
	}

	clips, err := h.store.ListClipsFiltered(userID, ListFilter{
		Limit:         limit,
		SourceFilter:  sourceFilter,
		ExcludeSource: excludeSource,
		ExcludeImage:  excludeImage,
		ExcludeText:   excludeText,
		ClipIDs:       clipIDs,
	})
	if err != nil {
		writeInternalError(w, "list failed", "list", err)
		return
	}
	h.emitClipReads(userID, r.Header.Get("X-Device-ID"), r.Header.Get("X-Is-Demo") == "true", clips)
	writeJSON(w, http.StatusOK, clips)
}

// DeleteClip removes a clip.
func (h *Handler) DeleteClip(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	clipID := r.PathValue("id")

	mediaPath, err := h.store.DeleteClipReturningMedia(userID, clipID)
	if err != nil {
		if errors.Is(err, ErrClipNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeInternalError(w, "delete_failed", "delete clip", err)
		return
	}

	if mediaPath != "" && h.media != nil {
		if err := h.media.Delete(r.Context(), mediaPath); err != nil {
			slog.Error("media delete failed", "media_path", mediaPath, "err", err)
		}
	}

	if err := h.store.InsertTombstone(userID, clipID); err != nil {
		slog.Error("InsertTombstone failed", "clip_id", clipID, "err", err)
	}

	h.hub.SendClipDeleted(userID, clipID)

	w.WriteHeader(http.StatusNoContent)
}

// ListTombstones returns tombstones (deleted clip IDs) for the authenticated user.
// Query params: since=<RFC3339> (optional, defaults to epoch), limit=<int> (optional, default 200, max 500).
func (h *Handler) ListTombstones(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")

	var since time.Time
	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		var err error
		since, err = time.Parse(time.RFC3339, sinceStr)
		if err != nil {
			http.Error(w, `{"error":"invalid_since","message":"since must be RFC3339"}`, http.StatusBadRequest)
			return
		}
	}
	// since zero value means "return all" — ListTombstones treats it as epoch.

	limit := 200
	if ls := r.URL.Query().Get("limit"); ls != "" {
		n, err := strconv.Atoi(ls)
		if err != nil || n < 1 {
			http.Error(w, `{"error":"invalid_limit"}`, http.StatusBadRequest)
			return
		}
		if n > 500 {
			n = 500
		}
		limit = n
	}

	tombstones, err := h.store.ListTombstones(userID, since, limit)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	if tombstones == nil {
		tombstones = []Tombstone{} // never return null
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tombstones)
}

// GetLatestClip returns the most recent clip for the authenticated user.
// Accepts at most one of `source` or `exclude_source`. With neither, returns
// the absolute latest clip across every device.
func (h *Handler) GetLatestClip(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	q := r.URL.Query()
	source := q.Get("source")
	excludeSource := q.Get("exclude_source")

	if source != "" && excludeSource != "" {
		writeError(w, http.StatusBadRequest, "invalid_arguments", "source and exclude_source are mutually exclusive", "")
		return
	}

	var (
		clip *cinchv1.Clip
		err  error
	)
	switch {
	case excludeSource != "":
		clip, err = h.store.GetLatestClipExcludingSource(userID, excludeSource)
	case source != "":
		clip, err = h.store.GetLatestClipBySource(userID, source)
	default:
		clip, err = h.store.GetLatestClipForUser(userID)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "not found", "no matching clip", "")
			return
		}
		writeError(w, http.StatusNotFound, "not found", err.Error(), "No clips from this source yet")
		return
	}
	// Loop-completion numerator: a device read a clip. The dashboard counts it as a
	// completed loop only when the reader's device_ref differs from the sender's.
	h.emitClipRead(userID, r.Header.Get("X-Device-ID"), clip.ClipId, r.Header.Get("X-Is-Demo") == "true")
	writeJSON(w, http.StatusOK, clip)
}

// SetClipPin sets or clears the pin state for a clip owned by the caller.
func (h *Handler) SetClipPin(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	clipID := r.PathValue("id")
	if clipID == "" {
		writeError(w, http.StatusBadRequest, "missing_id", "Clip ID required", "")
		return
	}

	var req struct {
		IsPinned bool    `json:"is_pinned"`
		PinNote  *string `json:"pin_note,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Could not parse request body", "")
		return
	}

	if err := h.store.SetClipPin(userID, clipID, req.IsPinned, req.PinNote); err != nil {
		if errors.Is(err, ErrClipNotFound) {
			writeError(w, http.StatusNotFound, "clip_not_found", "Clip not found", "")
			return
		}
		writeInternalError(w, "update_failed", "update", err)
		return
	}

	h.hub.SendClipPinned(userID, clipID, req.IsPinned, req.PinNote)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ListDevices returns paired devices with online status.
func (h *Handler) ListDevices(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	devices, err := h.store.ListDevices(userID)
	if err != nil {
		writeInternalError(w, "list failed", "list", err)
		return
	}

	// Enrich with online status from hub
	for _, d := range devices {
		d.Online = h.hub.IsDeviceOnline(userID, d.Id)
	}

	if devices == nil {
		devices = []*cinchv1.Device{}
	}
	writeJSON(w, http.StatusOK, devices)
}

// HandleWebSocket upgrades the connection and registers the agent.
// Authentication is per-device (devices.token); the legacy master-token
// fallback was removed alongside the OAuth-only schema migration.
//
// Preferred auth path: ?ticket=<ticket> — a short-lived single-use ticket
// obtained from POST /ws/ticket. The bearer token never appears in the URL.
// Legacy path: ?token=<token> — kept for legacy clients during the
// migration window.
const (
	// defaultWSReadLimitBytes bounds a single inbound WebSocket frame. Agents
	// only ever send small pong frames (HandleAgentMessage handles nothing
	// else), so this is deliberately tight.
	defaultWSReadLimitBytes int64 = 32 << 10 // 32 KiB
	// defaultWSReadDeadline is how long a connection may stay silent before the
	// read loop reaps it. It must exceed the hub's heartbeat interval (5m) so a
	// live-but-quiet client, which replies to each ping, is never killed.
	defaultWSReadDeadline = 11 * time.Minute
)

func (h *Handler) wsReadLimit() int64 {
	if h.WSReadLimitBytes > 0 {
		return h.WSReadLimitBytes
	}
	return defaultWSReadLimitBytes
}

func (h *Handler) wsReadDeadlineDur() time.Duration {
	if h.WSReadDeadline > 0 {
		return h.WSReadDeadline
	}
	return defaultWSReadDeadline
}

func (h *Handler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Ticket path: short-lived, single-use — bearer token not exposed in URL.
	if ticket := r.URL.Query().Get("ticket"); ticket != "" {
		userID, deviceID, ok := consumeWsTicket(ticket)
		if !ok {
			http.Error(w, "invalid or expired ticket", http.StatusUnauthorized)
			return
		}
		ug := h.wsUpgrader()
		conn, err := ug.Upgrade(w, r, nil)
		if err != nil {
			slog.Info("ws upgrade failed", "err", err)
			return
		}
		ac := h.hub.Register(userID, deviceID, conn)
		h.replayPendingAndStartReadLoop(ac)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}

	// Per-device token only. The legacy master-token (users.token) lookup
	// and lazy-migration branch were removed in the OAuth-only migration.
	deviceID, revoked, derr := h.store.DeviceIDByToken(token)
	if derr != nil {
		if derr == sql.ErrNoRows {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		slog.Error("DeviceIDByToken WS error", "err", derr)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if revoked {
		http.Error(w, "device_revoked", http.StatusUnauthorized)
		return
	}
	userID, err := h.store.DeviceOwner(deviceID)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	ug := h.wsUpgrader()
	conn, err := ug.Upgrade(w, r, nil)
	if err != nil {
		slog.Info("ws upgrade failed", "err", err)
		return
	}

	ac := h.hub.Register(userID, deviceID, conn)
	h.replayPendingAndStartReadLoop(ac)
}

// replayPendingAndStartReadLoop replays state a freshly-connected agent may
// have missed while offline — pending key exchanges and pending device-code
// approval prompts — then starts the read loop that feeds agent messages into
// the hub. Shared by both the ticket and legacy-token WS upgrade paths.
func (h *Handler) replayPendingAndStartReadLoop(ac *AgentConn) {
	userID, conn := ac.UserID, ac.Conn

	// Notify desktop of any pending key exchanges for this user. Handles the
	// offline-desktop case: desktop learns about devices that paired while
	// it was offline.
	go func() {
		pending, err := h.store.ListPendingKeyExchanges(userID)
		if err != nil {
			slog.Error("ListPendingKeyExchanges failed", "err", err)
			return
		}
		for _, d := range pending {
			conn.WriteJSON(protocol.WSMessage{ //nolint:errcheck
				Action:   protocol.ActionKeyExchangeRequested,
				DeviceID: d.Id,
				Hostname: d.Hostname,
			})
		}
	}()

	// Replay pending device-code approval requests for this user.
	// Closes the UX gap where a desktop was offline at DeviceCodeStart
	// fan-out time and would otherwise miss the prompt entirely.
	go func() {
		pendingCodes, err := h.store.ListPendingDeviceCodes(userID)
		if err != nil {
			slog.Error("ListPendingDeviceCodes failed", "err", err)
			return
		}
		for _, p := range pendingCodes {
			conn.WriteJSON(protocol.WSMessage{ //nolint:errcheck
				Action:      protocol.ActionDeviceCodePending,
				UserCode:    p.UserCode,
				Hostname:    p.Hostname,
				RequestedAt: p.RequestedAt.Unix(),
			})
		}
	}()

	// Read loop for agent messages. Tears down exactly this connection on exit
	// via RemoveConn, so a stale loop whose conn was already replaced by a
	// reconnect cannot evict the live replacement.
	go func() {
		defer h.hub.RemoveConn(ac)
		// Bound a single inbound frame (agents only send tiny pong frames) so a
		// malicious client cannot make the server buffer a huge message.
		conn.SetReadLimit(h.wsReadLimit())
		readDeadline := h.wsReadDeadlineDur()
		for {
			// Refresh before each read. The hub's app-level heartbeat keeps a
			// live client sending pongs well inside this window; a silent socket
			// trips the deadline and is reaped instead of pinned forever.
			_ = conn.SetReadDeadline(time.Now().Add(readDeadline))
			var msg protocol.WSMessage
			if err := conn.ReadJSON(&msg); err != nil {
				if shouldLogWSClose(err) {
					slog.Info("ws read error", "user", short(userID), "err", err)
				}
				return
			}
			h.hub.HandleAgentMessage(&msg)
		}
	}()
}

// PushBinaryClip receives an image file via multipart upload.
func (h *Handler) PushBinaryClip(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")

	if h.media == nil {
		writeError(w, http.StatusNotImplemented, "not_configured",
			"Media storage is not configured", "Set MEDIA_BACKEND env var")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 20<<20)
	if err := r.ParseMultipartForm(20 << 20); err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "file too large", "Maximum file size is 20MB", "")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing file", "No file in request", "Include a 'file' field in multipart form")
		return
	}
	defer file.Close()

	contentType := r.FormValue("content_type")
	if contentType == "" {
		contentType = header.Header.Get("Content-Type")
	}
	if !strings.HasPrefix(contentType, "image/") {
		writeError(w, http.StatusBadRequest, "invalid type", "Only image files are supported", "")
		return
	}

	// Rate limit and storage limit check.
	cap, capErr := h.store.GetUserCapabilities(userID)
	if capErr == nil {
		if cap.MaxClipSizeKb > 0 {
			if header.Size > int64(cap.MaxClipSizeKb)*1024 {
				writeError(w, http.StatusBadRequest, "clip_too_large",
					fmt.Sprintf("Maximum allowed size is %d KB", cap.MaxClipSizeKb), "")
				return
			}
		}
		if cap.StorageLimitMb > 0 {
			used, usedErr := h.store.GetUserStorageUsage(userID)
			if usedErr == nil && used+header.Size > int64(cap.StorageLimitMb)*1024*1024 {
				writeError(w, http.StatusTooManyRequests, "storage_quota_exceeded",
					fmt.Sprintf("Total storage limit of %d MB reached", cap.StorageLimitMb),
					"Delete old clips, self-host the relay, or contact support if you need a private relay.")
				return
			}
		}
	}

	exts, _ := mime.ExtensionsByType(contentType)
	ext := ".png"
	if len(exts) > 0 {
		ext = exts[0]
	}

	clipID := ulid.Make().String()
	filename := clipID + ext
	mediaPath := "media/" + filename
	n := header.Size

	if err := h.media.Upload(r.Context(), mediaPath, file, n, contentType); err != nil {
		slog.Error("media upload failed", "err", err)
		writeError(w, http.StatusInternalServerError, "save failed", "Could not upload file", "")
		return
	}

	source := r.FormValue("source")
	label := r.FormValue("label")
	req := &cinchv1.PushClipRequest{
		Content:     "",
		ContentType: protocol.ContentImage,
		Source:      source,
		Label:       label,
		MediaPath:   &mediaPath,
		ByteSize:    n,
	}

	clip, isDup, err := h.store.SaveClip(userID, req)
	if err != nil {
		h.media.Delete(r.Context(), mediaPath)
		writeInternalError(w, "save failed", "save clip", err)
		return
	}

	if source != "" {
		if err := h.store.UpdateDeviceActivity(userID, source); err != nil {
			slog.Error("device activity update failed", "err", err)
		}
	}
	if !isDup {
		delivered, sendErr := h.hub.SendClip(userID, clip)
		if sendErr != nil {
			slog.Error("ws broadcast failed", "err", sendErr)
		}
		// Loop completion: image clips count as sends/reads too.
		h.emitClipSendAndDeliveries(userID, r.Header.Get("X-Device-ID"), clip.ClipId, r.Header.Get("X-Is-Demo") == "true", delivered)
	}

	writeJSON(w, http.StatusOK, cinchv1.PushClipResponse{
		ClipId:   clip.ClipId,
		ByteSize: clip.ByteSize,
	})
}

// GetClipMedia serves a media file for a clip.
func (h *Handler) GetClipMedia(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	clipID := r.PathValue("id")

	if h.media == nil {
		http.Error(w, "media storage not configured", http.StatusNotImplemented)
		return
	}

	mediaPath, err := h.store.GetClipMediaPath(userID, clipID)
	if err != nil || mediaPath == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	body, err := h.media.Download(r.Context(), mediaPath)
	if err != nil {
		slog.Error("media download failed", "media_path", mediaPath, "err", err)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer body.Close()

	ext := filepath.Ext(mediaPath)
	ct := mime.TypeByExtension(ext)
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	// Headers are already committed, so we can't change the status on failure —
	// log so operators can detect truncated deliveries (client disconnects,
	// backend read errors).
	if _, err := io.Copy(w, body); err != nil {
		slog.Error("media stream to client failed", "media_path", mediaPath, "err", err)
	}
}

// Helpers

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, errType, message, fix string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(cinchv1.ErrorResponse{
		Error:   errType,
		Message: message,
		Fix:     fix,
	})
}

// writeInternalError logs the underlying error for operators and returns a
// generic 500 to the client. Use for failures originating from DB, disk, or
// downstream services — leaking raw err.Error() exposes driver versions,
// schema details, and file paths.
func writeInternalError(w http.ResponseWriter, errType, opName string, err error) {
	slog.Error("internal error", "op", opName, "err", err)
	writeError(w, http.StatusInternalServerError, errType, "Internal error", "")
}

// checkLoginRateLimit returns true if the given IP should be denied for
// hitting the per-IP login rate window. Loopback is always allowed.
// Records the attempt on a non-limited hit.
func (h *Handler) checkLoginRateLimit(ip string) bool {
	if ip == "127.0.0.1" || ip == "::1" {
		return false
	}
	return !h.loginLimiter.Allow(ip)
}

func generateToken() string {
	return randomHex(32)
}

// DemoSession mints a short-lived demo token for the landing page.
// One token per page load — no IP-based reuse (NAT/VPN).
func (h *Handler) DemoSession(w http.ResponseWriter, r *http.Request) {
	userID := ulid.Make().String()
	token := generateToken()

	if err := h.store.CreateDemoUser(userID, token); err != nil {
		writeInternalError(w, "demo create failed", "create demo session", err)
		return
	}

	wsURL := deriveWSURL(r)
	relayURL := deriveRelayURL(r)

	region := os.Getenv("RELAY_REGION")
	if region == "" {
		region = "us-east"
	}

	writeJSON(w, http.StatusOK, protocol.DemoSessionResponse{
		Token:     token,
		ExpiresAt: time.Now().UTC().Add(demoTTL),
		RelayURL:  relayURL,
		WSURL:     wsURL,
		MaxClips:  demoMaxClips,
		MaxBytes:  demoMaxBytes,
		Region:    region,
	})
}

// DemoStats returns today's demo push count for the "N developers tried this today" counter.
func (h *Handler) DemoStats(w http.ResponseWriter, r *http.Request) {
	count, err := h.store.GetDemoStats()
	if err != nil {
		writeInternalError(w, "stats failed", "stats", err)
		return
	}
	writeJSON(w, http.StatusOK, protocol.DemoStatsResponse{PushesToday: count})
}

// requestIsHTTPS reports whether the inbound request reached the public edge
// over TLS. Direct TLS (r.TLS) and the standard X-Forwarded-Proto header are
// honored, plus Cloudflare's CF-Visitor JSON ({"scheme":"https"}) which is
// what the cinchcli.com relay sees in production.
func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if r.Header.Get("X-Forwarded-Proto") == "https" {
		return true
	}
	if cv := r.Header.Get("CF-Visitor"); strings.Contains(cv, `"scheme":"https"`) {
		return true
	}
	return false
}

// deriveRelayURL returns the public URL of the relay. RELAY_PUBLIC_URL
// takes precedence when set, so deployments can pin the exact origin
// without relying on proxy-header detection.
func deriveRelayURL(r *http.Request) string {
	if v := os.Getenv("RELAY_PUBLIC_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	scheme := "http"
	if requestIsHTTPS(r) {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// deriveWSURL returns the WebSocket URL for the relay. RELAY_PUBLIC_WS_URL
// overrides everything; otherwise we derive from RELAY_PUBLIC_URL (https→wss,
// http→ws) or from the request scheme.
func deriveWSURL(r *http.Request) string {
	if v := os.Getenv("RELAY_PUBLIC_WS_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	if v := os.Getenv("RELAY_PUBLIC_URL"); v != "" {
		base := strings.TrimRight(v, "/")
		if strings.HasPrefix(base, "https://") {
			return "wss://" + strings.TrimPrefix(base, "https://") + "/ws"
		}
		if strings.HasPrefix(base, "http://") {
			return "ws://" + strings.TrimPrefix(base, "http://") + "/ws"
		}
	}
	scheme := "ws"
	if requestIsHTTPS(r) {
		scheme = "wss"
	}
	return scheme + "://" + r.Host + "/ws"
}

// DemoCORS wraps a handler with CORS headers allowing the landing page origin
// plus any extra origins configured via h.CORSOrigins (from the CORS_ORIGINS env var).
func (h *Handler) DemoCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowed := origin == demoAllowOrigin || origin == demoAllowOriginL
		if !allowed {
			for _, o := range h.CORSOrigins {
				if o == origin {
					allowed = true
					break
				}
			}
		}
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Max-Age", "600")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

// RevokeDevice soft-deletes a device by device_id. Only the owning user may revoke.
// Cross-user revoke returns 404 (not 403) — no existence oracle per RESEARCH Pitfall 5.
func (h *Handler) RevokeDevice(w http.ResponseWriter, r *http.Request) {
	callerUserID := r.Header.Get("X-User-ID")

	var req cinchv1.RevokeDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request", "Could not parse request body", "")
		return
	}
	if req.DeviceId == "" {
		writeError(w, http.StatusBadRequest, "missing_device_id", "device_id is required", "")
		return
	}

	ownerID, err := h.store.DeviceOwner(req.DeviceId)
	if err != nil && err != sql.ErrNoRows {
		// A transient DB error must never be folded into the not-found branch —
		// otherwise it could mask a real failure (or, in a different ordering,
		// let a cross-user revoke slip through). Fail closed with a 500.
		writeInternalError(w, "revoke_failed", "revoke device", err)
		return
	}
	if err == sql.ErrNoRows || ownerID != callerUserID {
		// Treat both unknown and cross-user devices as "not found" — no
		// existence oracle.
		writeError(w, http.StatusNotFound, "device_not_found", "Device not found", "")
		return
	}

	revokedAt, err := h.store.RevokeDevice(req.DeviceId)
	if err != nil {
		writeInternalError(w, "revoke_failed", "revoke device", err)
		return
	}

	// Best-effort WS push to victim device. Do not block or surface errors —
	// the client-side 401 (device_revoked) is the authoritative signal.
	h.hub.SendToDevice(ownerID, req.DeviceId, &cinchv1.ServerEvent{
		Event: &cinchv1.ServerEvent_Revoked{
			Revoked: &cinchv1.RevokedEvent{Reason: "revoked_by_user"},
		},
	})

	writeJSON(w, http.StatusOK, cinchv1.RevokeDeviceResponse{
		Ok:        true,
		DeviceId:  req.DeviceId,
		RevokedAt: protocol.FormatRFC3339(revokedAt),
	})
}

// SetDeviceNickname updates the display name for a device owned by the caller.
func (h *Handler) SetDeviceNickname(w http.ResponseWriter, r *http.Request) {
	callerUserID := r.Header.Get("X-User-ID")
	deviceID := r.PathValue("id")
	if deviceID == "" {
		writeError(w, http.StatusBadRequest, "missing_id", "Device ID required", "")
		return
	}

	var req struct {
		Nickname string `json:"nickname"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Could not parse request body", "")
		return
	}

	// Max 32 Unicode runes (per CONTEXT.md specifics)
	if len([]rune(req.Nickname)) > 32 {
		writeError(w, http.StatusUnprocessableEntity, "nickname_too_long",
			"Nickname must be 32 characters or fewer", "")
		return
	}

	// Verify caller owns this device (same pattern as RevokeDevice)
	ownerID, err := h.store.DeviceOwner(deviceID)
	if err != nil || ownerID != callerUserID {
		writeError(w, http.StatusNotFound, "device_not_found", "Device not found", "")
		return
	}

	if err := h.store.SetDeviceNickname(deviceID, req.Nickname); err != nil {
		writeInternalError(w, "update_failed", "update", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// authBrowserData holds the data passed to the self-host browser sign-in template.
type authBrowserData struct {
	// SelfHost is true when no OAuth providers are configured. When true,
	// the template renders invite-code and display-name fields in addition
	// to the device-name field.
	SelfHost bool
}

// authBrowserTemplate is the self-contained login page served by GET /auth/browser
// for self-hosted relays. It is parsed once at package init via html/template so
// that the {{if .SelfHost}} conditional is evaluated safely at render time.
var authBrowserTemplate = template.Must(template.New("self-host-browser").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in to Cinch</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#07080a;color:#F0EBE0;font-family:'Inter',system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#0f1114;border:1px solid #1a1d23;border-radius:12px;padding:2.5rem;width:100%;max-width:400px}
h1{font-size:1.25rem;font-weight:600;margin-bottom:.5rem}
p.sub{color:#8a8a8a;font-size:.875rem;margin-bottom:1.5rem}
label{display:block;font-size:.8125rem;font-weight:500;color:#a0a0a0;margin-bottom:.375rem}
input{width:100%;padding:.625rem .75rem;background:#07080a;border:1px solid #2a2d33;border-radius:6px;color:#F0EBE0;font-size:.875rem;outline:none;transition:border-color .15s}
input:focus{border-color:#4FB3A9}
.field{margin-bottom:1rem}
button{width:100%;padding:.75rem;background:#4FB3A9;color:#07080a;border:none;border-radius:6px;font-size:.875rem;font-weight:600;cursor:pointer;transition:opacity .15s}
button:hover{opacity:.9}
button:disabled{opacity:.5;cursor:not-allowed}
.error{color:#e55;font-size:.8125rem;margin-top:.75rem;display:none}
.success{color:#4FB3A9;font-size:.8125rem;margin-top:.75rem;display:none}
</style>
</head>
<body>
<div class="card">
  <h1>Sign in to Cinch</h1>
  <p class="sub">Create an account or sign in to connect your devices.</p>
  <form id="loginForm">
    {{if .SelfHost}}
    <div class="field">
      <label for="invite">Invite code</label>
      <input type="text" id="invite" name="invite" placeholder="cinch_inv_…" required autocomplete="off">
    </div>
    <div class="field">
      <label for="display">Your name (optional)</label>
      <input type="text" id="display" name="display" placeholder="han" autocomplete="off">
    </div>
    {{end}}
    <div class="field">
      <label for="hostname">Device Name</label>
      <input type="text" id="hostname" name="hostname" placeholder="my-macbook" autocomplete="off">
    </div>
    <button type="submit" id="submitBtn">Sign In</button>
    <div class="error" id="errorMsg"></div>
    <div class="success" id="successMsg"></div>
  </form>
</div>
<script>
(function(){
  var form = document.getElementById('loginForm');
  var btn = document.getElementById('submitBtn');
  var errorEl = document.getElementById('errorMsg');
  var successEl = document.getElementById('successMsg');
  var params = new URLSearchParams(window.location.search);
  var deviceCode = params.get('device_code') || '';
  var relayURL = window.location.origin;

  form.addEventListener('submit', function(e){
    e.preventDefault();
    btn.disabled = true;
    errorEl.style.display = 'none';
    successEl.style.display = 'none';
    var hostname = document.getElementById('hostname').value.trim() || 'unknown';

    fetch(relayURL + '/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        hostname: hostname,
        invite_code: document.getElementById('invite') ? document.getElementById('invite').value.trim() : undefined,
        display_name: document.getElementById('display') ? document.getElementById('display').value.trim() : undefined
      })
    })
    .then(function(r){ return r.json().then(function(d){ return {ok: r.ok, data: d}; }); })
    .then(function(res){
      if (!res.ok) {
        throw new Error(res.data.message || 'Login failed');
      }
      var d = res.data;
      if (deviceCode) {
        return fetch(relayURL + '/auth/device-code/complete', {
          method: 'POST',
          headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + d.token},
          body: JSON.stringify({user_code: deviceCode})
        }).then(function(){ return d; });
      }
      return d;
    })
    .then(function(d){
      var callbackURL = 'cinch://auth/callback?token=' + encodeURIComponent(d.token) +
        '&device_id=' + encodeURIComponent(d.device_id) +
        '&user_id=' + encodeURIComponent(d.user_id) +
        '&relay_url=' + encodeURIComponent(relayURL);
      successEl.textContent = 'Signed in! Redirecting to Cinch...';
      successEl.style.display = 'block';
      window.location.href = callbackURL;
    })
    .catch(function(err){
      errorEl.textContent = err.message;
      errorEl.style.display = 'block';
      btn.disabled = false;
    });
  });
})();
</script>
</body>
</html>`))

// deviceCodePattern validates the device_code query parameter format before
// it is interpolated into HTML. Only XXXX-XXXX (4 uppercase alphanumeric,
// dash, 4 uppercase alphanumeric) is accepted; anything else gets a 400.
var deviceCodePattern = regexp.MustCompile(`^[A-Z0-9]{4}-[A-Z0-9]{4}$`)

// authOAuthData holds the data passed to the OAuth picker template.
type authOAuthData struct {
	GitHubURL template.URL
	GoogleURL template.URL
}

// AuthBrowser serves the sign-in page.
// When OAuth is configured, shows GitHub/Google buttons.
// When exactly one OAuth provider is configured AND ?device_code= is present,
// skips the picker and 302s straight to the provider start URL — eliminates a
// click on the common "single GitHub provider" deployment.
// Falls back to the legacy username form for self-hosters who don't set OAuth env vars.
func (h *Handler) AuthBrowser(w http.ResponseWriter, r *http.Request) {
	deviceCode := r.URL.Query().Get("device_code")

	// Validate device_code format before any use. An empty device_code is
	// allowed (direct browser navigation); a non-empty one must match the
	// canonical format to prevent reflected XSS.
	if deviceCode != "" && !deviceCodePattern.MatchString(deviceCode) {
		writeError(w, http.StatusBadRequest, "invalid_device_code", "Invalid or missing device code", "")
		return
	}

	hasGitHub := h.OAuth != nil && h.OAuth.GitHub != nil
	hasGoogle := h.OAuth != nil && h.OAuth.Google != nil

	// Auto-redirect: one provider + a device_code in scope = no picker needed.
	// Without device_code, we still render the picker so a user navigating in
	// directly knows what they're about to sign in to.
	if deviceCode != "" {
		switch {
		case hasGitHub && !hasGoogle:
			http.Redirect(w, r, "/auth/oauth/github/start?device_code="+deviceCode, http.StatusFound)
			return
		case hasGoogle && !hasGitHub:
			http.Redirect(w, r, "/auth/oauth/google/start?device_code="+deviceCode, http.StatusFound)
			return
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if hasGitHub || hasGoogle {
		// Build the OAuth picker page using html/template so all interpolated
		// values are automatically HTML-escaped — no raw user input in output.
		tmpl := template.Must(template.New("oauth-picker").Parse(authOAuthHTMLTemplate))

		var data authOAuthData
		if hasGitHub {
			data.GitHubURL = template.URL("/auth/oauth/github/start?device_code=" + deviceCode)
		}
		if hasGoogle {
			data.GoogleURL = template.URL("/auth/oauth/google/start?device_code=" + deviceCode)
		}
		if err := tmpl.Execute(w, data); err != nil {
			slog.Error("AuthBrowser template execute failed", "err", err)
		}
		return
	}

	// Self-host fallback: render the invite + display-name form via template.
	selfHost := !hasGitHub && !hasGoogle
	if err := authBrowserTemplate.Execute(w, authBrowserData{SelfHost: selfHost}); err != nil {
		slog.Error("AuthBrowser template execute failed", "err", err)
	}
}

// authOAuthHTMLTemplate is the OAuth sign-in page rendered via html/template.
// GitHubURL and GoogleURL are template.URL values (already-validated safe URLs);
// when either is empty the corresponding button is omitted.
const authOAuthHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in to Cinch</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#07080a;color:#F0EBE0;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#0f1114;border:1px solid #1a1d23;border-radius:12px;padding:2.5rem;width:100%;max-width:400px;text-align:center}
h1{font-size:1.25rem;font-weight:600;margin-bottom:.5rem}
p{color:#8a8a8a;font-size:.875rem;margin-bottom:1.75rem}
.btn{display:flex;align-items:center;justify-content:center;gap:.625rem;width:100%;padding:.75rem;border-radius:6px;font-size:.875rem;font-weight:600;text-decoration:none;margin-bottom:.75rem;transition:opacity .15s}
.github{background:#f0f0f0;color:#07080a}
.google{background:#fff;color:#3c4043;border:1px solid #dadce0}
.btn:hover{opacity:.9}
</style>
</head>
<body>
<div class="card">
  <h1>Sign in to Cinch</h1>
  <p>Connect your devices with a free account.</p>
  {{if .GitHubURL}}<a class="btn github" href="{{.GitHubURL}}">
    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/>
    </svg>
    Sign in with GitHub
  </a>{{end}}
  {{if .GoogleURL}}<a class="btn google" href="{{.GoogleURL}}">
    <svg width="20" height="20" viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>
    Sign in with Google
  </a>{{end}}
</div>
</body>
</html>`

// CompleteDeviceCodeHTTP is the HTTP handler for POST /auth/device-code/complete.
// Called by `cinch auth approve` to let an already-authenticated device mint
// fresh credentials for the machine that initiated the device-code flow.
//
// Security: the approving device's identity is used only to determine the
// user account. A brand-new deviceID and token are created for the incoming
// machine via CreateDeviceForUser — the approving device's token is never
// shared with or forwarded to the requesting machine.
func (h *Handler) CompleteDeviceCodeHTTP(w http.ResponseWriter, r *http.Request) {
	// RequireAuth sets X-User-ID from the verified auth token.
	// We need the user account but must NOT pass the approving device's
	// deviceID or token to the new machine.
	approverUserID := r.Header.Get("X-User-ID")

	var req struct {
		UserCode string `json:"user_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Could not parse request body", "")
		return
	}
	if req.UserCode == "" {
		writeError(w, http.StatusBadRequest, "missing_user_code", "user_code is required", "")
		return
	}

	if err := h.completeDeviceCodeForCaller(approverUserID, req.UserCode); err != nil {
		if errors.Is(err, errDeviceProvisionFailed) {
			writeInternalError(w, "device_create_failed", "create device for code", err)
			return
		}
		writeError(w, http.StatusBadRequest, "complete_failed", err.Error(), "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "complete"})
}

// completeDeviceCodeForCaller provisions a fresh device for the machine that
// initiated the device-code flow, under the authenticated approver's account,
// then marks the device code complete with that new device's own credentials.
//
// The approver's identity (approverUserID) must come from the verified bearer
// token — never from the request body — and the new device's id and token are
// minted server-side, so the approving device's credentials are never shared
// with or dictated by the requesting machine. Shared by the REST and Connect
// completion paths.
//
// Returns errDeviceProvisionFailed (wrapped) if device creation fails, or the
// CompleteDeviceCode error otherwise (which may wrap ErrDeviceLimitExceeded).
func (h *Handler) completeDeviceCodeForCaller(approverUserID, userCode string) error {
	// Fetch the requesting machine's hostname and machine_id so the new
	// device row is labelled correctly (best-effort; falls back to "unknown").
	hostname, machineID, _ := h.store.DeviceCodeContext(userCode)

	newDeviceID, newToken, err := h.store.CreateDeviceForUser(approverUserID, hostname, machineID)
	if err != nil {
		return fmt.Errorf("%w: %v", errDeviceProvisionFailed, err)
	}
	return h.store.CompleteDeviceCode(userCode, approverUserID, newDeviceID, newToken)
}

// SetDisplayNameHTTP handles POST /auth/display-name.
// Body: {"display_name": "string"} → {"ok": true, "display_name": "trimmed"}.
// Mirrors AuthService.SetDisplayName (Connect-RPC).
// RequireAuth sets X-User-ID before this handler is called.
func (h *Handler) SetDisplayNameHTTP(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	var body struct {
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error(), "")
		return
	}
	trimmed := strings.TrimSpace(body.DisplayName)
	if trimmed == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "display_name must not be empty", "")
		return
	}
	if len(trimmed) > 64 {
		writeError(w, http.StatusBadRequest, "invalid_argument", "display_name max 64 bytes", "")
		return
	}
	if err := h.store.SetUserDisplayName(userID, trimmed); err != nil {
		writeInternalError(w, "set_display_name_failed", "store update", err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Ok          bool   `json:"ok"`
		DisplayName string `json:"display_name"`
	}{Ok: true, DisplayName: trimmed})
}

// IssueWsTicket issues a short-lived single-use ticket for WebSocket auth.
// POST /ws/ticket — RequireAuth sets X-User-ID and X-Device-ID headers.
// The ticket is valid for 30 s and consumed on first use, so the long-lived
// bearer token never appears in the WebSocket URL or server access logs.
func (h *Handler) IssueWsTicket(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	deviceID := r.Header.Get("X-Device-ID")
	ticket := issueWsTicket(userID, deviceID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ticket": ticket,
		"ttl":    30,
	})
}

// startDeviceCode runs the device-code-start logic shared by the REST and
// Connect-RPC entry points: per-IP rate limiting, code creation with requester
// attribution, and the per-pending-user rate-limited WebSocket notification.
// Returns ErrRateLimited when the requester IP is over the limit, or the store
// error otherwise; the caller maps these to its transport's status codes and
// builds the verification URI.
func (h *Handler) startDeviceCode(hostname, machineID, userHint, requesterIP string) (*cinchv1.DeviceCodeStartResponse, error) {
	if requesterIP != "" && !h.deviceCodeIPLimit.Allow(requesterIP) {
		return nil, ErrRateLimited
	}

	resp, pendingUserID, err := h.store.CreateDeviceCode(hostname, machineID, userHint, requesterIP)
	if err != nil {
		return nil, err
	}

	// Per-user broadcast suppression: drop the notification (but still succeed)
	// when the pending user has already received the cap of pending frames this
	// minute, so the response can't leak whether the hint matched a real user.
	if pendingUserID != "" && h.pendingLimit.Allow(pendingUserID) {
		h.hub.BroadcastWSToUser(pendingUserID, &protocol.WSMessage{
			Action:      protocol.ActionDeviceCodePending,
			UserCode:    resp.UserCode,
			Hostname:    hostname,
			RequestedAt: time.Now().Unix(),
		})
	}
	return resp, nil
}

// IssueDeviceCode creates a new device code for CLI auth.
// POST /auth/device-code — no auth required (this IS the auth entry point).
func (h *Handler) IssueDeviceCode(w http.ResponseWriter, r *http.Request) {
	var req cinchv1.DeviceCodeStartRequest
	if r.Body != nil && r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	hostname := ""
	if req.Hostname != nil {
		hostname = *req.Hostname
	}
	if hostname == "" {
		hostname = "unknown"
	}
	machineID := ""
	if req.MachineId != nil {
		machineID = *req.MachineId
	}
	userHint := ""
	if req.UserHint != nil {
		userHint = *req.UserHint
	}

	resp, err := h.startDeviceCode(hostname, machineID, userHint, clientIP(r.RemoteAddr, r.Header))
	if err != nil {
		if errors.Is(err, ErrRateLimited) {
			writeError(w, http.StatusTooManyRequests, "rate_limited",
				"Too many device-code requests. Try again shortly.", "")
			return
		}
		writeInternalError(w, "device_code_failed", "device code", err)
		return
	}

	// Build verification URI from BaseURL or derive from request.
	baseURL := h.BaseURL
	if baseURL == "" {
		baseURL = deriveRelayURL(r)
	}
	resp.VerificationUri = baseURL + "/auth/browser?device_code=" + resp.UserCode

	writeJSON(w, http.StatusOK, resp)
}

// PollDeviceCode checks the status of a device code.
// GET /auth/device-code/poll?code=<device_code> — no auth required.
func (h *Handler) PollDeviceCode(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "missing_code", "code query parameter is required", "")
		return
	}

	resp, err := h.store.PollDeviceCode(code)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error(), "Run cinch auth login again")
		return
	}

	if resp.Status == "expired" {
		writeError(w, http.StatusGone, "expired", "Device code expired", "Run cinch auth login again")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// UpdateDeviceRetention handles PUT /devices/self/retention.
// Accepts JSON body: {"remote_retention_days": N} where N is 1-365.
// Updates the authenticated device's remote_retention_days column.
func (h *Handler) UpdateDeviceRetention(w http.ResponseWriter, r *http.Request) {
	deviceID := r.Header.Get("X-Device-ID")
	if deviceID == "" {
		writeError(w, http.StatusBadRequest, "missing_device",
			"This endpoint requires per-device authentication",
			"Re-authenticate with a per-device token")
		return
	}

	var req struct {
		RemoteRetentionDays int `json:"remote_retention_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"Could not parse request body", "Send JSON: {\"remote_retention_days\": 30}")
		return
	}

	if err := h.store.UpdateDeviceRetention(deviceID, req.RemoteRetentionDays); err != nil {
		if errors.Is(err, ErrRetentionOutOfRange) {
			writeError(w, http.StatusBadRequest, "invalid_range",
				err.Error(), "Value must be between 1 and 365")
			return
		}
		writeError(w, http.StatusInternalServerError, "update_failed",
			err.Error(), "")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// UpdateUserQuota handles POST /internal/quota.
// Called by the biz control plane to write numeric plan limits for a user.
// Protected by INTERNAL_QUOTA_WRITE_SECRET (or legacy INTERNAL_SERVICE_SECRET) bearer.
func (h *Handler) UpdateUserQuota(w http.ResponseWriter, r *http.Request) {
	// Write-scoped: accept the quota-write secret, falling back to the legacy
	// shared secret for backward compatibility.
	switch internalauth.Check(r.Header.Get("Authorization"), h.internalQuotaWriteSecret, h.internalServiceSecret) {
	case internalauth.Disabled:
		writeError(w, http.StatusServiceUnavailable, "not_configured",
			"Internal quota endpoint is not configured on this relay", "")
		return
	case internalauth.Denied:
		writeError(w, http.StatusForbidden, "forbidden", "Invalid service secret", "")
		return
	}

	var req struct {
		UserID         string  `json:"user_id"`
		DeviceLimit    int     `json:"device_limit"`
		RetentionDays  int     `json:"retention_days"`
		RateLimit      int     `json:"rate_limit"`
		StorageLimitMb int     `json:"storage_limit_mb"`
		MaxClipSizeKb  int     `json:"max_clip_size_kb"`
		GraceExpiresAt *string `json:"grace_expires_at"` // RFC 3339, optional
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Could not parse request body", "")
		return
	}
	if req.UserID == "" {
		writeError(w, http.StatusBadRequest, "missing_user_id", "user_id is required", "")
		return
	}
	if req.DeviceLimit < 0 || req.RetentionDays < 0 || req.RateLimit < 0 || req.StorageLimitMb < 0 || req.MaxClipSizeKb < 0 {
		writeError(w, http.StatusBadRequest, "invalid_limits", "Limits must be non-negative", "")
		return
	}

	cap := UserCapabilities{
		UserID:         req.UserID,
		DeviceLimit:    req.DeviceLimit,
		RetentionDays:  req.RetentionDays,
		RateLimit:      req.RateLimit,
		StorageLimitMb: req.StorageLimitMb,
		MaxClipSizeKb:  req.MaxClipSizeKb,
	}
	if req.GraceExpiresAt != nil && *req.GraceExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.GraceExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_grace", "grace_expires_at must be RFC 3339", "")
			return
		}
		cap.GraceExpiresAt = t
	}

	if err := h.store.UpsertUserCapabilities(cap); err != nil {
		writeInternalError(w, "upsert_failed", "upsert quota", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// middleware decorates an http.HandlerFunc. Routes list their middleware in
// outermost-first order; applyMiddleware wraps so the first listed runs first.
type middleware func(http.HandlerFunc) http.HandlerFunc

// httpRoute is one row of the route table: a method+pattern, the handler, and
// the middleware stack guarding it. Keeping the stack as data makes auth
// coverage auditable at a glance — grep the table for `auth`/`admin`.
type httpRoute struct {
	pattern string
	handler http.HandlerFunc
	mw      []middleware
}

func applyMiddleware(handler http.HandlerFunc, mw []middleware) http.HandlerFunc {
	for i := len(mw) - 1; i >= 0; i-- {
		handler = mw[i](handler)
	}
	return handler
}

// httpRoutes returns the full REST route table. Middleware stacks:
//   - {auth}        → RequireAuth (verified bearer; sets identity headers)
//   - {admin}       → RequireAdmin (RequireAuth + is_admin check)
//   - {cors}        → DemoCORS (landing-page CORS)
//   - {cors, auth}  → DemoCORS(RequireAuth(...))
//   - nil           → public (handler self-guards if needed, e.g. /internal/quota)
func (h *Handler) httpRoutes() []httpRoute {
	auth := []middleware{h.RequireAuth}
	admin := []middleware{h.RequireAdmin}
	cors := []middleware{h.DemoCORS}
	corsAuth := []middleware{h.DemoCORS, h.RequireAuth}
	noop := func(w http.ResponseWriter, r *http.Request) {}

	return []httpRoute{
		// Auth + device-code entry points (public).
		{"GET /auth/browser", h.AuthBrowser, nil},
		{"POST /auth/device-code", h.IssueDeviceCode, nil},
		{"GET /auth/device-code/poll", h.PollDeviceCode, nil},
		{"POST /auth/device-code/complete", h.CompleteDeviceCodeHTTP, auth},
		{"POST /auth/device/revoke", h.RevokeDevice, auth},

		// Clips.
		{"POST /clips", h.PushClip, corsAuth},
		{"OPTIONS /clips", noop, cors},
		{"GET /clips", h.ListClips, auth},
		{"DELETE /clips/{id}", h.DeleteClip, auth},
		{"POST /clips/{id}/pin", h.SetClipPin, auth},
		{"GET /tombstones", h.ListTombstones, auth},
		{"GET /clips/latest", h.GetLatestClip, auth},
		{"POST /clips/binary", h.PushBinaryClip, auth},
		{"GET /clips/{id}/media", h.GetClipMedia, auth},

		// Devices.
		{"GET /devices", h.ListDevices, auth},
		{"PUT /devices/{id}/nickname", h.SetDeviceNickname, auth},
		{"PUT /devices/self/retention", h.UpdateDeviceRetention, auth},

		// Account + keys.
		{"POST /auth/display-name", h.SetDisplayNameHTTP, auth},
		{"POST /auth/key-bundle", h.PostKeyBundle, auth},
		{"GET /auth/key-bundle", h.GetKeyBundle, auth},
		{"POST /auth/key-bundle/retry", h.KeyBundleRetry, auth},
		{"POST /auth/device/public-key", h.RegisterDevicePublicKey, auth},

		// WebSocket.
		{"GET /ws", h.HandleWebSocket, nil},
		{"POST /ws/ticket", h.IssueWsTicket, auth},

		// Ops + internal (self-guarded by INTERNAL_SERVICE_SECRET).
		{"GET /health", h.Health, nil},
		{"POST /internal/quota", h.UpdateUserQuota, nil},
		{"GET /internal/users", h.ListInternalUsers, nil},

		// Admin (RequireAdmin wraps RequireAuth).
		{"POST /admin/invites", h.AdminCreateInvite, admin},
		{"GET /admin/invites", h.AdminListInvites, admin},
		{"DELETE /admin/invites/{hash}", h.AdminRevokeInvite, admin},
		{"GET /admin/users", h.AdminListUsers, admin},
		{"DELETE /admin/users/{id}", h.AdminDeleteUser, admin},

		// Demo (CORS-enabled for the landing page).
		{"POST /demo/session", h.DemoSession, cors},
		{"OPTIONS /demo/session", noop, cors},
		{"GET /demo/stats", h.DemoStats, cors},
		{"OPTIONS /demo/stats", noop, cors},

		// OAuth (no-op when OAuth not configured).
		{"GET /auth/providers", h.GetProviders, nil},
		{"GET /auth/oauth/github/start", h.OAuthStart("github"), nil},
		{"GET /auth/oauth/github/callback", h.OAuthCallback("github"), nil},
		{"GET /auth/oauth/google/start", h.OAuthStart("google"), nil},
		{"GET /auth/oauth/google/callback", h.OAuthCallback("google"), nil},
		{"POST /auth/oauth/confirm", h.OAuthConfirm, nil},

		// Anonymous opt-in telemetry (always 200; dropped if backend unset).
		{"POST /telemetry", h.HandleTelemetry, nil},
	}
}

// RegisterRoutes registers all relay HTTP routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Only register the legacy auth/login endpoint when no OAuth providers are
	// configured. When OAuth is active, all accounts must be created via the
	// OAuth flow to preserve the identity audit trail (security finding 3).
	if h.OAuth == nil || (h.OAuth.GitHub == nil && h.OAuth.Google == nil) {
		mux.HandleFunc("POST /auth/login", h.AuthLogin)
	}

	for _, rt := range h.httpRoutes() {
		mux.HandleFunc(rt.pattern, applyMiddleware(rt.handler, rt.mw))
	}

	// Catch-all: return JSON 404 instead of Go's default plain-text response.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "Endpoint not found", "")
	})

	// Connect-RPC handlers — mounted in parallel with REST (PR-B1 pilot).
	// REST endpoints above are kept until all clients migrate.
	authSvcPath, authSvcHandler := h.newAuthConnectHandler()
	mux.Handle(authSvcPath, authSvcHandler)

	clipsSvcPath, clipsSvcHandler := h.newClipsConnectHandler()
	mux.Handle(clipsSvcPath, clipsSvcHandler)

	devicesSvcPath, devicesSvcHandler := h.newDevicesConnectHandler()
	mux.Handle(devicesSvcPath, devicesSvcHandler)

	eventsSvcPath, eventsSvcHandler := h.newEventsConnectHandler()
	mux.Handle(eventsSvcPath, eventsSvcHandler)

	meSvcPath, meSvcHandler := h.newMeConnectHandler()
	mux.Handle(meSvcPath, meSvcHandler)
}
