// Package relay implements the cinch relay server: HTTP handlers, WebSocket
// hub, and SQLite-backed clip storage.
package relay

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	cinchv1 "github.com/cinchcli/relay/internal/gen/cinch/v1"
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

const playgroundRecentMax = 20 // keep last N clips so refreshing visitors see history

// Playground shared session — one session per hour, reset by goroutine.
// userID = empty string indicates "not yet seeded" (StartPlaygroundReset must be called).
type playgroundState struct {
	mu          sync.RWMutex
	userID      string
	token       string
	streamID    string
	expiresAt   time.Time
	recentClips []string // last playgroundRecentMax clips, newest last
}

var playground playgroundState

// ipRateEntry tracks last-push timestamp for the in-memory IP rate limiter
// for POST /demo/playground/push. Map is goroutine-safe via ipRateMu.
// Memory bound: ~50 bytes per IP × ~1000 active IPs = trivial; no eviction needed
// for v1 — entries simply remain after their 30s window expires.
type ipRateEntry struct {
	lastPush time.Time
}

var (
	ipRateMu  sync.Mutex
	ipRateMap = map[string]ipRateEntry{}
)

// loginRateWindow is the minimum interval between anonymous account creations
// from the same IP. One new account per minute is generous for legitimate use
// (smoke tests, demos) while blocking trivial DB-bloat attacks.
const loginRateWindow = 1 * time.Minute

var (
	ErrAgentOffline = errors.New("desktop agent is not connected")
	ErrAgentTimeout = errors.New("desktop agent did not respond in time")
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
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
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	ticket := hex.EncodeToString(b)
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

type Handler struct {
	store       *Store
	hub         *Hub
	media       media.Store     // nil means binary upload disabled
	BaseURL     string          // public base URL of the relay (for verification URIs)
	OAuth       *OAuthProviders // nil = OAuth not configured; self-host falls back to username form
	CORSOrigins []string        // extra allowed origins beyond the hardcoded landing page defaults

	TelemetryURL    string // e.g. https://telemetry.jinmu.me
	TelemetryAPIKey string // X-API-Key sent to telemetry backend

	telemetryLimiter *rateLimiter

	loginRateMu  sync.Mutex
	loginRateMap map[string]time.Time
}

func NewHandler(store *Store, hub *Hub) *Handler {
	return &Handler{
		store:            store,
		hub:              hub,
		telemetryLimiter: newRateLimiter(5, time.Hour),
		loginRateMap:     make(map[string]time.Time),
	}
}

// SetMediaStore attaches a media backend to the handler.
func (h *Handler) SetMediaStore(s media.Store) { h.media = s }

// RequireAuth wraps a handler with token authentication.
// After the OAuth-only migration every active token lives on devices.token;
// the legacy master-token (users.token) lookup has been removed.
func (h *Handler) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			writeError(w, http.StatusUnauthorized, "not authenticated", "No auth token provided", "Run: cinch auth login")
			return
		}

		deviceID, revoked, derr := h.store.DeviceIDByToken(token)
		if derr != nil {
			if derr != sql.ErrNoRows {
				log.Printf("DeviceIDByToken error: %v", derr)
			}
			writeError(w, http.StatusUnauthorized, "invalid token", "Token is invalid or expired", "Run: cinch auth login")
			return
		}
		if revoked {
			writeError(w, http.StatusUnauthorized, "device_revoked",
				"This device was revoked", "Run: cinch auth login")
			return
		}
		userID, err := h.store.DeviceOwner(deviceID)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid token", "Token is invalid or expired", "Run: cinch auth login")
			return
		}

		// Demo TTL gate: demo sessions are bounded to 10 minutes; reject
		// stale device tokens with a distinct error so the landing page
		// can prompt the visitor to refresh for a fresh session.
		var isDemo int
		var createdAt time.Time
		if err := h.store.db.QueryRow(
			"SELECT is_demo, created_at FROM users WHERE id = ?", userID,
		).Scan(&isDemo, &createdAt); err == nil && isDemo == 1 {
			if time.Since(createdAt) > demoTTL {
				writeError(w, http.StatusUnauthorized, "demo expired", "Demo session expired", "Refresh the page for a new session")
				return
			}
		}

		r.Header.Set("X-Device-ID", deviceID)
		r.Header.Set("X-User-ID", userID)
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

	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip, _, _ = strings.Cut(r.RemoteAddr, ":")
	} else {
		ip = strings.TrimSpace(strings.SplitN(ip, ",", 2)[0])
	}
	// Loopback addresses are only reachable locally (smoke tests, local dev).
	// Real public traffic always arrives via Cloudflare with X-Forwarded-For set.
	if ip != "127.0.0.1" && ip != "::1" {
		h.loginRateMu.Lock()
		if last, ok := h.loginRateMap[ip]; ok && time.Since(last) < loginRateWindow {
			h.loginRateMu.Unlock()
			writeError(w, http.StatusTooManyRequests, "rate_limited",
				"Too many login attempts. Try again in a minute.", "")
			return
		}
		h.loginRateMap[ip] = time.Now()
		h.loginRateMu.Unlock()
	}

	var req cinchv1.LoginRequest
	if r.Body != nil && r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	hostname := "unknown"
	if req.Hostname != nil && *req.Hostname != "" {
		hostname = *req.Hostname
	}

	userID := ulid.Make().String()
	if err := h.store.CreateUser(userID); err != nil {
		writeError(w, http.StatusInternalServerError, "account creation failed", err.Error(), "")
		return
	}

	deviceID := ulid.Make().String()
	deviceToken := generateToken()
	if err := h.store.RegisterDeviceWithToken(userID, deviceID, hostname, deviceToken); err != nil {
		writeError(w, http.StatusInternalServerError, "device creation failed", err.Error(), "")
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
// when the device or `cinch auth retry-key` asks for a re-share.
// Bearer-authenticated; the device_id is taken from the auth header.
func (h *Handler) RegisterDevicePublicKey(w http.ResponseWriter, r *http.Request) {
	deviceID := r.Header.Get("X-Device-ID")
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
		writeError(w, http.StatusInternalServerError, "store error", err.Error(), "")
		return
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
		writeError(w, http.StatusInternalServerError, "store error", err.Error(), "")
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

	// E2EE is mandatory for non-demo users. Demo identities are server-side
	// ephemeral with no client-side key exchange; demo data is intentionally
	// public, capped at 1024 bytes, and TTL'd.
	isDemoUser, _ := h.store.IsDemoUser(userID)
	if !isDemoUser && !req.Encrypted {
		writeError(w, http.StatusUnprocessableEntity, "encryption_required",
			"Server requires end-to-end encrypted clips. Plaintext push was rejected.",
			"Run cinch auth login to (re)generate your encryption key.")
		return
	}

	targetDeviceID := ""
	if req.TargetDeviceId != nil {
		targetDeviceID = *req.TargetDeviceId
	}

	// Targeted push — check online BEFORE SaveClip (per D-10: no clip saved if device offline)
	if targetDeviceID != "" {
		if !h.hub.IsDeviceOnline(userID, targetDeviceID) {
			writeError(w, http.StatusNotFound, "device_offline",
				"Device is not currently online. Push was not delivered.",
				"Wait for the device to come online and retry.")
			return
		}
		clip, err := h.store.SaveClip(userID, &req)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "save_failed", err.Error(), "")
			return
		}
		if req.Source != "" {
			h.store.UpdateDeviceActivity(userID, req.Source)
		}
		if err := h.hub.SendToDevice(userID, targetDeviceID, &cinchv1.ServerEvent{
			Event: &cinchv1.ServerEvent_NewClip{
				NewClip: &cinchv1.NewClipEvent{Clip: clip},
			},
		}); err != nil {
			log.Printf("SendToDevice failed after online check: %v", err)
		}
		writeJSON(w, http.StatusOK, cinchv1.PushClipResponse{
			ClipId: clip.ClipId, ByteSize: clip.ByteSize,
		})
		return
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

	clip, err := h.store.SaveClip(userID, &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "save failed", err.Error(), "")
		return
	}

	if isDemoUser {
		if err := h.store.IncrementDemoCounter(); err != nil {
			log.Printf("demo counter increment failed: %v", err)
		}
	}

	// Update device activity stats
	if req.Source != "" {
		if err := h.store.UpdateDeviceActivity(userID, req.Source); err != nil {
			log.Printf("device activity update failed: %v", err)
		}
	}

	if err := h.hub.SendClip(userID, clip); err != nil {
		log.Printf("ws broadcast failed for %s: %v", userID, err)
	}

	writeJSON(w, http.StatusOK, cinchv1.PushClipResponse{
		ClipId:   clip.ClipId,
		ByteSize: clip.ByteSize,
	})
}

// ListClips returns recent clips for the authenticated user.
// Accepts optional query params: ?since=<RFC3339> and ?limit=<int>.
func (h *Handler) ListClips(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")

	var sinceTime time.Time
	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		t, err := time.Parse(time.RFC3339, sinceStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_since", "invalid since parameter", "")
			return
		}
		sinceTime = t
	}

	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		n, err := strconv.Atoi(limitStr)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "invalid_limit", "invalid limit parameter", "")
			return
		}
		if n > 100 {
			n = 100
		}
		if n > 0 {
			limit = n
		}
	}

	clips, err := h.store.ListClipsSince(userID, sinceTime, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed", err.Error(), "")
		return
	}
	writeJSON(w, http.StatusOK, clips)
}

// DeleteClip removes a clip.
func (h *Handler) DeleteClip(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	clipID := r.PathValue("id")

	mediaPath, err := h.store.DeleteClipReturningMedia(userID, clipID)
	if err != nil {
		if err.Error() == "clip not found" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeError(w, http.StatusInternalServerError, "delete_failed", err.Error(), "")
		return
	}

	if mediaPath != "" && h.media != nil {
		if err := h.media.Delete(r.Context(), mediaPath); err != nil {
			log.Printf("media delete %q: %v", mediaPath, err)
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// PullClipboard requests clipboard content from the desktop agent.
func (h *Handler) PullClipboard(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")

	if isDemo, _ := h.store.IsDemoUser(userID); isDemo {
		writeError(w, http.StatusForbidden, "demo read only", "Demo sessions cannot pull from a desktop agent", "Install cinch to pull clips")
		return
	}

	pullID := ulid.Make().String()

	content, err := h.hub.RequestClipboard(userID, pullID)
	if err != nil {
		switch {
		case errors.Is(err, ErrAgentOffline):
			writeError(w, http.StatusServiceUnavailable, "agent offline", "Your desktop agent is not connected", "Make sure cinchd is running on your Mac")
		case errors.Is(err, ErrAgentTimeout):
			writeError(w, http.StatusGatewayTimeout, "agent timeout", "Desktop agent did not respond within 10 seconds", "Check if cinchd is running")
		default:
			writeError(w, http.StatusInternalServerError, "pull failed", err.Error(), "")
		}
		return
	}

	writeJSON(w, http.StatusOK, cinchv1.PullResponse{
		PullId:  pullID,
		Content: content,
	})
}

// GetLatestClip returns the most recent clip from a specific source.
func (h *Handler) GetLatestClip(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	source := r.URL.Query().Get("source")
	if source == "" {
		writeError(w, http.StatusBadRequest, "missing source", "source query parameter is required", "Usage: cinch pull --from <hostname>")
		return
	}

	clip, err := h.store.GetLatestClipBySource(userID, source)
	if err != nil {
		writeError(w, http.StatusNotFound, "not found", err.Error(), "No clips from this source yet")
		return
	}

	writeJSON(w, http.StatusOK, clip)
}

// ListDevices returns paired devices with online status.
func (h *Handler) ListDevices(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	devices, err := h.store.ListDevices(userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed", err.Error(), "")
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
// Legacy path: ?token=<token> — kept for the playground and legacy clients
// during the migration window.
func (h *Handler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Ticket path: short-lived, single-use — bearer token not exposed in URL.
	if ticket := r.URL.Query().Get("ticket"); ticket != "" {
		userID, deviceID, ok := consumeWsTicket(ticket)
		if !ok {
			http.Error(w, "invalid or expired ticket", http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("ws upgrade failed: %v", err)
			return
		}
		h.hub.Register(userID, deviceID, conn)

		// Notify desktop of any pending key exchanges for this user.
		go func() {
			pending, err := h.store.ListPendingKeyExchanges(userID)
			if err != nil {
				log.Printf("ListPendingKeyExchanges: %v", err)
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

		// Read loop for agent messages.
		go func() {
			defer h.hub.Remove(userID, deviceID)
			for {
				var msg protocol.WSMessage
				if err := conn.ReadJSON(&msg); err != nil {
					if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
						log.Printf("ws read error for %s: %v", userID[:8], err)
					}
					return
				}
				h.hub.HandleAgentMessage(&msg)
			}
		}()
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}

	// Playground shared session: validate against in-memory state before hitting the DB.
	// The playground token is never written to SQLite, so DB lookups would always fail.
	playground.mu.RLock()
	pgToken := playground.token
	pgUserID := playground.userID
	pgExpiry := playground.expiresAt
	playground.mu.RUnlock()
	if token == pgToken && pgUserID != "" && time.Now().Before(pgExpiry) {
		// Upgrade and subscribe to the demo broadcast channel.
		// BroadcastDemoClip sends to demoSubs channels (not the agent conns map),
		// so we must subscribe here and pump channel messages to the WS connection.
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("ws playground upgrade failed: %v", err)
			return
		}
		// Replay recent clips so refreshing visitors see history immediately.
		playground.mu.RLock()
		recent := make([]string, len(playground.recentClips))
		copy(recent, playground.recentClips)
		playground.mu.RUnlock()
		for _, content := range recent {
			msg := map[string]any{
				"action": "demo_clip",
				"clip":   map[string]string{"content": content, "clip_id": ulid.Make().String()},
			}
			if err := conn.WriteJSON(msg); err != nil {
				return
			}
		}

		ch := h.hub.SubscribeDemoStream(pgUserID)
		defer h.hub.UnsubscribeDemoStream(pgUserID, ch)
		// Detect client disconnect by draining incoming frames in a goroutine.
		closed := make(chan struct{})
		go func() {
			defer close(closed)
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}()
		// Pump broadcast channel → WebSocket until client disconnects or channel closes.
		for {
			select {
			case <-closed:
				return
			case content, ok := <-ch:
				if !ok {
					return
				}
				msg := map[string]any{
					"action": "demo_clip",
					"clip":   map[string]string{"content": content, "clip_id": ulid.Make().String()},
				}
				if err := conn.WriteJSON(msg); err != nil {
					return
				}
			}
		}
	}

	// Per-device token only. The legacy master-token (users.token) lookup
	// and lazy-migration branch were removed in the OAuth-only migration.
	deviceID, revoked, derr := h.store.DeviceIDByToken(token)
	if derr != nil {
		if derr == sql.ErrNoRows {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		log.Printf("DeviceIDByToken WS error: %v", derr)
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

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ws upgrade failed: %v", err)
		return
	}

	h.hub.Register(userID, deviceID, conn)

	// Phase 4.5: notify desktop of any pending key exchanges for this user.
	// Handles the offline-desktop case: desktop learns about devices that paired while offline.
	go func() {
		pending, err := h.store.ListPendingKeyExchanges(userID)
		if err != nil {
			log.Printf("ListPendingKeyExchanges: %v", err)
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

	// Read loop for agent messages.
	go func() {
		defer h.hub.Remove(userID, deviceID)
		for {
			var msg protocol.WSMessage
			if err := conn.ReadJSON(&msg); err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
					log.Printf("ws read error for %s: %v", userID[:8], err)
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
		log.Printf("media upload failed: %v", err)
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

	clip, err := h.store.SaveClip(userID, req)
	if err != nil {
		h.media.Delete(r.Context(), mediaPath)
		writeError(w, http.StatusInternalServerError, "save failed", err.Error(), "")
		return
	}

	if source != "" {
		if err := h.store.UpdateDeviceActivity(userID, source); err != nil {
			log.Printf("device activity update: %v", err)
		}
	}
	if err := h.hub.SendClip(userID, clip); err != nil {
		log.Printf("ws broadcast: %v", err)
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
		log.Printf("media download %q: %v", mediaPath, err)
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
	io.Copy(w, body)
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

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// DemoSession mints a short-lived demo token for the landing page.
// One token per page load — no IP-based reuse (NAT/VPN).
func (h *Handler) DemoSession(w http.ResponseWriter, r *http.Request) {
	userID := ulid.Make().String()
	token := generateToken()

	if err := h.store.CreateDemoUser(userID, token); err != nil {
		writeError(w, http.StatusInternalServerError, "demo create failed", err.Error(), "")
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

// PlaygroundSession returns the shared playground session.
// One session is active per hour; all anonymous visitors share it.
// Per D-decisions: GET /demo/playground returns {token, stream_id, ws_url, relay_url, expires_at, region}.
func (h *Handler) PlaygroundSession(w http.ResponseWriter, r *http.Request) {
	playground.mu.RLock()
	token := playground.token
	streamID := playground.streamID
	expiresAt := playground.expiresAt
	playground.mu.RUnlock()

	if token == "" {
		writeError(w, http.StatusServiceUnavailable, "not_ready",
			"Playground session not initialized", "")
		return
	}

	wsURL := deriveWSURL(r)
	relayURL := deriveRelayURL(r)
	region := os.Getenv("RELAY_REGION")
	if region == "" {
		region = "us-east"
	}

	writeJSON(w, http.StatusOK, protocol.PlaygroundSessionResponse{
		Token:     token,
		StreamID:  streamID,
		ExpiresAt: expiresAt,
		RelayURL:  relayURL,
		WSURL:     wsURL,
		Region:    region,
	})
}

// PlaygroundPush accepts unauthenticated text pushes for the shared playground.
// No auth middleware — visitors are identified by IP for rate limiting (1 push per IP per 30s).
// Per D-decisions: returns HTTP 429 {"error":"rate_limited","retry_after":30} on rate-limit hit,
// HTTP 410 on expired session, HTTP 413 on >500 byte content.
func (h *Handler) PlaygroundPush(w http.ResponseWriter, r *http.Request) {
	// IP-based rate limit. Prefer X-Forwarded-For when behind a proxy.
	// Strip port from RemoteAddr (format "IP:port") so all requests from the
	// same IP share one rate-limit bucket regardless of ephemeral source port.
	ip := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ip = strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
	} else if host, _, found := strings.Cut(ip, ":"); found && host != "" {
		ip = host
	}
	ipRateMu.Lock()
	entry := ipRateMap[ip]
	if !entry.lastPush.IsZero() && time.Since(entry.lastPush) < 30*time.Second {
		ipRateMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":       "rate_limited",
			"retry_after": 30,
		})
		return
	}
	ipRateMap[ip] = ipRateEntry{lastPush: time.Now()}
	ipRateMu.Unlock()

	var req struct {
		Content     string `json:"content"`
		ContentType string `json:"content_type"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096) // hard cap before decode; 500-byte content check follows
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Could not parse request body", "")
		return
	}
	if req.Content == "" {
		writeError(w, http.StatusBadRequest, "empty_content", "content is required", "")
		return
	}
	if req.ContentType != "" && req.ContentType != "text" {
		writeError(w, http.StatusBadRequest, "invalid_content_type",
			"Only content_type=text is accepted on the playground", "")
		return
	}
	const playgroundMaxBytes = 500
	if len(req.Content) > playgroundMaxBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large",
			fmt.Sprintf("Content exceeds %d bytes", playgroundMaxBytes), "")
		return
	}

	// Validate session still active; return 410 if expired (frontend re-fetches on 410).
	playground.mu.RLock()
	userID := playground.userID
	expiresAt := playground.expiresAt
	playground.mu.RUnlock()

	if userID == "" || time.Now().After(expiresAt) {
		writeError(w, http.StatusGone, "session_expired",
			"Playground session has reset. Fetch /demo/playground for a new session.", "")
		return
	}

	// Store in recent history so refreshing visitors see the last N clips.
	playground.mu.Lock()
	playground.recentClips = append(playground.recentClips, req.Content)
	if len(playground.recentClips) > playgroundRecentMax {
		playground.recentClips = playground.recentClips[len(playground.recentClips)-playgroundRecentMax:]
	}
	playground.mu.Unlock()

	h.hub.BroadcastDemoClip(userID, req.Content)

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// StartPlaygroundReset seeds the first shared session and starts a goroutine
// that resets it every hour. Safe to call exactly once at startup; subsequent
// calls would create duplicate goroutines (they are not idempotent).
func (h *Handler) StartPlaygroundReset() {
	h.resetPlayground()
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			h.resetPlayground()
		}
	}()
}

// resetPlayground rotates the shared playground userID/token/streamID and
// re-registers the new streamID with the hub. The previous userID's
// demo subscribers naturally drain when their connection closes.
func (h *Handler) resetPlayground() {
	userID := ulid.Make().String()
	token := generateToken()
	streamBytes := make([]byte, 4)
	if _, err := rand.Read(streamBytes); err != nil {
		log.Printf("playground reset: rand.Read error: %v", err)
		return
	}
	streamID := hex.EncodeToString(streamBytes)

	h.hub.RegisterStreamID(streamID, userID)

	playground.mu.Lock()
	playground.userID = userID
	playground.token = token
	playground.streamID = streamID
	playground.expiresAt = time.Now().UTC().Add(time.Hour)
	playground.recentClips = nil // clear history on hourly reset
	playground.mu.Unlock()

	log.Printf("playground session reset: stream=%s expires=%s",
		streamID, playground.expiresAt.Format(time.RFC3339))
}

// DemoStream subscribes to a demo broadcast channel over SSE using the public stream_id.
// Used by the /playground curl read command: `curl -sN {relay_url}/demo/stream/{sid}`
func (h *Handler) DemoStream(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	if sid == "" {
		writeError(w, http.StatusBadRequest, "missing_sid", "stream_id is required", "")
		return
	}
	userID := h.hub.LookupStreamID(sid)
	if userID == "" {
		writeError(w, http.StatusNotFound, "unknown_stream", "Stream not found or expired", "")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	ch := h.hub.SubscribeDemoStream(userID)
	defer h.hub.UnsubscribeDemoStream(userID, ch)

	plain := r.URL.Query().Get("plain") == "1"

	flusher, canFlush := w.(http.Flusher)
	if canFlush {
		flusher.Flush()
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case content, ok := <-ch:
			if !ok {
				return
			}
			if plain {
				fmt.Fprintf(w, "%s\n", content)
			} else {
				data, _ := json.Marshal(map[string]any{
					"action": "demo_clip",
					"clip":   map[string]string{"content": content, "clip_id": ulid.Make().String()},
				})
				fmt.Fprintf(w, "data: %s\n\n", data)
			}
			if canFlush {
				flusher.Flush()
			}
		}
	}
}

// DemoStats returns today's demo push count for the "N developers tried this today" counter.
func (h *Handler) DemoStats(w http.ResponseWriter, r *http.Request) {
	count, err := h.store.GetDemoStats()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "stats failed", err.Error(), "")
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

// deriveRelayURL returns the public URL of the relay (used in the CLI curl
// command shown on the playground page). RELAY_PUBLIC_URL takes precedence
// when set, so deployments can pin the exact origin without relying on
// proxy-header detection.
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
	if err == sql.ErrNoRows || ownerID != callerUserID {
		// Treat cross-user as "not found" — no existence oracle.
		writeError(w, http.StatusNotFound, "device_not_found", "Device not found", "")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "revoke_failed", err.Error(), "")
		return
	}

	revokedAt, err := h.store.RevokeDevice(req.DeviceId)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "revoke_failed", err.Error(), "")
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
		writeError(w, http.StatusInternalServerError, "update_failed", err.Error(), "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// authBrowserHTML is the self-contained login page served by GET /auth/browser.
const authBrowserHTML = `<!DOCTYPE html>
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
      body: JSON.stringify({hostname: hostname})
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
</html>`

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
			log.Printf("AuthBrowser: template execute error: %v", err)
		}
		return
	}

	// Legacy self-host fallback: username form.
	w.Write([]byte(authBrowserHTML))
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
// Called by the browser auth page to bridge device-code flow completion.
// Credentials (user_id, device_id, token) are derived from the authenticated
// session — NOT from the request body — to prevent session-swap attacks.
func (h *Handler) CompleteDeviceCodeHTTP(w http.ResponseWriter, r *http.Request) {
	// RequireAuth sets these headers from the verified auth token.
	userID := r.Header.Get("X-User-ID")
	deviceID := r.Header.Get("X-Device-ID")
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

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
	if err := h.store.CompleteDeviceCode(req.UserCode, userID, deviceID, token); err != nil {
		writeError(w, http.StatusBadRequest, "complete_failed", err.Error(), "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "complete"})
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

	resp, err := h.store.CreateDeviceCode(hostname, machineID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "device_code_failed", err.Error(), "")
		return
	}

	// Build verification URI from BaseURL or derive from request
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
// Accepts JSON body: {"remote_retention_days": N} where N is 7-365.
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
		if strings.Contains(err.Error(), "between 7 and 365") {
			writeError(w, http.StatusBadRequest, "invalid_range",
				err.Error(), "Value must be between 7 and 365")
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

// RegisterRoutes registers all relay HTTP routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Only register the legacy auth/login endpoint when no OAuth providers are
	// configured. When OAuth is active, all accounts must be created via the
	// OAuth flow to preserve the identity audit trail (security finding 3).
	if h.OAuth == nil || (h.OAuth.GitHub == nil && h.OAuth.Google == nil) {
		mux.HandleFunc("POST /auth/login", h.AuthLogin)
	}
	mux.HandleFunc("GET /auth/browser", h.AuthBrowser)
	mux.HandleFunc("POST /auth/device-code", h.IssueDeviceCode)
	mux.HandleFunc("GET /auth/device-code/poll", h.PollDeviceCode)
	mux.HandleFunc("POST /auth/device-code/complete", h.RequireAuth(h.CompleteDeviceCodeHTTP))
	mux.HandleFunc("POST /auth/device/revoke", h.RequireAuth(h.RevokeDevice))
	mux.HandleFunc("POST /clips", h.DemoCORS(h.RequireAuth(h.PushClip)))
	mux.HandleFunc("OPTIONS /clips", h.DemoCORS(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("GET /clips", h.RequireAuth(h.ListClips))
	mux.HandleFunc("DELETE /clips/{id}", h.RequireAuth(h.DeleteClip))
	mux.HandleFunc("POST /pull", h.RequireAuth(h.PullClipboard))
	mux.HandleFunc("GET /clips/latest", h.RequireAuth(h.GetLatestClip))
	mux.HandleFunc("GET /devices", h.RequireAuth(h.ListDevices))
	mux.HandleFunc("PUT /devices/{id}/nickname", h.RequireAuth(h.SetDeviceNickname))
	mux.HandleFunc("PUT /devices/self/retention", h.RequireAuth(h.UpdateDeviceRetention))
	mux.HandleFunc("POST /auth/key-bundle", h.RequireAuth(h.PostKeyBundle))
	mux.HandleFunc("GET /auth/key-bundle", h.RequireAuth(h.GetKeyBundle))
	mux.HandleFunc("POST /auth/key-bundle/retry", h.RequireAuth(h.KeyBundleRetry))
	mux.HandleFunc("POST /auth/device/public-key", h.RequireAuth(h.RegisterDevicePublicKey))
	mux.HandleFunc("POST /clips/binary", h.RequireAuth(h.PushBinaryClip))
	mux.HandleFunc("GET /clips/{id}/media", h.RequireAuth(h.GetClipMedia))
	mux.HandleFunc("GET /ws", h.HandleWebSocket)
	mux.HandleFunc("POST /ws/ticket", h.RequireAuth(h.IssueWsTicket))
	mux.HandleFunc("GET /health", h.Health)

	// Demo session endpoints (CORS-enabled for landing page)
	mux.HandleFunc("POST /demo/session", h.DemoCORS(h.DemoSession))
	mux.HandleFunc("OPTIONS /demo/session", h.DemoCORS(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("GET /demo/stats", h.DemoCORS(h.DemoStats))
	mux.HandleFunc("OPTIONS /demo/stats", h.DemoCORS(func(w http.ResponseWriter, r *http.Request) {}))

	// Playground shared-session endpoints (CORS-enabled for /playground page)
	mux.HandleFunc("GET /demo/playground", h.DemoCORS(h.PlaygroundSession))
	mux.HandleFunc("OPTIONS /demo/playground", h.DemoCORS(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("POST /demo/playground/push", h.DemoCORS(h.PlaygroundPush))
	mux.HandleFunc("OPTIONS /demo/playground/push", h.DemoCORS(func(w http.ResponseWriter, r *http.Request) {}))
	mux.HandleFunc("GET /demo/stream/{sid}", h.DemoCORS(h.DemoStream))
	mux.HandleFunc("OPTIONS /demo/stream/{sid}", h.DemoCORS(func(w http.ResponseWriter, r *http.Request) {}))

	// OAuth sign-in routes (no-op when OAuth not configured; self-host falls back to username form)
	mux.HandleFunc("GET /auth/providers", h.GetProviders)
	mux.HandleFunc("GET /auth/oauth/github/start", h.OAuthStart("github"))
	mux.HandleFunc("GET /auth/oauth/github/callback", h.OAuthCallback("github"))
	mux.HandleFunc("GET /auth/oauth/google/start", h.OAuthStart("google"))
	mux.HandleFunc("GET /auth/oauth/google/callback", h.OAuthCallback("google"))

	// Anonymous opt-in telemetry (no auth; always 200 to client; silently dropped if backend not configured)
	mux.HandleFunc("POST /telemetry", h.HandleTelemetry)

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
}
