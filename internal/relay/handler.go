package relay

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cinchcli/protocol"
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

var (
	ErrAgentOffline = errors.New("desktop agent is not connected")
	ErrAgentTimeout = errors.New("desktop agent did not respond in time")
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type Handler struct {
	store   *Store
	hub     *Hub
	BaseURL string // public base URL of the relay (for verification URIs)
}

func NewHandler(store *Store, hub *Hub) *Handler {
	return &Handler{store: store, hub: hub}
}

// RequireAuth wraps a handler with token authentication.
// Phase 2: checks per-device tokens (devices.token) first, then falls back to
// the master token (users.token) for backward compatibility with pre-Phase-2 clients.
func (h *Handler) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			writeError(w, http.StatusUnauthorized, "not authenticated", "No auth token provided", "Run: cinch auth login")
			return
		}

		// Phase 2: try per-device token lookup first.
		deviceID, revoked, derr := h.store.DeviceIDByToken(token)
		if derr == nil {
			// Token found in devices table.
			if revoked {
				writeError(w, http.StatusUnauthorized, "device_revoked",
					"This device was revoked", "Run: cinch auth login")
				return
			}
			// Resolve user from device row.
			userID, err := h.store.DeviceOwner(deviceID)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "invalid token", "Token is invalid or expired", "Run: cinch auth login")
				return
			}
			r.Header.Set("X-Device-ID", deviceID)
			r.Header.Set("X-User-ID", userID)
			// Opportunistic: close grace window early on first per-device-token use.
			go h.store.CloseGraceEarlyIfNeeded(userID)
			next(w, r)
			return
		}

		// Fall back to master token (users.token) — pre-Phase-2 clients and login machine.
		if derr != sql.ErrNoRows {
			log.Printf("DeviceIDByToken error: %v", derr)
		}

		userID, err := h.store.UserByToken(token)
		if err != nil {
			// Check if this was a demo token that expired (lookup without TTL filter)
			var expiredID string
			expErr := h.store.db.QueryRow("SELECT id FROM users WHERE token = ? AND is_demo = 1", token).Scan(&expiredID)
			if expErr == nil {
				writeError(w, http.StatusUnauthorized, "demo expired", "Demo session expired", "Refresh the page for a new session")
				return
			}
			writeError(w, http.StatusUnauthorized, "invalid token", "Token is invalid or expired", "Run: cinch auth login")
			return
		}

		r.Header.Set("X-User-ID", userID)
		next(w, r)
	}
}

// AuthLogin creates a new user account and returns tokens.
func (h *Handler) AuthLogin(w http.ResponseWriter, r *http.Request) {
	// Parse optional body — backward-compatible: empty body still works.
	var req protocol.AuthLoginRequest
	if r.Body != nil && r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	hostname := req.Hostname
	if hostname == "" {
		hostname = "unknown"
	}

	userID := ulid.Make().String()
	token := generateToken()
	pairToken := generatePairToken()

	if err := h.store.CreateUser(userID, token, pairToken); err != nil {
		writeError(w, http.StatusInternalServerError, "account creation failed", err.Error(), "")
		return
	}

	// D-05: login machine is a device too. Mint a device row with the same token.
	// The login device's token works via both users.token and devices.token lookups.
	deviceID := ulid.Make().String()
	if err := h.store.RegisterDeviceWithToken(userID, deviceID, hostname, token); err != nil {
		// Soft-fail: user is created, login token works via users.token.
		// Device row will be created lazily on first WS handshake.
		log.Printf("AuthLogin: RegisterDeviceWithToken failed for %s: %v", userID[:8], err)
		deviceID = ""
	} else {
		_, _ = h.store.db.Exec(
			`UPDATE users SET token_migrated_at = COALESCE(token_migrated_at, CURRENT_TIMESTAMP) WHERE id = ?`,
			userID,
		)
	}

	writeJSON(w, http.StatusOK, protocol.AuthLoginResponse{
		Token:     token,
		PairToken: pairToken,
		UserID:    userID,
		DeviceID:  deviceID,
	})
}

// AuthPair exchanges a pair token for a per-device auth token.
func (h *Handler) AuthPair(w http.ResponseWriter, r *http.Request) {
	var req protocol.AuthPairRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request", "Could not parse request body", "")
		return
	}

	if req.PairToken == "" {
		writeError(w, http.StatusBadRequest, "missing pair token", "pair_token is required", "Run: cinch auth login on your Mac to get a pair token")
		return
	}

	hostname := req.Hostname
	if hostname == "" {
		hostname = "unknown"
	}

	userID, deviceID, deviceToken, err := h.store.ConsumePairTokenMintDevice(req.PairToken, hostname)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "pairing failed", err.Error(),
			"Run: cinch auth login on your Mac to generate a new pair token")
		return
	}

	// Phase 4.5: store device public key for E2EE key exchange if provided.
	if req.DevicePublicKey != "" {
		// Compute fingerprint: SHA-256 of the raw public key bytes, first 8 bytes as hex.
		// Prefer the fingerprint sent by the CLI (req.DeviceKeyFingerprint); if absent,
		// compute it here from the base64url-decoded public key bytes.
		fingerprint := req.DeviceKeyFingerprint
		if fingerprint == "" {
			if rawPub, err := base64.RawURLEncoding.DecodeString(req.DevicePublicKey); err == nil {
				digest := sha256.Sum256(rawPub)
				fingerprint = hex.EncodeToString(digest[:8])
			}
		}
		if err := h.store.SetDevicePublicKey(deviceID, req.DevicePublicKey, fingerprint); err != nil {
			log.Printf("failed to store device public key: %v", err)
			// non-fatal — pairing still succeeds; key exchange will happen later
		}
		// Notify all online devices of this user that a new device needs the encryption key.
		// Include the fingerprint so the desktop can verify the public key out-of-band.
		h.hub.SendToUser(userID, protocol.WSMessage{
			Action:               protocol.ActionKeyExchangeRequested,
			DeviceID:             deviceID,
			Hostname:             hostname,
			DeviceKeyFingerprint: fingerprint,
		})
	}

	writeJSON(w, http.StatusOK, protocol.AuthPairResponse{
		Token:    deviceToken,
		UserID:   userID,
		DeviceID: deviceID,
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
// Returns 404 if the desktop has not yet completed the key exchange.
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
	if eph == "" || bundle == "" {
		writeError(w, http.StatusNotFound, "not_ready", "Key bundle not yet available", "Desktop must be online to complete key exchange")
		return
	}
	writeJSON(w, http.StatusOK, KeyBundleResponse{
		EphemeralPublicKey: eph,
		EncryptedBundle:    bundle,
	})
}

// PushClip receives a clip from the CLI and broadcasts to the agent.
func (h *Handler) PushClip(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")

	var req protocol.PushRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request", "Could not parse request body", "")
		return
	}

	if req.Content == "" {
		writeError(w, http.StatusBadRequest, "empty content", "No content to push", "Pipe content: echo 'text' | cinch push")
		return
	}

	// Targeted push — check online BEFORE SaveClip (per D-10: no clip saved if device offline)
	if req.TargetDeviceID != "" {
		if !h.hub.IsDeviceOnline(userID, req.TargetDeviceID) {
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
		if err := h.hub.SendToDevice(userID, req.TargetDeviceID, protocol.WSMessage{
			Action: protocol.ActionNewClip, Clip: clip,
		}); err != nil {
			log.Printf("SendToDevice failed after online check: %v", err)
		}
		writeJSON(w, http.StatusOK, protocol.PushResponse{
			ClipID: clip.ID, ByteSize: clip.ByteSize,
		})
		return
	}

	// Demo sessions are restricted to prevent abuse: text-only, 1KB, 5 clips.
	isDemo, _ := h.store.IsDemoUser(userID)
	if isDemo {
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

	if isDemo {
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

	writeJSON(w, http.StatusOK, protocol.PushResponse{
		ClipID:   clip.ID,
		ByteSize: clip.ByteSize,
	})
}

// ListClips returns recent clips for the authenticated user.
func (h *Handler) ListClips(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	clips, err := h.store.ListClips(userID, 50)
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

	if err := h.store.DeleteClip(userID, clipID); err != nil {
		writeError(w, http.StatusNotFound, "not found", err.Error(), "")
		return
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

	writeJSON(w, http.StatusOK, protocol.PullResponse{
		PullID:  pullID,
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
		d.Online = h.hub.IsDeviceOnline(userID, d.ID)
	}

	if devices == nil {
		devices = []*protocol.DeviceInfo{}
	}
	writeJSON(w, http.StatusOK, devices)
}

// HandleWebSocket upgrades the connection and registers the agent.
// Phase 2: checks per-device token (devices.token) first; falls back to master token
// (users.token) with lazy migration for pre-Phase-2 clients.
func (h *Handler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
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

	// Phase 2: try per-device token first.
	var userID string
	var deviceID string

	did, revoked, derr := h.store.DeviceIDByToken(token)
	if derr == nil {
		// Token is a per-device token.
		if revoked {
			http.Error(w, "device_revoked", http.StatusUnauthorized)
			return
		}
		deviceID = did
		uid, err := h.store.DeviceOwner(did)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		userID = uid
	} else if derr == sql.ErrNoRows {
		// Fall back to master token (users.token) — pre-Phase-2 or login-machine token
		// that hasn't been migrated to devices.token yet.
		uid, err := h.store.UserByToken(token)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		userID = uid
		// deviceID stays empty; lazy migration branch below will mint one.
	} else {
		log.Printf("DeviceIDByToken WS error: %v", derr)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ws upgrade failed: %v", err)
		return
	}

	if deviceID == "" {
		// Lazy migration: token is a master token with no devices.token row.
		// Mint a new device row + send token_rotated as the first WS message.
		hostname := r.URL.Query().Get("hostname")
		if hostname == "" {
			hostname = r.Header.Get("User-Agent")
		}
		if hostname == "" {
			hostname = "unknown"
		}
		newDeviceID := ulid.Make().String()
		newToken := generateToken()
		if err := h.store.RegisterDeviceWithToken(userID, newDeviceID, hostname, newToken); err != nil {
			log.Printf("lazy migration failed for user %s: %v", userID[:8], err)
			// Fallthrough: connect with empty deviceID; retry on next WS connect.
		} else {
			// Stamp token_migrated_at for the 7-day grace sweeper.
			_, _ = h.store.db.Exec(
				`UPDATE users SET token_migrated_at = COALESCE(token_migrated_at, CURRENT_TIMESTAMP) WHERE id = ?`,
				userID,
			)
			deviceID = newDeviceID
			// Send token_rotated BEFORE Register — first message the client sees post-upgrade.
			rotated := protocol.WSMessage{
				Action:   protocol.ActionTokenRotated,
				Token:    newToken,
				DeviceID: newDeviceID,
				Hostname: hostname,
			}
			if err := conn.WriteJSON(rotated); err != nil {
				log.Printf("token_rotated write failed: %v", err)
			}
		}
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
				DeviceID: d.ID,
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

	// Limit request body to 20MB
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

	// Determine file extension from MIME type
	exts, _ := mime.ExtensionsByType(contentType)
	ext := ".png"
	if len(exts) > 0 {
		ext = exts[0]
	}

	clipID := ulid.Make().String()
	filename := clipID + ext
	mediaPath := "media/" + filename
	fullPath := filepath.Join(h.store.MediaDir, filename)

	// Atomic write: write to temp file, then rename
	tmpFile, err := os.CreateTemp(h.store.MediaDir, "upload-*")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "save failed", "Could not create temp file", "")
		return
	}
	tmpPath := tmpFile.Name()

	n, err := io.Copy(tmpFile, file)
	tmpFile.Close()
	if err != nil {
		os.Remove(tmpPath)
		writeError(w, http.StatusInternalServerError, "save failed", "Could not write file", "")
		return
	}

	if err := os.Rename(tmpPath, fullPath); err != nil {
		os.Remove(tmpPath)
		writeError(w, http.StatusInternalServerError, "save failed", "Could not finalize file", "")
		return
	}

	// Build clip metadata
	source := r.FormValue("source")
	label := r.FormValue("label")

	req := &protocol.PushRequest{
		Content:     "",
		ContentType: protocol.ContentImage,
		Source:      source,
		Label:       label,
		MediaPath:   mediaPath,
		ByteSize:    int(n),
	}

	clip, err := h.store.SaveClip(userID, req)
	if err != nil {
		os.Remove(fullPath)
		writeError(w, http.StatusInternalServerError, "save failed", err.Error(), "")
		return
	}

	// Track media size and cleanup if over limit
	h.store.AddMediaBytes(n)
	const maxMediaBytes = 500 << 20 // 500MB
	h.store.CleanupMediaOverLimit(maxMediaBytes)

	// Update device activity
	if source != "" {
		if err := h.store.UpdateDeviceActivity(userID, source); err != nil {
			log.Printf("device activity update failed: %v", err)
		}
	}

	// Broadcast to desktop agent
	if err := h.hub.SendClip(userID, clip); err != nil {
		log.Printf("ws broadcast failed for %s: %v", userID, err)
	}

	writeJSON(w, http.StatusOK, protocol.PushResponse{
		ClipID:   clip.ID,
		ByteSize: clip.ByteSize,
	})
}

// GetClipMedia serves a media file for a clip.
func (h *Handler) GetClipMedia(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	clipID := r.PathValue("id")

	mediaPath, err := h.store.GetClipMediaPath(userID, clipID)
	if err != nil || mediaPath == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	fullPath := filepath.Join(h.store.MediaDir, filepath.Base(mediaPath))

	f, err := os.Open(fullPath)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer f.Close()

	// Set content type from extension
	ext := filepath.Ext(fullPath)
	ct := mime.TypeByExtension(ext)
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)

	stat, _ := f.Stat()
	http.ServeContent(w, r, filepath.Base(fullPath), stat.ModTime(), f)
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
	json.NewEncoder(w).Encode(protocol.ErrorResponse{
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

func generatePairToken() string {
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("%s-%s", hex.EncodeToString(b[:2]), hex.EncodeToString(b[2:]))
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
			data, _ := json.Marshal(map[string]any{
				"action": "demo_clip",
				"clip":   map[string]string{"content": content, "clip_id": ulid.Make().String()},
			})
			fmt.Fprintf(w, "data: %s\n\n", data)
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

// deriveRelayURL returns the public HTTPS URL of the relay (for the CLI curl command).
func deriveRelayURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

// deriveWSURL returns the WebSocket URL for the relay (wss:// in prod).
func deriveWSURL(r *http.Request) string {
	scheme := "wss"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		scheme = "ws"
	}
	return scheme + "://" + r.Host + "/ws"
}

// DemoCORS wraps a handler with CORS headers allowing the landing page origin.
func (h *Handler) DemoCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == demoAllowOrigin || origin == demoAllowOriginL {
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

	var req protocol.DeviceRevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request", "Could not parse request body", "")
		return
	}
	if req.DeviceID == "" {
		writeError(w, http.StatusBadRequest, "missing_device_id", "device_id is required", "")
		return
	}

	ownerID, err := h.store.DeviceOwner(req.DeviceID)
	if err == sql.ErrNoRows || ownerID != callerUserID {
		// Treat cross-user as "not found" — no existence oracle.
		writeError(w, http.StatusNotFound, "device_not_found", "Device not found", "")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "revoke_failed", err.Error(), "")
		return
	}

	revokedAt, err := h.store.RevokeDevice(req.DeviceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "revoke_failed", err.Error(), "")
		return
	}

	// Best-effort WS push to victim device. Do not block or surface errors —
	// the client-side 401 (device_revoked) is the authoritative signal.
	h.hub.SendToDevice(ownerID, req.DeviceID, protocol.WSMessage{
		Action: protocol.ActionRevoked,
		Reason: "revoked_by_user",
	})

	writeJSON(w, http.StatusOK, protocol.DeviceRevokeResponse{
		OK:        true,
		DeviceID:  req.DeviceID,
		RevokedAt: revokedAt,
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

// RegeneratePairToken mints a fresh pair token for the calling user so they can pair
// additional devices without re-running `auth login` (D-05).
func (h *Handler) RegeneratePairToken(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	newPairToken := generatePairToken()
	_, err := h.store.db.Exec(
		"UPDATE users SET pair_token = ? WHERE id = ?", newPairToken, userID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"pair_token_regenerate_failed", err.Error(), "")
		return
	}
	writeJSON(w, http.StatusOK, protocol.PairTokenRegenerateResponse{
		PairToken: newPairToken,
	})
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
          body: JSON.stringify({user_code: deviceCode, user_id: d.user_id, device_id: d.device_id, token: d.token})
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

// AuthBrowser serves a self-contained HTML login page.
// On success, redirects to cinch://auth/callback with token credentials.
// If ?device_code=XXXX-XXXX is present, also completes the device-code flow.
func (h *Handler) AuthBrowser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(authBrowserHTML))
}

// CompleteDeviceCodeHTTP is the HTTP handler for POST /auth/device-code/complete.
// Called by the browser auth page to bridge device-code flow completion.
func (h *Handler) CompleteDeviceCodeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserCode string `json:"user_code"`
		UserID   string `json:"user_id"`
		DeviceID string `json:"device_id"`
		Token    string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Could not parse request body", "")
		return
	}
	if req.UserCode == "" {
		writeError(w, http.StatusBadRequest, "missing_user_code", "user_code is required", "")
		return
	}
	if err := h.store.CompleteDeviceCode(req.UserCode, req.UserID, req.DeviceID, req.Token); err != nil {
		writeError(w, http.StatusBadRequest, "complete_failed", err.Error(), "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "complete"})
}

// IssueDeviceCode creates a new device code for CLI auth.
// POST /auth/device-code — no auth required (this IS the auth entry point).
func (h *Handler) IssueDeviceCode(w http.ResponseWriter, r *http.Request) {
	var req protocol.DeviceCodeRequest
	if r.Body != nil && r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	hostname := req.Hostname
	if hostname == "" {
		hostname = "unknown"
	}

	resp, err := h.store.CreateDeviceCode(hostname)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "device_code_failed", err.Error(), "")
		return
	}

	// Build verification URI from BaseURL or derive from request
	baseURL := h.BaseURL
	if baseURL == "" {
		baseURL = deriveRelayURL(r)
	}
	resp.VerificationURI = baseURL + "/auth/browser?device_code=" + resp.UserCode

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
	mux.HandleFunc("POST /auth/login", h.AuthLogin)
	mux.HandleFunc("POST /auth/pair", h.AuthPair)
	mux.HandleFunc("GET /auth/browser", h.AuthBrowser)
	mux.HandleFunc("POST /auth/device-code", h.IssueDeviceCode)
	mux.HandleFunc("GET /auth/device-code/poll", h.PollDeviceCode)
	mux.HandleFunc("POST /auth/device-code/complete", h.RequireAuth(h.CompleteDeviceCodeHTTP))
	mux.HandleFunc("POST /auth/device/revoke", h.RequireAuth(h.RevokeDevice))
	mux.HandleFunc("POST /auth/pair-token/new", h.RequireAuth(h.RegeneratePairToken))
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
	mux.HandleFunc("POST /clips/binary", h.RequireAuth(h.PushBinaryClip))
	mux.HandleFunc("GET /clips/{id}/media", h.RequireAuth(h.GetClipMedia))
	mux.HandleFunc("GET /ws", h.HandleWebSocket)
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
