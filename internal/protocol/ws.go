// Package protocol holds the relay's hand-written wire types — the WS
// envelope and the demo/status DTOs that aren't represented in
// `proto/cinch/v1`. Everything that IS in the proto comes from
// `internal/gen/cinch/v1` directly; there is no more `github.com/cinchcli/protocol`
// module dependency.
package protocol

import cinchv1 "github.com/cinchcli/relay/internal/gen/cinch/v1"

// WSMessage is the envelope for all WebSocket communication.
//
// The shape is action + 8 optional siblings; structurally awkward as a
// proto oneof, so we keep it hand-written and carry a generated
// `*cinchv1.Clip` for the only sub-field that needs cross-language type
// fidelity. Migrating the WS envelope to `event_stream.proto`'s streaming
// oneof is tracked separately; that change would alter the WS wire format.
type WSMessage struct {
	Action string `json:"action"`

	// new_clip / clip_deleted (relay → agent) — full Clip payload.
	Clip *cinchv1.Clip `json:"clip,omitempty"`

	// send_clipboard request (relay → agent) and clipboard_content
	// response (agent → relay) — pull correlation ID.
	PullID string `json:"pull_id,omitempty"`

	// clipboard_content response body.
	Content string `json:"content,omitempty"`

	// Error frame.
	Error string `json:"error,omitempty"`

	// revoked (relay → agent) — reason why the device was revoked.
	Reason string `json:"reason,omitempty"`

	// token_rotated (relay → agent) — new per-device credentials after
	// lazy migration from the legacy single-master token.
	Token    string `json:"token,omitempty"`
	DeviceID string `json:"device_id,omitempty"`
	Hostname string `json:"hostname,omitempty"`

	// key_exchange_requested (relay → agent) — fingerprint of the new
	// device's public key for out-of-band verification before completing
	// the ECDH key exchange.
	DeviceKeyFingerprint string `json:"device_key_fingerprint,omitempty"`

	// device_code_pending (relay → desktop) — push-approval notification
	// for a remote machine that just initiated DeviceCodeStart.
	// Hostname (above) is reused to carry the requester's hostname.
	UserCode     string `json:"user_code,omitempty"`
	RequestedAt  int64  `json:"requested_at,omitempty"`  // unix seconds
	SourceRegion string `json:"source_region,omitempty"` // best-effort GeoIP, empty if unavailable
}

// WebSocket action constants.
const (
	ActionNewClip          = "new_clip"
	ActionClipDeleted      = "clip_deleted"
	ActionSendClipboard    = "send_clipboard"
	ActionClipboardContent = "clipboard_content"
	ActionPing             = "ping"
	ActionPong             = "pong"

	// Phase 2 — per-device token actions.
	ActionRevoked      = "revoked"
	ActionTokenRotated = "token_rotated"

	// Phase 4.5 — E2EE key exchange.
	ActionKeyExchangeRequested = "key_exchange_requested"

	// Pin sync — relay broadcasts pin state changes to all connected clients.
	ActionClipPinned = "clip_pinned"

	// Remote-login push approval (relay → desktop) — a CLI device-code
	// flow that resolved a user_hint to this user is awaiting approval.
	ActionDeviceCodePending = "device_code_pending"
)

// ContentType is the app-level enum for clip classification. The wire uses
// plain `string` (matching `cinchv1.Clip.ContentType`); this typed alias is
// kept so callers can write `protocol.ContentImage` instead of the raw
// "image" literal. Conversion between this and `string` is implicit.
type ContentType = string

const (
	ContentCode  ContentType = "code"
	ContentURL   ContentType = "url"
	ContentText  ContentType = "text"
	ContentImage ContentType = "image"
)
