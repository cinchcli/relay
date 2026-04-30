// HTTP-only DTOs that are not in `proto/cinch/v1`. The demo and
// playground responses, and the auth status snapshot, exist purely on the
// legacy REST surface and are unique to the relay — no Rust client
// consumes them, so they don't need cross-language type unification.

package protocol

import "time"

// AuthStatusResponse shows the current auth state for `GET /auth/status`.
type AuthStatusResponse struct {
	Authenticated bool   `json:"authenticated"`
	UserID        string `json:"user_id,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
}

// DemoSessionResponse is returned when a landing-page visitor requests a
// demo token via `POST /demo/session`.
type DemoSessionResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	RelayURL  string    `json:"relay_url"`
	WSURL     string    `json:"ws_url"`
	MaxClips  int       `json:"max_clips"`
	MaxBytes  int       `json:"max_bytes"`
	Region    string    `json:"region"`
}

// PlaygroundSessionResponse is returned by `GET /demo/playground`. All
// anonymous visitors share the same token + stream_id until the hourly
// reset; per-visitor limits are enforced by IP.
type PlaygroundSessionResponse struct {
	Token     string    `json:"token"`
	StreamID  string    `json:"stream_id"`
	ExpiresAt time.Time `json:"expires_at"`
	RelayURL  string    `json:"relay_url"`
	WSURL     string    `json:"ws_url"`
	Region    string    `json:"region"`
}

// DemoStatsResponse reports today's demo push counter for the UI.
type DemoStatsResponse struct {
	PushesToday int `json:"pushes_today"`
}
