package relay

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// telemetryPayload is what the CLI sends to POST /telemetry.
type telemetryPayload struct {
	Event      string         `json:"event"`
	Properties map[string]any `json:"properties"`
}

// telemetryForwardBody is what gets forwarded to telemetry.jinmu.me.
type telemetryForwardBody struct {
	App        string         `json:"app"`
	Event      string         `json:"event"`
	Properties map[string]any `json:"properties"`
}

// allowedTelemetryEvents is the set of events the relay will forward.
// Any other event is acknowledged and silently dropped.
var allowedTelemetryEvents = map[string]bool{
	"tthw":       true,
	"push.first": true,
}

// HandleTelemetry accepts anonymous opt-in events from the CLI and proxies
// them to the configured telemetry backend. If TELEMETRY_URL / TELEMETRY_API_KEY
// are not set the request is acknowledged and silently dropped — self-hosters
// who skip telemetry config don't see errors.
func (h *Handler) HandleTelemetry(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > 4096 {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}

	var payload telemetryPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.Event == "" {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	// Always 200 to the client — we never want telemetry to block the user.
	w.WriteHeader(http.StatusOK)

	if h.TelemetryURL == "" || h.TelemetryAPIKey == "" {
		return
	}

	if !allowedTelemetryEvents[payload.Event] {
		return
	}

	// Rate-limit: 5 events per IP per hour.
	ip := realIP(r)
	if !h.telemetryLimiter.allow(ip) {
		return
	}

	go h.forwardTelemetry(payload)
}

func (h *Handler) forwardTelemetry(payload telemetryPayload) {
	body, err := json.Marshal(telemetryForwardBody{
		App:        "cinch",
		Event:      payload.Event,
		Properties: payload.Properties,
	})
	if err != nil {
		return
	}

	req, err := http.NewRequest(http.MethodPost, h.TelemetryURL+"/v1/events", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", h.TelemetryAPIKey)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// realIP extracts the client IP, respecting CF-Connecting-IP when behind Cloudflare.
func realIP(r *http.Request) string {
	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
		return cf
	}
	return r.RemoteAddr
}

// rateLimiter counts requests per key within a sliding window.
type rateLimiter struct {
	mu     sync.Mutex
	counts map[string][]time.Time
	limit  int
	window time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		counts: make(map[string][]time.Time),
		limit:  limit,
		window: window,
	}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	ts := rl.counts[key]
	valid := ts[:0]
	for _, t := range ts {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	rl.counts[key] = valid

	if len(valid) >= rl.limit {
		return false
	}
	rl.counts[key] = append(rl.counts[key], now)
	return true
}
