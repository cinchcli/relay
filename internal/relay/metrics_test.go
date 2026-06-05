package relay

import (
	"strings"
	"testing"
)

func TestAnonID(t *testing.T) {
	a := anonID("salt", "user-123")

	// Deterministic for the same salt + user (so count_uniq dedups correctly).
	if b := anonID("salt", "user-123"); a != b {
		t.Fatalf("anonID not deterministic: %s != %s", a, b)
	}
	// HMAC-SHA256 hex == 64 chars.
	if len(a) != 64 {
		t.Fatalf("expected 64 hex chars, got %d (%q)", len(a), a)
	}
	// Per-deployment salt: a different salt must change the output.
	if anonID("salt2", "user-123") == a {
		t.Fatal("salt change did not change anon_id")
	}
	// Different user must produce a different anon_id.
	if anonID("salt", "user-456") == a {
		t.Fatal("different user produced same anon_id")
	}
	// The raw user id must never appear in the anon id (non-reversible).
	if strings.Contains(a, "user-123") {
		t.Fatal("anon_id leaks raw user id")
	}
}

func TestActiveUserTrackerDailyDedup(t *testing.T) {
	tr := newActiveUserTracker()

	if !tr.firstSeenToday("a", "20260101") {
		t.Fatal("first sight of anon should be true")
	}
	if tr.firstSeenToday("a", "20260101") {
		t.Fatal("second sight of same anon same day should be false")
	}
	if !tr.firstSeenToday("b", "20260101") {
		t.Fatal("a different anon the same day should be true")
	}
	// A new UTC day resets the set.
	if !tr.firstSeenToday("a", "20260102") {
		t.Fatal("the same anon on a new day should be true again")
	}
}

// TestEmitUserActiveNoOpWithoutConfig guards the privacy/fail-safe contract: when
// the salt (or url/token) is unset, or the user is a demo session, nothing is
// emitted — and critically, we never fall back to sending a raw user id.
func TestEmitUserActiveNoOpWithoutConfig(t *testing.T) {
	// Salt unset -> disabled. If this enqueued a send it could leak a raw id;
	// firstSeenToday must NOT be consulted/recorded when disabled.
	h := &Handler{
		MetricsIngestURL:   "https://ingest.example",
		MetricsIngestToken: "tok",
		MetricsAnonSalt:    "", // unset: must disable, never raw fallback
		activeUsers:        newActiveUserTracker(),
	}
	h.emitUserActive("user-123", false)
	if len(h.activeUsers.seen) != 0 {
		t.Fatal("emit must be a no-op (and not record) when the anon salt is unset")
	}

	// Demo sessions are excluded even when fully configured.
	h2 := &Handler{
		MetricsIngestURL:   "https://ingest.example",
		MetricsIngestToken: "tok",
		MetricsAnonSalt:    "salt",
		activeUsers:        newActiveUserTracker(),
	}
	h2.emitUserActive("user-123", true) // isDemo
	if len(h2.activeUsers.seen) != 0 {
		t.Fatal("emit must be a no-op for demo sessions")
	}

	// Kill switch.
	h3 := &Handler{
		MetricsIngestURL:   "https://ingest.example",
		MetricsIngestToken: "tok",
		MetricsAnonSalt:    "salt",
		MetricsDisabled:    true,
		activeUsers:        newActiveUserTracker(),
	}
	h3.emitUserActive("user-123", false)
	if len(h3.activeUsers.seen) != 0 {
		t.Fatal("emit must be a no-op when MetricsDisabled is set")
	}
}

func TestMetricsUserAgent(t *testing.T) {
	// A named, non-browser User-Agent is required: Go's default
	// (Go-http-client/1.1) trips Cloudflare's bot challenge at the ingest edge.
	if got := (&Handler{}).metricsUserAgent(); got != "cinch-relay" {
		t.Fatalf("empty version: got %q, want cinch-relay", got)
	}
	if got := (&Handler{Version: "v0.4.1"}).metricsUserAgent(); got != "cinch-relay/v0.4.1" {
		t.Fatalf("with version: got %q, want cinch-relay/v0.4.1", got)
	}
}
