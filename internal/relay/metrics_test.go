package relay

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	// anonID is a thin wrapper over the generic hmacHex primitive.
	if anonID("salt", "user-123") != hmacHex("salt", "user-123") {
		t.Fatal("anonID must equal hmacHex(salt, userID)")
	}
}

// TestHmacHexDistinct guards that clip_ref, device_ref and anon_id never collide
// for the loop-completion math: they are HMACs of different identifier spaces under
// one salt, so the same salt must map different inputs to different refs.
func TestHmacHexDistinct(t *testing.T) {
	clipRef := hmacHex("salt", "clip-X")
	deviceRef := hmacHex("salt", "dev-A")
	if len(clipRef) != 64 || len(deviceRef) != 64 {
		t.Fatalf("expected 64 hex chars")
	}
	if clipRef == deviceRef {
		t.Fatal("distinct ids must produce distinct refs under the same salt")
	}
	if hmacHex("salt", "clip-X") != clipRef {
		t.Fatal("hmacHex not deterministic")
	}
}

func TestDailySeenSetDedup(t *testing.T) {
	tr := newDailySeenSet()

	if !tr.firstSeenToday("a", "20260101") {
		t.Fatal("first sight of key should be true")
	}
	if tr.firstSeenToday("a", "20260101") {
		t.Fatal("second sight of same key same day should be false")
	}
	if !tr.firstSeenToday("b", "20260101") {
		t.Fatal("a different key the same day should be true")
	}
	// A new UTC day resets the set.
	if !tr.firstSeenToday("a", "20260102") {
		t.Fatal("the same key on a new day should be true again")
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
		activeUsers:        newDailySeenSet(),
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
		activeUsers:        newDailySeenSet(),
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
		activeUsers:        newDailySeenSet(),
	}
	h3.emitUserActive("user-123", false)
	if len(h3.activeUsers.seen) != 0 {
		t.Fatal("emit must be a no-op when MetricsDisabled is set")
	}
}

// TestEmitClipEventNoOpWithoutConfig guards the same fail-safe contract for the
// clip events: any missing precondition must short-circuit BEFORE recording, so a
// raw id can never leak and a disabled relay never tracks state.
func TestEmitClipEventNoOpWithoutConfig(t *testing.T) {
	cfg := func() *Handler {
		return &Handler{
			MetricsIngestURL:   "https://ingest.example",
			MetricsIngestToken: "tok",
			MetricsAnonSalt:    "salt",
			clipEvents:         newDailySeenSet(),
		}
	}
	cases := []struct {
		name string
		call func(h *Handler)
		h    *Handler
	}{
		{"salt unset", func(h *Handler) { h.emitClipSend("user", "dev", "clip", false) },
			&Handler{MetricsIngestURL: "u", MetricsIngestToken: "t", clipEvents: newDailySeenSet()}},
		{"demo", func(h *Handler) { h.emitClipRead("user", "dev", "clip", true) }, cfg()},
		{"empty user", func(h *Handler) { h.emitClipSend("", "dev", "clip", false) }, cfg()},
		{"empty clip", func(h *Handler) { h.emitClipRead("user", "dev", "", false) }, cfg()},
		// An unattributable read (no reader device) must drop, never emit a blank
		// device_ref that could falsely satisfy count_uniq(device_ref) >= 2.
		{"empty device", func(h *Handler) { h.emitClipRead("user", "", "clip", false) }, cfg()},
		{"disabled", func(h *Handler) {
			h.MetricsDisabled = true
			h.emitClipSend("user", "dev", "clip", false)
		}, cfg()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.call(tc.h)
			if len(tc.h.clipEvents.seen) != 0 {
				t.Fatalf("clip emit must be a no-op (and not record) for %q", tc.name)
			}
		})
	}
}

// TestClipEventsEndToEnd drives the full producer path through a fake ingest server
// and asserts: (1) the clip_send/clip_read wire shape and flat attributes the
// dashboard keys on; (2) refs are HMACs of the raw ids and raw ids never hit the
// wire; (3) a send + a cross-device read share clip_ref but differ in device_ref
// (the loop-completion signal); (4) a repeat same-device read is deduped.
func TestClipEventsEndToEnd(t *testing.T) {
	bodies := make(chan []byte, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got == "" || got == "Go-http-client/1.1" {
			t.Errorf("telemetry must set a named User-Agent, got %q", got)
		}
		b, _ := io.ReadAll(r.Body)
		bodies <- b
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	h := &Handler{
		MetricsIngestURL:   srv.URL,
		MetricsIngestToken: "tok",
		MetricsAnonSalt:    "salt",
		clipEvents:         newDailySeenSet(),
	}

	recv := func() (raw []byte, resource, attrs map[string]string) {
		t.Helper()
		select {
		case raw = <-bodies:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for telemetry POST")
		}
		resource, attrs = flattenOTLP(t, raw)
		return
	}

	// A clip is sent from device A.
	h.emitClipSend("user-1", "dev-A", "clip-X", false)
	sendRaw, sendRes, send := recv()
	if sendRes["service.name"] != "relay" {
		t.Fatalf("service.name must be relay, got %q", sendRes["service.name"])
	}
	if send["event"] != relayClipSendEvent || send["op"] != "send" {
		t.Fatalf("unexpected send event: %+v", send)
	}
	if send["anon_id"] != hmacHex("salt", "user-1") ||
		send["clip_ref"] != hmacHex("salt", "clip-X") ||
		send["device_ref"] != hmacHex("salt", "dev-A") {
		t.Fatalf("send refs must be HMAC of raw ids: %+v", send)
	}
	for _, rawID := range []string{"user-1", "dev-A", "clip-X"} {
		if bytes.Contains(sendRaw, []byte(rawID)) {
			t.Fatalf("raw id %q leaked on the wire: %s", rawID, sendRaw)
		}
	}

	// The same clip is read on a DIFFERENT device — the cross-machine completion.
	h.emitClipRead("user-1", "dev-B", "clip-X", false)
	_, _, read := recv()
	if read["event"] != relayClipReadEvent || read["op"] != "read" {
		t.Fatalf("unexpected read event: %+v", read)
	}
	if read["clip_ref"] != send["clip_ref"] {
		t.Fatal("clip_ref must match across send and read for the same clip")
	}
	if read["device_ref"] == send["device_ref"] {
		t.Fatal("a cross-device read must carry a different device_ref")
	}

	// A repeat read from the SAME device the same day must NOT emit again.
	h.emitClipRead("user-1", "dev-B", "clip-X", false)
	select {
	case b := <-bodies:
		t.Fatalf("duplicate same-device read must not emit: %s", b)
	case <-time.After(250 * time.Millisecond):
	}
}

// TestEmitClipSendAndDeliveries covers the push side of loop completion: one
// clip_send plus exactly one clip_read per device the hub delivered to over WS, all
// sharing the clip_ref. This is the fix for the legacy-WS coverage gap.
func TestEmitClipSendAndDeliveries(t *testing.T) {
	bodies := make(chan []byte, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies <- b
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	h := &Handler{
		MetricsIngestURL:   srv.URL,
		MetricsIngestToken: "tok",
		MetricsAnonSalt:    "salt",
		clipEvents:         newDailySeenSet(),
	}

	// Sender dev-A pushes clip-X; the hub delivered it to dev-A (itself), dev-B, dev-C.
	h.emitClipSendAndDeliveries("user-1", "dev-A", "clip-X", false, []string{"dev-A", "dev-B", "dev-C"})

	// Expect 4 events total: 1 send + 3 reads.
	sends, reads := 0, 0
	readDeviceRefs := map[string]bool{}
	wantClipRef := hmacHex("salt", "clip-X")
	for i := 0; i < 4; i++ {
		var raw []byte
		select {
		case raw = <-bodies:
		case <-time.After(2 * time.Second):
			t.Fatalf("expected 4 telemetry POSTs, got %d", i)
		}
		_, attrs := flattenOTLP(t, raw)
		if attrs["clip_ref"] != wantClipRef {
			t.Fatalf("every event must share clip_ref, got %q", attrs["clip_ref"])
		}
		switch attrs["event"] {
		case relayClipSendEvent:
			sends++
			if attrs["device_ref"] != hmacHex("salt", "dev-A") {
				t.Fatalf("send device_ref must be the sender's")
			}
		case relayClipReadEvent:
			reads++
			readDeviceRefs[attrs["device_ref"]] = true
		default:
			t.Fatalf("unexpected event %q", attrs["event"])
		}
	}
	if sends != 1 || reads != 3 {
		t.Fatalf("want 1 send + 3 reads, got %d send + %d read", sends, reads)
	}
	for _, dev := range []string{"dev-A", "dev-B", "dev-C"} {
		if !readDeviceRefs[hmacHex("salt", dev)] {
			t.Fatalf("missing clip_read for delivered device %q", dev)
		}
	}
	// No extra events (e.g. a duplicate send) leaked.
	select {
	case b := <-bodies:
		t.Fatalf("unexpected extra event: %s", b)
	case <-time.After(150 * time.Millisecond):
	}
}

// flattenOTLP round-trips a captured request body through the same typed structs
// the producer marshals, returning the resource attributes and the single log
// record's flat attributes as maps.
func flattenOTLP(t *testing.T, body []byte) (resource, attrs map[string]string) {
	t.Helper()
	var b otlpLogsBody
	if err := json.Unmarshal(body, &b); err != nil {
		t.Fatalf("bad OTLP body: %v (%s)", err, body)
	}
	if len(b.ResourceLogs) != 1 || len(b.ResourceLogs[0].ScopeLogs) != 1 ||
		len(b.ResourceLogs[0].ScopeLogs[0].LogRecords) != 1 {
		t.Fatalf("unexpected OTLP envelope shape: %s", body)
	}
	resource = map[string]string{}
	for _, a := range b.ResourceLogs[0].Resource.Attributes {
		resource[a.Key] = a.Value.StringValue
	}
	attrs = map[string]string{}
	for _, a := range b.ResourceLogs[0].ScopeLogs[0].LogRecords[0].Attributes {
		attrs[a.Key] = a.Value.StringValue
	}
	return
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
