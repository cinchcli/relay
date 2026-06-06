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

// fakeIngest spins an httptest server that captures forwarded OTLP bodies on a
// channel, so tests can wait for the fire-and-forget POST deterministically
// instead of racing on time.Sleep.
func fakeIngest(t *testing.T) (*httptest.Server, chan []byte) {
	t.Helper()
	bodies := make(chan []byte, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies <- b
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, bodies
}

// cliTelemetryHandler returns a handler wired to the given ingest URL with test
// secrets, plus a constructed CLI telemetry limiter (no Postgres required).
func cliTelemetryHandler(ingestURL string) *Handler {
	return &Handler{
		MetricsIngestURL:    ingestURL,
		MetricsIngestToken:  "tok",
		MetricsAnonSalt:     "salt",
		MetricsDisabled:     false,
		cliTelemetryLimiter: newSlidingWindowLimiter(600, time.Hour),
	}
}

// postOTLPBatch invokes the handler directly with a JSON batch body and returns
// the response recorder. ContentLength is set so the size guard sees a real value.
func postOTLPBatch(h *Handler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/telemetry/otlp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))
	rec := httptest.NewRecorder()
	h.HandleTelemetryOTLP(rec, req)
	return rec
}

// flattenCLIRecords decodes a forwarded OTLP body into the resource attrs plus one
// flat attr map per log record (CLI batches may carry multiple records, unlike the
// single-record relay.* path that flattenOTLP handles).
func flattenCLIRecords(t *testing.T, body []byte) (resource map[string]string, records []map[string]string) {
	t.Helper()
	var b otlpLogsBody
	if err := json.Unmarshal(body, &b); err != nil {
		t.Fatalf("bad OTLP body: %v (%s)", err, body)
	}
	if len(b.ResourceLogs) != 1 || len(b.ResourceLogs[0].ScopeLogs) != 1 {
		t.Fatalf("unexpected OTLP envelope shape: %s", body)
	}
	resource = map[string]string{}
	for _, a := range b.ResourceLogs[0].Resource.Attributes {
		resource[a.Key] = a.Value.StringValue
	}
	for _, rec := range b.ResourceLogs[0].ScopeLogs[0].LogRecords {
		m := map[string]string{}
		for _, a := range rec.Attributes {
			m[a.Key] = a.Value.StringValue
		}
		records = append(records, m)
	}
	return
}

// recvBody waits for one forwarded POST or fails after a timeout.
func recvBody(t *testing.T, bodies chan []byte) []byte {
	t.Helper()
	select {
	case b := <-bodies:
		return b
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for telemetry POST")
		return nil
	}
}

// expectNoBody asserts no POST is forwarded within a short window.
func expectNoBody(t *testing.T, bodies chan []byte) {
	t.Helper()
	select {
	case b := <-bodies:
		t.Fatalf("unexpected forwarded POST: %s", b)
	case <-time.After(250 * time.Millisecond):
	}
}

// TestTelemetryOTLPForwardShape covers the happy path: a well-formed batch returns
// 200, forwards a service.name=cinch-cli OTLP body, every record carries the
// reserved event + anon_id attrs, anon_id is the HMAC of the raw UUID, and the raw
// UUID appears nowhere in the forwarded bytes.
func TestTelemetryOTLPForwardShape(t *testing.T) {
	srv, bodies := fakeIngest(t)
	h := cliTelemetryHandler(srv.URL)

	const rawUUID = "0190c0de-cafe-7000-8000-abcdef012345"
	body := `{"anon_id":"` + rawUUID + `","events":[` +
		`{"name":"cli.command.completed","attrs":[{"k":"command","v":"send"},{"k":"success","v":"true"}]},` +
		`{"name":"cli.send.completed","attrs":[{"k":"bytes","v":"42"}]}` +
		`]}`

	rec := postOTLPBatch(h, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	raw := recvBody(t, bodies)
	resource, records := flattenCLIRecords(t, raw)
	if resource["service.name"] != "cinch-cli" {
		t.Fatalf("service.name must be cinch-cli, got %q", resource["service.name"])
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	wantAnon := hmacHex("salt", rawUUID)
	for _, r := range records {
		if r["event"] == "" {
			t.Fatalf("record missing event attr: %+v", r)
		}
		if r["anon_id"] != wantAnon {
			t.Fatalf("anon_id must be HMAC of raw uuid, got %q want %q", r["anon_id"], wantAnon)
		}
	}
	// The raw UUID must NEVER appear on the wire.
	if bytes.Contains(raw, []byte(rawUUID)) {
		t.Fatalf("raw anon_id leaked on the wire: %s", raw)
	}
	// Client attrs are preserved on the right records.
	if records[0]["command"] != "send" || records[0]["success"] != "true" {
		t.Fatalf("first record lost client attrs: %+v", records[0])
	}
	if records[1]["bytes"] != "42" {
		t.Fatalf("second record lost client attrs: %+v", records[1])
	}
}

// TestTelemetryOTLPAllowlist asserts a non-allowlisted event name is dropped while
// allowlisted ones in the same batch still forward.
func TestTelemetryOTLPAllowlist(t *testing.T) {
	srv, bodies := fakeIngest(t)
	h := cliTelemetryHandler(srv.URL)

	body := `{"anon_id":"u1","events":[` +
		`{"name":"evil.event","attrs":[{"k":"x","v":"y"}]},` +
		`{"name":"cli.command.invoked","attrs":[]}` +
		`]}`
	if rec := postOTLPBatch(h, body); rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	_, records := flattenCLIRecords(t, recvBody(t, bodies))
	if len(records) != 1 {
		t.Fatalf("expected only the allowlisted event to survive, got %d records", len(records))
	}
	if records[0]["event"] != "cli.command.invoked" {
		t.Fatalf("unexpected surviving event: %q", records[0]["event"])
	}
}

// TestTelemetryOTLPReservedAttrsCannotBeSpoofed asserts a client attr keyed "event"
// or "anon_id" is dropped, so a client cannot override the relay-set reserved attrs.
func TestTelemetryOTLPReservedAttrsCannotBeSpoofed(t *testing.T) {
	srv, bodies := fakeIngest(t)
	h := cliTelemetryHandler(srv.URL)

	body := `{"anon_id":"u1","events":[{"name":"cli.command.completed","attrs":[` +
		`{"k":"event","v":"spoofed"},{"k":"anon_id","v":"spoofed"},{"k":"command","v":"send"}` +
		`]}]}`
	if rec := postOTLPBatch(h, body); rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	_, records := flattenCLIRecords(t, recvBody(t, bodies))
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	r := records[0]
	if r["event"] != "cli.command.completed" {
		t.Fatalf("client spoofed the reserved event attr: %q", r["event"])
	}
	if r["anon_id"] != hmacHex("salt", "u1") {
		t.Fatalf("client spoofed the reserved anon_id attr: %q", r["anon_id"])
	}
	if r["command"] != "send" {
		t.Fatalf("legitimate client attr was dropped: %+v", r)
	}
}

// TestTelemetryOTLPOversize asserts a body whose ContentLength exceeds the cap is
// rejected with 413 and never forwarded.
func TestTelemetryOTLPOversize(t *testing.T) {
	srv, bodies := fakeIngest(t)
	h := cliTelemetryHandler(srv.URL)

	big := strings.Repeat("x", cliTelemetryMaxBytes+1)
	body := `{"anon_id":"u1","events":[{"name":"cli.command.completed","attrs":[{"k":"big","v":"` + big + `"}]}]}`
	rec := postOTLPBatch(h, body)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rec.Code)
	}
	expectNoBody(t, bodies)
}

// TestTelemetryOTLPNotConfigured asserts that when the ingest is not configured the
// handler still returns 200 and forwards nothing.
func TestTelemetryOTLPNotConfigured(t *testing.T) {
	srv, bodies := fakeIngest(t)
	h := cliTelemetryHandler(srv.URL)
	h.MetricsIngestURL = "" // unconfigured -> metricsConfigured() == false

	body := `{"anon_id":"u1","events":[{"name":"cli.command.completed","attrs":[]}]}`
	if rec := postOTLPBatch(h, body); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 even when ingest unconfigured, got %d", rec.Code)
	}
	expectNoBody(t, bodies)
}

// TestTelemetryOTLPSanitization asserts an over-long value is truncated to the cap
// and that more than the per-event attr cap is dropped.
func TestTelemetryOTLPSanitization(t *testing.T) {
	srv, bodies := fakeIngest(t)
	h := cliTelemetryHandler(srv.URL)

	longVal := strings.Repeat("v", cliTelemetryMaxValLen+50)
	var attrs []string
	attrs = append(attrs, `{"k":"long","v":"`+longVal+`"}`)
	// 20 extra attrs, more than the cap of 16.
	for i := 0; i < 20; i++ {
		attrs = append(attrs, `{"k":"k`+itoa(i)+`","v":"x"}`)
	}
	body := `{"anon_id":"u1","events":[{"name":"cli.command.completed","attrs":[` +
		strings.Join(attrs, ",") + `]}]}`

	if rec := postOTLPBatch(h, body); rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	_, records := flattenCLIRecords(t, recvBody(t, bodies))
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	r := records[0]
	if got := len(r["long"]); got != cliTelemetryMaxValLen {
		t.Fatalf("value not truncated to %d, got %d", cliTelemetryMaxValLen, got)
	}
	// Count client attrs (exclude the two reserved ones). At most cliTelemetryMaxAttrs.
	clientCount := 0
	for k := range r {
		if k != "event" && k != "anon_id" {
			clientCount++
		}
	}
	if clientCount > cliTelemetryMaxAttrs {
		t.Fatalf("client attrs not capped: got %d > %d", clientCount, cliTelemetryMaxAttrs)
	}
}

// TestTelemetryOTLPAlwaysOK asserts a well-formed batch always yields 200.
func TestTelemetryOTLPAlwaysOK(t *testing.T) {
	srv, bodies := fakeIngest(t)
	h := cliTelemetryHandler(srv.URL)
	body := `{"anon_id":"u1","events":[{"name":"mcp.session.completed","attrs":[{"k":"tools","v":"3"}]}]}`
	if rec := postOTLPBatch(h, body); rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	// Drain the forwarded body so the goroutine completes cleanly.
	recvBody(t, bodies)
}

// TestTelemetryOTLPServiceNamePerSurface asserts the top-level app field selects
// the OTLP service.name: "desktop" -> cinch-desktop, an unknown/empty surface ->
// cinch-cli. This keeps CLI and desktop product events in distinct Grafana buckets.
func TestTelemetryOTLPServiceNamePerSurface(t *testing.T) {
	cases := []struct {
		app  string
		want string
	}{
		{"desktop", "cinch-desktop"},
		{"cli", "cinch-cli"},
		{"", "cinch-cli"},      // older client without the field
		{"bogus", "cinch-cli"}, // attacker-chosen surface collapses to the default
	}
	for _, tc := range cases {
		srv, bodies := fakeIngest(t)
		h := cliTelemetryHandler(srv.URL)
		body := `{"app":"` + tc.app + `","anon_id":"u1","events":[{"name":"cli.command.invoked","attrs":[]}]}`
		if rec := postOTLPBatch(h, body); rec.Code != http.StatusOK {
			t.Fatalf("app=%q: expected 200, got %d", tc.app, rec.Code)
		}
		resource, _ := flattenCLIRecords(t, recvBody(t, bodies))
		if resource["service.name"] != tc.want {
			t.Fatalf("app=%q: service.name = %q, want %q", tc.app, resource["service.name"], tc.want)
		}
	}
}

// TestTelemetryOTLPSaltUnsetDrops asserts that when the ingest URL and token are
// set but the anon salt is empty, the handler returns 200 and forwards nothing: an
// unset salt must always disable emission, never fall back to a raw identifier.
func TestTelemetryOTLPSaltUnsetDrops(t *testing.T) {
	srv, bodies := fakeIngest(t)
	h := cliTelemetryHandler(srv.URL)
	h.MetricsAnonSalt = "" // URL + token set, salt cleared -> metricsConfigured() == false

	body := `{"anon_id":"u1","events":[{"name":"cli.command.completed","attrs":[]}]}`
	if rec := postOTLPBatch(h, body); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 even when salt unset, got %d", rec.Code)
	}
	expectNoBody(t, bodies)
}

// TestTelemetryOTLPChunkedOversizeIsBounded asserts that a request which omits
// Content-Length (chunked: ContentLength == -1) cannot stream a body past the size
// cap. The Content-Length guard cannot see -1, but io.LimitReader truncates the
// read, so an oversized chunked body fails to decode and forwards nothing — it
// never buffers unbounded memory.
func TestTelemetryOTLPChunkedOversizeIsBounded(t *testing.T) {
	srv, bodies := fakeIngest(t)
	h := cliTelemetryHandler(srv.URL)

	big := strings.Repeat("x", cliTelemetryMaxBytes*2)
	body := `{"anon_id":"u1","events":[{"name":"cli.command.completed","attrs":[{"k":"big","v":"` + big + `"}]}]}`
	req := httptest.NewRequest(http.MethodPost, "/telemetry/otlp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = -1 // simulate chunked: the Content-Length guard cannot see the size
	rec := httptest.NewRecorder()
	h.HandleTelemetryOTLP(rec, req)

	// The truncated read yields invalid JSON -> 400, and nothing is forwarded.
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for truncated oversized chunked body, got %d", rec.Code)
	}
	expectNoBody(t, bodies)
}

// itoa is a tiny dependency-free int-to-string helper for building test attr keys.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
