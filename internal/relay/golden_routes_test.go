package relay_test

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	cinchv1 "github.com/cinchcli/relay/internal/cinchv1"
	"github.com/cinchcli/relay/internal/cinchv1/cinchv1connect"
	"github.com/cinchcli/relay/internal/protocol"

	"connectrpc.com/connect"
)

// updateGolden regenerates the golden files instead of comparing against them.
// Run: go test ./internal/relay -run TestGoldenRoutes -update
var updateGolden = flag.Bool("update", false, "update golden route characterization files")

// Characterization (golden) tests freeze the current observable behavior of
// every registered HTTP route — {status, Content-Type, JSON body} — so the
// layered refactor can prove it changes nothing. Volatile values (ULIDs,
// random tokens, RFC3339 timestamps, device/user codes) are normalized to
// stable placeholders before comparison; only intentional behavior changes
// (the separately-committed security fixes) should ever require -update.
//
// Routes covered: all entries in Handler.RegisterRoutes. The previously
// untested holes called out in the refactor plan are exercised explicitly:
// POST /clips/{id}/pin (+ SendClipPinned fan-out), POST /telemetry,
// PUT /devices/{id}/nickname, the DevicesService and EventStreamService
// Connect RPCs.

var (
	ulidRe  = regexp.MustCompile(`[0-9A-HJKMNP-TV-Z]{26}`)
	hexRe   = regexp.MustCompile(`\b[0-9a-f]{32,64}\b`)
	tsRe    = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})`)
	codeRe  = regexp.MustCompile(`\b[A-Z0-9]{4}-[A-Z0-9]{4}\b`)
	epochRe = regexp.MustCompile(`"(requested_at|expires_at|expires_in|interval|interval_ms)":\s*\d+`)
	// The httptest server binds a random loopback port each run; normalize the
	// host:port so URL-bearing bodies (relay_url, ws_url, verification_uri) are
	// stable. Runs before the ULID pass so the port digits aren't mangled.
	hostRe = regexp.MustCompile(`(https?|wss?)://(?:127\.0\.0\.1|localhost|\[::1\]):\d+`)
)

// normalizeBody replaces volatile values with stable placeholders and
// pretty-prints JSON bodies so golden diffs are readable and order-stable.
func normalizeBody(contentType string, body []byte) string {
	s := string(body)
	if strings.Contains(contentType, "application/json") {
		var v any
		if err := json.Unmarshal(body, &v); err == nil {
			pretty, _ := json.MarshalIndent(v, "", "  ")
			s = string(pretty)
		}
	}
	s = hostRe.ReplaceAllString(s, "$1://<HOST>")
	s = ulidRe.ReplaceAllString(s, "<ULID>")
	s = codeRe.ReplaceAllString(s, "<CODE>")
	s = tsRe.ReplaceAllString(s, "<TS>")
	s = hexRe.ReplaceAllString(s, "<HEX>")
	s = epochRe.ReplaceAllString(s, `"$1": <NUM>`)
	return strings.TrimSpace(s)
}

type goldenResult struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        string `json:"body"`
}

func captureResp(t *testing.T, resp *http.Response) goldenResult {
	t.Helper()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	ct := resp.Header.Get("Content-Type")
	return goldenResult{
		Status:      resp.StatusCode,
		ContentType: ct,
		Body:        normalizeBody(ct, body),
	}
}

func compareGolden(t *testing.T, name string, got goldenResult) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name+".json")
	rendered, _ := json.MarshalIndent(got, "", "  ")
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir golden dir: %v", err)
		}
		if err := os.WriteFile(path, append(rendered, '\n'), 0o644); err != nil {
			t.Fatalf("write golden %s: %v", name, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run with -update to create): %v", name, err)
	}
	if strings.TrimSpace(string(want)) != strings.TrimSpace(string(rendered)) {
		t.Errorf("golden mismatch for %s:\n--- want ---\n%s\n--- got ---\n%s",
			name, want, rendered)
	}
}

// authed builds a request with the bearer token set.
func authedReq(t *testing.T, method, url, token string, body string) *http.Request {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

// firstDeviceID returns the calling token's own device id via GET /devices.
func firstDeviceID(t *testing.T, baseURL, token string) string {
	t.Helper()
	resp, err := http.DefaultClient.Do(authedReq(t, "GET", baseURL+"/devices", token, ""))
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	defer resp.Body.Close()
	var devices []struct {
		ID string `json:"id"`
	}
	json.NewDecoder(resp.Body).Decode(&devices)
	if len(devices) == 0 {
		t.Fatal("expected at least one device")
	}
	return devices[0].ID
}

func TestGoldenRoutes(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)
	clipID := pushClip(t, ts.URL, token, "golden clip")
	deviceID := firstDeviceID(t, ts.URL, token)

	// Each case names a golden file and produces one HTTP response. Cases use
	// deterministic inputs (missing/invalid args produce stable error
	// envelopes; success paths are normalized). Order-independent.
	cases := []struct {
		name string
		req  func() *http.Request
	}{
		// ── health / misc ──
		{"health", func() *http.Request { return authedReq(t, "GET", ts.URL+"/health", "", "") }},
		{"unknown_route", func() *http.Request { return authedReq(t, "GET", ts.URL+"/does-not-exist", "", "") }},

		// ── auth ──
		{"login_missing_invite", func() *http.Request {
			return authedReq(t, "POST", ts.URL+"/auth/login", "", `{"hostname":"h"}`)
		}},
		{"auth_browser_missing_code", func() *http.Request {
			return authedReq(t, "GET", ts.URL+"/auth/browser", "", "")
		}},
		{"device_code_start", func() *http.Request {
			return authedReq(t, "POST", ts.URL+"/auth/device-code", "", `{"hostname":"laptop"}`)
		}},
		{"device_code_poll_missing", func() *http.Request {
			return authedReq(t, "GET", ts.URL+"/auth/device-code/poll", "", "")
		}},
		{"device_code_poll_unknown", func() *http.Request {
			return authedReq(t, "GET", ts.URL+"/auth/device-code/poll?code=nope", "", "")
		}},
		{"device_code_complete_noauth", func() *http.Request {
			return authedReq(t, "POST", ts.URL+"/auth/device-code/complete", "", `{"user_code":"AAAA-BBBB"}`)
		}},
		{"device_code_complete_unknown_code", func() *http.Request {
			return authedReq(t, "POST", ts.URL+"/auth/device-code/complete", token, `{"user_code":"AAAA-BBBB"}`)
		}},
		{"display_name_empty", func() *http.Request {
			return authedReq(t, "POST", ts.URL+"/auth/display-name", token, `{"display_name":""}`)
		}},
		{"display_name_ok", func() *http.Request {
			return authedReq(t, "POST", ts.URL+"/auth/display-name", token, `{"display_name":"Ada"}`)
		}},
		{"providers", func() *http.Request { return authedReq(t, "GET", ts.URL+"/auth/providers", "", "") }},

		// ── key bundle ──
		{"key_bundle_get_empty", func() *http.Request {
			return authedReq(t, "GET", ts.URL+"/auth/key-bundle", token, "")
		}},
		{"key_bundle_post_missing", func() *http.Request {
			return authedReq(t, "POST", ts.URL+"/auth/key-bundle", token, `{}`)
		}},
		{"key_bundle_retry_no_key", func() *http.Request {
			return authedReq(t, "POST", ts.URL+"/auth/key-bundle/retry", token, `{}`)
		}},
		{"device_public_key_missing", func() *http.Request {
			return authedReq(t, "POST", ts.URL+"/auth/device/public-key", token, `{}`)
		}},

		// ── clips ──
		{"push_clip_empty", func() *http.Request {
			return authedReq(t, "POST", ts.URL+"/clips", token, `{"content":""}`)
		}},
		{"push_clip_unauth", func() *http.Request {
			return authedReq(t, "POST", ts.URL+"/clips", "bad", `{"content":"x"}`)
		}},
		{"list_clips", func() *http.Request { return authedReq(t, "GET", ts.URL+"/clips", token, "") }},
		{"list_clips_bad_limit", func() *http.Request {
			return authedReq(t, "GET", ts.URL+"/clips?limit=abc", token, "")
		}},
		{"latest_clip_mutually_exclusive", func() *http.Request {
			return authedReq(t, "GET", ts.URL+"/clips/latest?source=a&exclude_source=b", token, "")
		}},
		{"pin_clip_ok", func() *http.Request {
			return authedReq(t, "POST", ts.URL+"/clips/"+clipID+"/pin", token, `{"is_pinned":true}`)
		}},
		{"pin_clip_unknown", func() *http.Request {
			return authedReq(t, "POST", ts.URL+"/clips/01BAD/pin", token, `{"is_pinned":true}`)
		}},
		{"tombstones", func() *http.Request { return authedReq(t, "GET", ts.URL+"/tombstones", token, "") }},
		{"delete_clip_unknown", func() *http.Request {
			return authedReq(t, "DELETE", ts.URL+"/clips/01DOESNOTEXIST", token, "")
		}},
		{"clip_media_unknown", func() *http.Request {
			return authedReq(t, "GET", ts.URL+"/clips/01NOPE/media", token, "")
		}},

		// ── devices ──
		{"list_devices", func() *http.Request { return authedReq(t, "GET", ts.URL+"/devices", token, "") }},
		{"device_nickname_ok", func() *http.Request {
			return authedReq(t, "PUT", ts.URL+"/devices/"+deviceID+"/nickname", token, `{"nickname":"work-laptop"}`)
		}},
		{"device_nickname_too_long", func() *http.Request {
			return authedReq(t, "PUT", ts.URL+"/devices/"+deviceID+"/nickname", token,
				`{"nickname":"`+strings.Repeat("x", 200)+`"}`)
		}},
		{"device_retention_bad_range", func() *http.Request {
			return authedReq(t, "PUT", ts.URL+"/devices/self/retention", token, `{"retention_days":9999}`)
		}},
		{"device_revoke_missing_id", func() *http.Request {
			return authedReq(t, "POST", ts.URL+"/auth/device/revoke", token, `{}`)
		}},
		{"device_revoke_cross_user", func() *http.Request {
			return authedReq(t, "POST", ts.URL+"/auth/device/revoke", token, `{"device_id":"01OTHERUSERDEVICE0000000AA"}`)
		}},

		// ── ws ticket ──
		{"ws_ticket", func() *http.Request {
			return authedReq(t, "POST", ts.URL+"/ws/ticket", token, "")
		}},

		// ── telemetry (untested hole) ──
		{"telemetry_disabled", func() *http.Request {
			return authedReq(t, "POST", ts.URL+"/telemetry", token, `{"event":"test"}`)
		}},
		{"telemetry_otlp_disabled", func() *http.Request {
			return authedReq(t, "POST", ts.URL+"/telemetry/otlp", token,
				`{"anon_id":"abc","events":[{"name":"cli.command.completed","attrs":[]}]}`)
		}},

		// ── internal / admin ──
		{"internal_quota_disabled", func() *http.Request {
			return authedReq(t, "POST", ts.URL+"/internal/quota", "", `{"user_id":"x"}`)
		}},
		{"admin_invites_requires_admin_or_ok", func() *http.Request {
			return authedReq(t, "GET", ts.URL+"/admin/invites", token, "")
		}},
		{"admin_users", func() *http.Request {
			return authedReq(t, "GET", ts.URL+"/admin/users", token, "")
		}},

		// ── demo ──
		{"demo_session", func() *http.Request {
			return authedReq(t, "POST", ts.URL+"/demo/session", "", "")
		}},
		{"demo_stats", func() *http.Request {
			return authedReq(t, "GET", ts.URL+"/demo/stats", "", "")
		}},
	}

	seen := map[string]bool{}
	for _, tc := range cases {
		if seen[tc.name] {
			t.Fatalf("duplicate golden case name %q", tc.name)
		}
		seen[tc.name] = true
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.DefaultClient.Do(tc.req())
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			compareGolden(t, tc.name, captureResp(t, resp))
		})
	}
}

// TestGoldenConnectRPC covers the Connect-RPC holes the plan named:
// DevicesService.ListDevices (connect_devices) and EventStreamService.Subscribe
// (connect_events), plus an unauthenticated ListDevices to pin its error code.
func TestGoldenConnectRPC(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	authInterceptor := connect.WithInterceptors(
		connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
			return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
				req.Header().Set("Authorization", "Bearer "+token)
				return next(ctx, req)
			}
		}),
	)

	t.Run("devices_list_authed", func(t *testing.T) {
		client := cinchv1connect.NewDevicesServiceClient(http.DefaultClient, ts.URL, authInterceptor)
		resp, err := client.ListDevices(context.Background(), connect.NewRequest(&cinchv1.ListDevicesRequest{}))
		if err != nil {
			t.Fatalf("ListDevices: %v", err)
		}
		if len(resp.Msg.Devices) == 0 {
			t.Fatal("expected at least one device from authed ListDevices")
		}
	})

	t.Run("devices_list_unauth", func(t *testing.T) {
		client := cinchv1connect.NewDevicesServiceClient(http.DefaultClient, ts.URL)
		_, err := client.ListDevices(context.Background(), connect.NewRequest(&cinchv1.ListDevicesRequest{}))
		if err == nil {
			t.Fatal("expected unauthenticated ListDevices to fail")
		}
		if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
			t.Errorf("expected CodeUnauthenticated, got %v", got)
		}
	})

	t.Run("events_subscribe_unauth", func(t *testing.T) {
		client := cinchv1connect.NewEventStreamServiceClient(http.DefaultClient, ts.URL)
		stream, err := client.Subscribe(context.Background(), connect.NewRequest(&cinchv1.SubscribeRequest{}))
		if err == nil {
			// Streaming errors may surface on first Receive rather than open.
			stream.Receive()
			err = stream.Err()
			_ = stream.Close()
		}
		if err == nil {
			t.Fatal("expected unauthenticated Subscribe to fail")
		}
	})
}

// TestSendClipPinnedFanout covers the SendClipPinned hub broadcast triggered by
// POST /clips/{id}/pin — a path the plan flagged as untested. A connected WS
// agent must receive a clip_pinned frame after the owner pins a clip.
func TestSendClipPinnedFanout(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)
	clipID := pushClip(t, ts.URL, token, "to be pinned")

	conn := connectFakeAgent(t, ts.URL, token)

	pinBody := `{"is_pinned":true,"pin_note":"keep"}`
	resp, err := http.DefaultClient.Do(authedReq(t, "POST", ts.URL+"/clips/"+clipID+"/pin", token, pinBody))
	if err != nil {
		t.Fatalf("pin clip: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pin returned %d", resp.StatusCode)
	}

	// Drain frames until the clip_pinned event arrives or we time out. The
	// agent may also receive heartbeat/key-exchange frames first.
	deadline := time.Now().Add(3 * time.Second)
	conn.SetReadDeadline(deadline)
	for {
		var msg protocol.WSMessage
		if err := conn.ReadJSON(&msg); err != nil {
			t.Fatalf("did not receive clip_pinned frame before timeout: %v", err)
		}
		if msg.Action == protocol.ActionClipPinned {
			if msg.Clip == nil || msg.Clip.ClipId != clipID || !msg.Clip.IsPinned {
				t.Fatalf("unexpected clip_pinned payload: %+v", msg)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for clip_pinned frame")
		}
	}
}
