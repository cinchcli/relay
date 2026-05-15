package relay_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cinchv1 "github.com/cinchcli/cinch-core/go/cinch/v1"
	"github.com/cinchcli/relay/internal/media"
	"github.com/cinchcli/relay/internal/protocol"
	relay "github.com/cinchcli/relay/internal/relay"
	"github.com/gorilla/websocket"
)

// setupTestServer creates a relay backed by the test PostgreSQL DB and returns the test server URL.
func setupTestServer(t *testing.T) (*httptest.Server, *relay.Hub) {
	t.Helper()

	store := relay.NewTestStore(t)

	hub := relay.NewHub()
	go hub.Run()

	handler := relay.NewHandler(store, hub)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	return ts, hub
}

// setupTestServerWithStore is like setupTestServer but also returns the Store so
// callers can configure per-user capabilities (e.g. rate limits) after setup.
func setupTestServerWithStore(t *testing.T) (*httptest.Server, *relay.Hub, *relay.Store) {
	t.Helper()

	store := relay.NewTestStore(t)

	hub := relay.NewHub()
	go hub.Run()

	handler := relay.NewHandler(store, hub)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	return ts, hub, store
}

// login creates a user + first device row and returns the device token,
// the (now-empty) pair token (kept in the signature for call-site
// compatibility — proto field is reserved), and the user_id.
func login(t *testing.T, baseURL string) (token, pairToken, userID string) {
	t.Helper()

	resp, err := http.Post(baseURL+"/auth/login", "application/json", nil)
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login returned %d", resp.StatusCode)
	}

	var loginResp cinchv1.LoginResponse
	json.NewDecoder(resp.Body).Decode(&loginResp)
	return loginResp.Token, "", loginResp.UserId
}

// connectFakeAgent connects a WebSocket client that acts as the desktop agent.
func connectFakeAgent(t *testing.T, baseURL, token string) *websocket.Conn {
	t.Helper()

	wsURL := strings.Replace(baseURL, "http://", "ws://", 1) + "/ws?token=" + token
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("ws connect failed: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return conn
}

func TestAuthLogin(t *testing.T) {
	ts, _ := setupTestServer(t)

	token, _, userID := login(t, ts.URL)

	if token == "" {
		t.Error("token is empty")
	}
	if userID == "" {
		t.Error("user ID is empty")
	}
}

// TestAuthLogin_Disabled_WhenOAuthConfigured verifies that POST /auth/login
// returns 403 when an OAuth provider is configured, preventing account
// creation outside the OAuth identity audit trail (security finding 3).
func TestAuthLogin_Disabled_WhenOAuthConfigured(t *testing.T) {
	ts, _ := setupOAuthTestServer(t, "some-subject", false)

	resp, err := http.Post(ts.URL+"/auth/login", "application/json",
		strings.NewReader(`{"hostname":"test-host"}`))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusMethodNotAllowed {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 403 or 405, got %d: %s", resp.StatusCode, body)
	}
}

// TestAuthLogin_Available_WhenNoOAuth verifies that POST /auth/login still
// works normally on a relay without any OAuth provider configured.
func TestAuthLogin_Available_WhenNoOAuth(t *testing.T) {
	ts, _ := setupTestServer(t)

	resp, err := http.Post(ts.URL+"/auth/login", "application/json",
		strings.NewReader(`{"hostname":"test-host"}`))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var loginResp cinchv1.LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if loginResp.Token == "" {
		t.Error("expected non-empty token when OAuth is not configured")
	}
}

// TestAuthPair / TestAuthPairInvalidToken removed — the /auth/pair
// endpoint and PairRequest/PairResponse messages were retired in the
// OAuth-only migration. Cross-device bootstrap is exercised by the
// integration smoke test (cinch pair via SSH).

func TestPushClip(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	// Push a clip
	reqBody, _ := json.Marshal(cinchv1.PushClipRequest{
		Content:   "hello from test",
		Source:    "remote:test-server",
		Encrypted: true,
	})
	req, _ := http.NewRequest("POST", ts.URL+"/clips", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("push request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("push returned %d", resp.StatusCode)
	}

	var pushResp cinchv1.PushClipResponse
	json.NewDecoder(resp.Body).Decode(&pushResp)

	if pushResp.ClipId == "" {
		t.Error("clip ID is empty")
	}
	if pushResp.ByteSize != int64(len("hello from test")) {
		t.Errorf("expected %d bytes, got %d", len("hello from test"), pushResp.ByteSize)
	}
}

func TestPushClipUnauthorized(t *testing.T) {
	ts, _ := setupTestServer(t)

	reqBody, _ := json.Marshal(cinchv1.PushClipRequest{Content: "test"})
	req, _ := http.NewRequest("POST", ts.URL+"/clips", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer invalid-token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestPushClipEmpty(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	reqBody, _ := json.Marshal(cinchv1.PushClipRequest{Content: ""})
	req, _ := http.NewRequest("POST", ts.URL+"/clips", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestPushClip_RejectsPlaintext(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	body, _ := json.Marshal(cinchv1.PushClipRequest{Content: "hi", Encrypted: false})
	req, _ := http.NewRequest("POST", ts.URL+"/clips", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", resp.StatusCode)
	}
	var errResp cinchv1.ErrorResponse
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp.Error != "encryption_required" {
		t.Errorf("want error=encryption_required, got %q", errResp.Error)
	}
}

func TestPushClip_AcceptsEncrypted(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	body, _ := json.Marshal(cinchv1.PushClipRequest{Content: "encrypted-content", Encrypted: true})
	req, _ := http.NewRequest("POST", ts.URL+"/clips", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestPushClip_DemoStillAllowsPlaintext(t *testing.T) {
	ts, _ := setupTestServer(t)
	sess := createDemoSession(t, ts.URL)

	body, _ := json.Marshal(cinchv1.PushClipRequest{Content: "demo-plaintext", Encrypted: false})
	req, _ := http.NewRequest("POST", ts.URL+"/clips", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sess.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestPushAndReceiveViaWebSocket(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	// Connect fake agent
	agent := connectFakeAgent(t, ts.URL, token)

	// Push a clip
	content := "E2E test: push → WS → agent"
	reqBody, _ := json.Marshal(cinchv1.PushClipRequest{
		Content:   content,
		Source:    "remote:ci-server",
		Encrypted: true,
	})
	req, _ := http.NewRequest("POST", ts.URL+"/clips", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("push failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("push returned %d", resp.StatusCode)
	}

	// Agent should receive the clip via WebSocket
	agent.SetReadDeadline(time.Now().Add(5 * time.Second))
	var msg protocol.WSMessage
	if err := agent.ReadJSON(&msg); err != nil {
		t.Fatalf("agent did not receive WS message: %v", err)
	}

	if msg.Action != protocol.ActionNewClip {
		t.Errorf("expected action %q, got %q", protocol.ActionNewClip, msg.Action)
	}
	if msg.Clip == nil {
		t.Fatal("clip is nil")
	}
	if msg.Clip.Content != content {
		t.Errorf("expected content %q, got %q", content, msg.Clip.Content)
	}
	if msg.Clip.Source != "remote:ci-server" {
		t.Errorf("expected source %q, got %q", "remote:ci-server", msg.Clip.Source)
	}
}

func TestPullClipboard(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	// Connect fake agent
	agent := connectFakeAgent(t, ts.URL, token)

	// Agent listens for pull requests and responds in a goroutine
	go func() {
		for {
			var msg protocol.WSMessage
			if err := agent.ReadJSON(&msg); err != nil {
				return
			}
			if msg.Action == protocol.ActionSendClipboard {
				agent.WriteJSON(protocol.WSMessage{
					Action:  protocol.ActionClipboardContent,
					PullID:  msg.PullID,
					Content: "clipboard content from Mac",
				})
			}
		}
	}()

	// Give the agent goroutine time to start
	time.Sleep(100 * time.Millisecond)

	// Pull request
	req, _ := http.NewRequest("POST", ts.URL+"/pull", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("pull request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pull returned %d", resp.StatusCode)
	}

	var pullResp cinchv1.PullResponse
	json.NewDecoder(resp.Body).Decode(&pullResp)

	if pullResp.Content != "clipboard content from Mac" {
		t.Errorf("expected clipboard content, got %q", pullResp.Content)
	}
	if pullResp.PullId == "" {
		t.Error("pull ID is empty")
	}
}

func TestPullAgentOffline(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	// No agent connected — pull should fail with 503
	req, _ := http.NewRequest("POST", ts.URL+"/pull", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("pull request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", resp.StatusCode)
	}
}

func TestListClips(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	// Push 3 clips
	for i := 0; i < 3; i++ {
		reqBody, _ := json.Marshal(cinchv1.PushClipRequest{
			Content:   fmt.Sprintf("clip %d", i),
			Encrypted: true,
		})
		req, _ := http.NewRequest("POST", ts.URL+"/clips", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
	}

	// List
	req, _ := http.NewRequest("GET", ts.URL+"/clips", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list request failed: %v", err)
	}
	defer resp.Body.Close()

	var clips []*cinchv1.Clip
	json.NewDecoder(resp.Body).Decode(&clips)

	if len(clips) != 3 {
		t.Errorf("expected 3 clips, got %d", len(clips))
	}

	// Should be ordered by created_at DESC
	if clips[0].Content != "clip 2" {
		t.Errorf("expected newest first, got %q", clips[0].Content)
	}
}

// TestListClips_ZeroLimit verifies that limit=0 is clamped to the default (50).
// This tests the bug fix where Limit: 0 (proto default when omitted) was passing
// 0 to the store's SQL LIMIT clause, returning zero rows instead of the default.
func TestListClips_ZeroLimit(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	// Push 3 clips
	for i := 0; i < 3; i++ {
		reqBody, _ := json.Marshal(cinchv1.PushClipRequest{
			Content:   fmt.Sprintf("clip %d", i),
			Encrypted: true,
		})
		req, _ := http.NewRequest("POST", ts.URL+"/clips", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
	}

	// List with explicit limit=0 (should be clamped to default 50)
	req, _ := http.NewRequest("GET", ts.URL+"/clips?limit=0", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list request with limit=0 failed: %v", err)
	}
	defer resp.Body.Close()

	var clips []*cinchv1.Clip
	json.NewDecoder(resp.Body).Decode(&clips)

	// Should return all 3 clips, not zero (which would indicate the bug is present)
	if len(clips) != 3 {
		t.Errorf("expected 3 clips with limit=0 (clamped to 50), got %d", len(clips))
	}
}

func TestDeleteClip(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	// Push a clip
	reqBody, _ := json.Marshal(cinchv1.PushClipRequest{Content: "to delete", Encrypted: true})
	pushReq, _ := http.NewRequest("POST", ts.URL+"/clips", bytes.NewReader(reqBody))
	pushReq.Header.Set("Content-Type", "application/json")
	pushReq.Header.Set("Authorization", "Bearer "+token)
	pushResp, _ := http.DefaultClient.Do(pushReq)
	var pr cinchv1.PushClipResponse
	json.NewDecoder(pushResp.Body).Decode(&pr)
	pushResp.Body.Close()

	// Delete it
	delReq, _ := http.NewRequest("DELETE", ts.URL+"/clips/"+pr.ClipId, nil)
	delReq.Header.Set("Authorization", "Bearer "+token)
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("delete request failed: %v", err)
	}
	delResp.Body.Close()

	if delResp.StatusCode != http.StatusNoContent {
		t.Errorf("expected 204, got %d", delResp.StatusCode)
	}

	// List should be empty
	listReq, _ := http.NewRequest("GET", ts.URL+"/clips", nil)
	listReq.Header.Set("Authorization", "Bearer "+token)
	listResp, _ := http.DefaultClient.Do(listReq)
	var clips []*cinchv1.Clip
	json.NewDecoder(listResp.Body).Decode(&clips)
	listResp.Body.Close()

	if len(clips) != 0 {
		t.Errorf("expected 0 clips after delete, got %d", len(clips))
	}
}

// setupTestServerWithDisk creates a relay backed by the test PostgreSQL DB (needed for media tests).
func setupTestServerWithDisk(t *testing.T) *httptest.Server {
	t.Helper()

	tmpDir := t.TempDir()

	store := relay.NewTestStore(t)

	mediaStore, err := media.NewLocalStore(filepath.Join(tmpDir, "media"))
	if err != nil {
		t.Fatalf("failed to create media store: %v", err)
	}

	hub := relay.NewHub()
	go hub.Run()

	handler := relay.NewHandler(store, hub)
	handler.SetMediaStore(mediaStore)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

// createTestPNG returns a minimal valid 1x1 PNG.
func createTestPNG() []byte {
	return []byte{
		0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, // PNG signature
		0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1
		0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
		0xde, 0x00, 0x00, 0x00, 0x0c, 0x49, 0x44, 0x41, // IDAT chunk
		0x54, 0x78, 0x9c, 0x63, 0xf8, 0x0f, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x05, 0x18, 0xd8, 0x4e, 0x00,
		0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, // IEND chunk
		0x42, 0x60, 0x82,
	}
}

func postBinary(t *testing.T, baseURL, token string, fileData []byte, contentType, source string) *http.Response {
	t.Helper()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, _ := w.CreateFormFile("file", "test.png")
	fw.Write(fileData)
	w.WriteField("content_type", contentType)
	w.WriteField("source", source)
	w.Close()

	req, _ := http.NewRequest("POST", baseURL+"/clips/binary", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("binary push failed: %v", err)
	}
	return resp
}

func TestPushBinaryClip(t *testing.T) {
	ts := setupTestServerWithDisk(t)
	token, _, _ := login(t, ts.URL)

	png := createTestPNG()
	resp := postBinary(t, ts.URL, token, png, "image/png", "remote:test")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("binary push returned %d: %s", resp.StatusCode, body)
	}

	var pr cinchv1.PushClipResponse
	json.NewDecoder(resp.Body).Decode(&pr)

	if pr.ClipId == "" {
		t.Error("clip ID is empty")
	}
	if pr.ByteSize != int64(len(png)) {
		t.Errorf("expected %d bytes, got %d", len(png), pr.ByteSize)
	}
}

func TestGetClipMedia(t *testing.T) {
	ts := setupTestServerWithDisk(t)
	token, _, _ := login(t, ts.URL)

	png := createTestPNG()
	resp := postBinary(t, ts.URL, token, png, "image/png", "remote:test")
	var pr cinchv1.PushClipResponse
	json.NewDecoder(resp.Body).Decode(&pr)
	resp.Body.Close()

	// Fetch media
	req, _ := http.NewRequest("GET", ts.URL+"/clips/"+pr.ClipId+"/media", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	mediaResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("media fetch failed: %v", err)
	}
	defer mediaResp.Body.Close()

	if mediaResp.StatusCode != http.StatusOK {
		t.Fatalf("media fetch returned %d", mediaResp.StatusCode)
	}

	ct := mediaResp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "image/png") {
		t.Errorf("expected image/png content type, got %q", ct)
	}

	body, _ := io.ReadAll(mediaResp.Body)
	if len(body) != len(png) {
		t.Errorf("expected %d bytes, got %d", len(png), len(body))
	}
}

func TestGetClipMediaUnauthorized(t *testing.T) {
	ts := setupTestServerWithDisk(t)
	token, _, _ := login(t, ts.URL)

	png := createTestPNG()
	resp := postBinary(t, ts.URL, token, png, "image/png", "remote:test")
	var pr cinchv1.PushClipResponse
	json.NewDecoder(resp.Body).Decode(&pr)
	resp.Body.Close()

	// Fetch without auth
	req, _ := http.NewRequest("GET", ts.URL+"/clips/"+pr.ClipId+"/media", nil)
	mediaResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer mediaResp.Body.Close()

	if mediaResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", mediaResp.StatusCode)
	}
}

func TestGetClipMedia404(t *testing.T) {
	ts := setupTestServerWithDisk(t)
	token, _, _ := login(t, ts.URL)

	req, _ := http.NewRequest("GET", ts.URL+"/clips/nonexistent/media", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestPushBinaryInvalidType(t *testing.T) {
	ts := setupTestServerWithDisk(t)
	token, _, _ := login(t, ts.URL)

	resp := postBinary(t, ts.URL, token, []byte("not an image"), "text/plain", "remote:test")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestPushBinaryTooLarge(t *testing.T) {
	ts := setupTestServerWithDisk(t)
	token, _, _ := login(t, ts.URL)

	// Create a 21MB payload
	bigData := make([]byte, 21*1024*1024)
	copy(bigData[:8], createTestPNG()[:8]) // PNG header to pass content type check

	resp := postBinary(t, ts.URL, token, bigData, "image/png", "remote:test")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d", resp.StatusCode)
	}
}

func TestBinaryClipAppearsInList(t *testing.T) {
	ts := setupTestServerWithDisk(t)
	token, _, _ := login(t, ts.URL)

	png := createTestPNG()
	resp := postBinary(t, ts.URL, token, png, "image/png", "remote:test")
	resp.Body.Close()

	// List clips
	req, _ := http.NewRequest("GET", ts.URL+"/clips", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	listResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list request failed: %v", err)
	}
	defer listResp.Body.Close()

	var clips []*cinchv1.Clip
	json.NewDecoder(listResp.Body).Decode(&clips)

	if len(clips) != 1 {
		t.Fatalf("expected 1 clip, got %d", len(clips))
	}
	if clips[0].ContentType != "image" {
		t.Errorf("expected content_type 'image', got %q", clips[0].ContentType)
	}
	if clips[0].MediaPath == nil || *clips[0].MediaPath == "" {
		t.Error("media_path is empty")
	}
	if clips[0].Content != "" {
		t.Errorf("expected empty content for image, got %q", clips[0].Content)
	}
}

func TestBinaryClipBroadcastViaWebSocket(t *testing.T) {
	ts := setupTestServerWithDisk(t)
	token, _, _ := login(t, ts.URL)

	agent := connectFakeAgent(t, ts.URL, token)

	png := createTestPNG()
	resp := postBinary(t, ts.URL, token, png, "image/png", "remote:ws-test")
	resp.Body.Close()

	// Agent should receive clip via WebSocket
	agent.SetReadDeadline(time.Now().Add(5 * time.Second))
	var msg protocol.WSMessage
	if err := agent.ReadJSON(&msg); err != nil {
		t.Fatalf("agent did not receive WS message: %v", err)
	}

	if msg.Action != protocol.ActionNewClip {
		t.Errorf("expected action %q, got %q", protocol.ActionNewClip, msg.Action)
	}
	if msg.Clip == nil {
		t.Fatal("clip is nil")
	}
	if msg.Clip.MediaPath == nil || *msg.Clip.MediaPath == "" {
		t.Error("media_path not broadcast via WebSocket")
	}
	if msg.Clip.ContentType != "image" {
		t.Errorf("expected content_type 'image', got %q", msg.Clip.ContentType)
	}
}

func TestGetLatestClipBySourceWithImage(t *testing.T) {
	ts := setupTestServerWithDisk(t)
	token, _, _ := login(t, ts.URL)

	png := createTestPNG()
	resp := postBinary(t, ts.URL, token, png, "image/png", "remote:img-server")
	resp.Body.Close()

	// Get latest from that source
	req, _ := http.NewRequest("GET", ts.URL+"/clips/latest?source=remote:img-server", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	latestResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("latest request failed: %v", err)
	}
	defer latestResp.Body.Close()

	if latestResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", latestResp.StatusCode)
	}

	var clip cinchv1.Clip
	json.NewDecoder(latestResp.Body).Decode(&clip)
	if clip.MediaPath == nil || *clip.MediaPath == "" {
		t.Error("media_path missing from GetLatestClipBySource")
	}
}

func TestTextPushStillWorksAfterBinary(t *testing.T) {
	// Regression: ensure text push via POST /clips still works
	ts := setupTestServerWithDisk(t)
	token, _, _ := login(t, ts.URL)

	// First push an image
	png := createTestPNG()
	imgResp := postBinary(t, ts.URL, token, png, "image/png", "remote:test")
	imgResp.Body.Close()

	// Then push text (should still work)
	reqBody, _ := json.Marshal(cinchv1.PushClipRequest{
		Content:   "text after image",
		Source:    "remote:test",
		Encrypted: true,
	})
	req, _ := http.NewRequest("POST", ts.URL+"/clips", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("text push failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("text push returned %d", resp.StatusCode)
	}

	var pr cinchv1.PushClipResponse
	json.NewDecoder(resp.Body).Decode(&pr)
	if pr.ByteSize != int64(len("text after image")) {
		t.Errorf("expected %d bytes, got %d", len("text after image"), pr.ByteSize)
	}
}

// ── Demo session tests ────────────────────────────────────────────

// createDemoSession hits POST /demo/session and returns the response.
func createDemoSession(t *testing.T, baseURL string) protocol.DemoSessionResponse {
	t.Helper()
	req, _ := http.NewRequest("POST", baseURL+"/demo/session", nil)
	req.Header.Set("Origin", "https://cinchcli.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("demo session request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("demo session returned %d", resp.StatusCode)
	}
	var out protocol.DemoSessionResponse
	json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func TestDemoSessionCreate(t *testing.T) {
	ts, _ := setupTestServer(t)

	sess := createDemoSession(t, ts.URL)

	if sess.Token == "" {
		t.Error("demo session returned empty token")
	}
	if sess.MaxClips != 5 {
		t.Errorf("expected MaxClips=5, got %d", sess.MaxClips)
	}
	if sess.MaxBytes != 1024 {
		t.Errorf("expected MaxBytes=1024, got %d", sess.MaxBytes)
	}
	if sess.ExpiresAt.Before(time.Now().UTC()) {
		t.Error("demo session expires_at is in the past")
	}
}

func TestDemoCORSHeaders(t *testing.T) {
	ts, _ := setupTestServer(t)

	req, _ := http.NewRequest("OPTIONS", ts.URL+"/demo/session", nil)
	req.Header.Set("Origin", "https://cinchcli.com")
	req.Header.Set("Access-Control-Request-Method", "POST")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("preflight failed: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://cinchcli.com" {
		t.Errorf("expected CORS origin to be allowed, got %q", got)
	}
}

func TestDemoCORSRejectsUnknownOrigin(t *testing.T) {
	ts, _ := setupTestServer(t)

	req, _ := http.NewRequest("POST", ts.URL+"/demo/session", nil)
	req.Header.Set("Origin", "https://evil.example.com")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("expected no CORS header for unknown origin, got %q", got)
	}
}

func TestDemoPushAndClipLimit(t *testing.T) {
	ts, _ := setupTestServer(t)
	sess := createDemoSession(t, ts.URL)

	push := func(content string) int {
		body, _ := json.Marshal(cinchv1.PushClipRequest{Content: content})
		req, _ := http.NewRequest("POST", ts.URL+"/clips", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+sess.Token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("push failed: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// First 5 pushes should succeed.
	for i := 0; i < 5; i++ {
		if code := push(fmt.Sprintf("clip %d", i)); code != http.StatusOK {
			t.Fatalf("push %d expected 200, got %d", i, code)
		}
	}
	// 6th should be rejected.
	if code := push("overflow"); code != http.StatusTooManyRequests {
		t.Errorf("6th push expected 429, got %d", code)
	}
}

func TestDemoPushSizeLimit(t *testing.T) {
	ts, _ := setupTestServer(t)
	sess := createDemoSession(t, ts.URL)

	// 1KB + 1 byte
	large := strings.Repeat("a", 1025)
	body, _ := json.Marshal(cinchv1.PushClipRequest{Content: large})
	req, _ := http.NewRequest("POST", ts.URL+"/clips", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sess.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("push failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d", resp.StatusCode)
	}
}

func TestDemoPullForbidden(t *testing.T) {
	ts, _ := setupTestServer(t)
	sess := createDemoSession(t, ts.URL)

	req, _ := http.NewRequest("POST", ts.URL+"/pull", nil)
	req.Header.Set("Authorization", "Bearer "+sess.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("pull failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 (demo read-only), got %d", resp.StatusCode)
	}
}

func TestDemoExpiredToken(t *testing.T) {
	store := relay.NewTestStore(t)

	hub := relay.NewHub()
	go hub.Run()
	handler := relay.NewHandler(store, hub)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	// Create a demo user, then backdate created_at to simulate expiry.
	userID := "01DEMOEXPIREDUSER000000000"
	token := "expired-demo-token"
	if err := store.CreateDemoUser(userID, token); err != nil {
		t.Fatalf("create demo: %v", err)
	}
	// Force expiry: bypass store API and update created_at directly via a new store on same file.
	// Since we're in-memory we can re-open with a PRAGMA-aware path — skip by testing the TTL SQL directly.
	_ = store.CleanupDemoSessions
	// Instead: validate that the SQL correctly filters expired users via UserByToken.
	// We piggyback on the fact that UserByToken rejects >10min old is_demo rows.
	// So insert a forcibly-aged row.
	if _, err := store.ExecForTest("UPDATE users SET created_at = NOW() - INTERVAL '11 minutes' WHERE id = $1", userID); err != nil {
		t.Fatalf("backdating failed: %v", err)
	}

	body, _ := json.Marshal(cinchv1.PushClipRequest{Content: "late"})
	req, _ := http.NewRequest("POST", ts.URL+"/clips", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("push failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired demo, got %d", resp.StatusCode)
	}
	var errResp cinchv1.ErrorResponse
	json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp.Error != "demo expired" {
		t.Errorf("expected 'demo expired' error, got %q", errResp.Error)
	}
}

func TestDemoCounterIncrement(t *testing.T) {
	ts, _ := setupTestServer(t)
	sess := createDemoSession(t, ts.URL)

	// Push once
	body, _ := json.Marshal(cinchv1.PushClipRequest{Content: "hello"})
	req, _ := http.NewRequest("POST", ts.URL+"/clips", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sess.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("push failed: %v", err)
	}
	resp.Body.Close()

	// Check stats
	statsResp, err := http.Get(ts.URL + "/demo/stats")
	if err != nil {
		t.Fatalf("stats request failed: %v", err)
	}
	defer statsResp.Body.Close()

	var stats protocol.DemoStatsResponse
	json.NewDecoder(statsResp.Body).Decode(&stats)

	if stats.PushesToday < 1 {
		t.Errorf("expected pushes_today >= 1, got %d", stats.PushesToday)
	}
}

func TestListClipsSince(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	pushClip := func(content string) {
		reqBody, _ := json.Marshal(cinchv1.PushClipRequest{
			Content:   content,
			Encrypted: true,
		})
		req, _ := http.NewRequest("POST", ts.URL+"/clips", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("push %q failed: %v", content, err)
		}
		resp.Body.Close()
	}

	// Push clip A, wait for a new second boundary, record midTS, wait again,
	// then push clips B and C. SQLite datetime() comparison operates at
	// second precision, so we need midTS and clip-B/C to be in different seconds.
	pushClip("clip-A")
	time.Sleep(1100 * time.Millisecond)
	midTS := time.Now().UTC().Truncate(time.Second)
	time.Sleep(1100 * time.Millisecond)
	pushClip("clip-B")
	pushClip("clip-C")
	time.Sleep(50 * time.Millisecond) // let writes settle

	// Request clips since midTS — expect only B and C, oldest-first.
	req, _ := http.NewRequest("GET", ts.URL+"/clips?since="+midTS.Format(time.RFC3339), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list since request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var clips []*cinchv1.Clip
	json.NewDecoder(resp.Body).Decode(&clips)

	if len(clips) != 2 {
		t.Fatalf("expected 2 clips after since filter, got %d", len(clips))
	}
	// Oldest-first ordering from ListClipsSince.
	if clips[0].Content != "clip-B" {
		t.Errorf("expected clips[0] = clip-B, got %q", clips[0].Content)
	}
	if clips[1].Content != "clip-C" {
		t.Errorf("expected clips[1] = clip-C, got %q", clips[1].Content)
	}

	// since=<invalid> should return 400.
	badReq, _ := http.NewRequest("GET", ts.URL+"/clips?since=not-a-date", nil)
	badReq.Header.Set("Authorization", "Bearer "+token)
	badResp, err := http.DefaultClient.Do(badReq)
	if err != nil {
		t.Fatalf("bad since request failed: %v", err)
	}
	badResp.Body.Close()
	if badResp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid since, got %d", badResp.StatusCode)
	}
}

// TestDeleteBroadcastsEvent verifies that deleting a clip via DELETE /clips/{id}
// broadcasts a clip_deleted WebSocket message to all connected devices of that user.
func TestDeleteBroadcastsEvent(t *testing.T) {
	ts, _ := setupTestServer(t)

	// One user with one connected agent.
	token, _, _ := login(t, ts.URL)
	agent := connectFakeAgent(t, ts.URL, token)

	// Push a clip.
	pushBody, _ := json.Marshal(cinchv1.PushClipRequest{
		Content:   "clip-to-delete",
		Source:    "remote:test-device",
		Encrypted: true,
	})
	pushReq, _ := http.NewRequest("POST", ts.URL+"/clips", bytes.NewReader(pushBody))
	pushReq.Header.Set("Content-Type", "application/json")
	pushReq.Header.Set("Authorization", "Bearer "+token)

	pushResp, err := http.DefaultClient.Do(pushReq)
	if err != nil {
		t.Fatalf("push request failed: %v", err)
	}
	defer pushResp.Body.Close()

	if pushResp.StatusCode != http.StatusOK {
		t.Fatalf("push returned %d", pushResp.StatusCode)
	}

	var pushResult cinchv1.PushClipResponse
	json.NewDecoder(pushResp.Body).Decode(&pushResult)
	clipID := pushResult.ClipId
	if clipID == "" {
		t.Fatal("clip ID is empty after push")
	}

	// Drain the new_clip broadcast so the next read sees only clip_deleted.
	agent.SetReadDeadline(time.Now().Add(3 * time.Second))
	var newClipMsg protocol.WSMessage
	if err := agent.ReadJSON(&newClipMsg); err != nil {
		t.Fatalf("agent did not receive new_clip broadcast: %v", err)
	}
	if newClipMsg.Action != protocol.ActionNewClip {
		t.Fatalf("expected new_clip, got %q", newClipMsg.Action)
	}

	// Delete the clip.
	delReq, _ := http.NewRequest("DELETE", ts.URL+"/clips/"+clipID, nil)
	delReq.Header.Set("Authorization", "Bearer "+token)

	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("delete request failed: %v", err)
	}
	delResp.Body.Close()

	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete returned %d, want 204", delResp.StatusCode)
	}

	// The agent should receive a clip_deleted message.
	agent.SetReadDeadline(time.Now().Add(3 * time.Second))
	var delMsg protocol.WSMessage
	if err := agent.ReadJSON(&delMsg); err != nil {
		t.Fatalf("agent did not receive clip_deleted message: %v", err)
	}

	if delMsg.Action != protocol.ActionClipDeleted {
		t.Errorf("expected action %q, got %q", protocol.ActionClipDeleted, delMsg.Action)
	}
	if delMsg.Clip == nil {
		t.Fatal("clip field is nil in clip_deleted message")
	}
	if delMsg.Clip.ClipId != clipID {
		t.Errorf("expected clip_id %q, got %q", clipID, delMsg.Clip.ClipId)
	}
}

// pushClip is a helper that pushes a clip and returns its clip_id.
func pushClip(t *testing.T, baseURL, token, content string) string {
	t.Helper()
	body, _ := json.Marshal(cinchv1.PushClipRequest{
		Content:   content,
		Source:    "remote:test",
		Encrypted: true,
	})
	req, _ := http.NewRequest("POST", baseURL+"/clips", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("push clip: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("push returned %d", resp.StatusCode)
	}
	var pr cinchv1.PushClipResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		t.Fatalf("decode push response: %v", err)
	}
	if pr.ClipId == "" {
		t.Fatal("push did not return a clip_id")
	}
	return pr.ClipId
}

// deleteClip is a helper that deletes a clip and asserts 204.
func deleteClip(t *testing.T, baseURL, token, clipID string) {
	t.Helper()
	req, _ := http.NewRequest("DELETE", baseURL+"/clips/"+clipID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete clip: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete returned %d, want 204", resp.StatusCode)
	}
}

// listTombstones queries GET /tombstones?since=<epoch> and returns the result.
func listTombstones(t *testing.T, baseURL, token string) []relay.Tombstone {
	t.Helper()
	since := time.Time{}.UTC().Format(time.RFC3339)
	req, _ := http.NewRequest("GET", baseURL+"/tombstones?since="+since, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list tombstones: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("tombstones returned %d: %s", resp.StatusCode, body)
	}
	var tombstones []relay.Tombstone
	if err := json.NewDecoder(resp.Body).Decode(&tombstones); err != nil {
		t.Fatalf("decode tombstones: %v", err)
	}
	return tombstones
}

// TestInsertTombstoneIdempotent verifies that inserting the same clip_id twice
// results in only one tombstone row (INSERT OR IGNORE semantics).
func TestInsertTombstoneIdempotent(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	clipID := pushClip(t, ts.URL, token, "idempotent test")
	deleteClip(t, ts.URL, token, clipID)

	tombstones := listTombstones(t, ts.URL, token)
	found := 0
	for _, tb := range tombstones {
		if tb.ClipID == clipID {
			found++
		}
	}
	if found != 1 {
		t.Errorf("expected exactly 1 tombstone for clip %q, got %d", clipID, found)
	}
}

// TestListTombstones pushes a clip, deletes it, and verifies the tombstone
// is returned from GET /tombstones?since=<epoch>.
func TestListTombstones(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	clipID := pushClip(t, ts.URL, token, "tombstone list test")
	deleteClip(t, ts.URL, token, clipID)

	tombstones := listTombstones(t, ts.URL, token)
	if len(tombstones) == 0 {
		t.Fatal("expected at least one tombstone, got none")
	}
	found := false
	for _, tb := range tombstones {
		if tb.ClipID == clipID {
			found = true
			if tb.DeletedAt == "" {
				t.Error("tombstone deleted_at is empty")
			}
		}
	}
	if !found {
		t.Errorf("tombstone for clip %q not found in response", clipID)
	}
}

// TestTombstoneSweep verifies that SweepTombstones removes tombstones older
// than the given threshold while leaving recent ones untouched.
func TestTombstoneSweep(t *testing.T) {
	store := relay.NewTestStore(t)

	userID := "sweep-user"
	if err := store.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Insert an old tombstone directly via the exported helper (simulating a
	// clip deleted 10 days ago).
	if err := store.InsertTombstoneAt(userID, "old-clip", time.Now().UTC().Add(-10*24*time.Hour)); err != nil {
		t.Fatalf("InsertTombstoneAt old: %v", err)
	}
	// Insert a recent tombstone (1 hour ago — within the 7-day window).
	if err := store.InsertTombstoneAt(userID, "new-clip", time.Now().UTC().Add(-1*time.Hour)); err != nil {
		t.Fatalf("InsertTombstoneAt new: %v", err)
	}

	// Sweep tombstones older than 7 days.
	n, err := store.SweepTombstones(7)
	if err != nil {
		t.Fatalf("SweepTombstones: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 tombstone swept, got %d", n)
	}

	// The recent tombstone must still be present.
	tombstones, err := store.ListTombstones(userID, time.Time{}, 100)
	if err != nil {
		t.Fatalf("ListTombstones: %v", err)
	}
	if len(tombstones) != 1 {
		t.Errorf("expected 1 remaining tombstone, got %d", len(tombstones))
	}
	if len(tombstones) > 0 && tombstones[0].ClipID != "new-clip" {
		t.Errorf("expected remaining tombstone clip_id %q, got %q", "new-clip", tombstones[0].ClipID)
	}
}

func TestUserCapabilities_DefaultUnlimited(t *testing.T) {
	store := relay.NewTestStore(t)
	userID := "no-caps-user"
	if err := store.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// A user with no capabilities row should return zero struct (unlimited).
	cap, err := store.GetUserCapabilities(userID)
	if err != nil {
		t.Fatalf("GetUserCapabilities: %v", err)
	}
	if cap.DeviceLimit != 0 || cap.RetentionDays != 0 || cap.RateLimit != 0 {
		t.Fatalf("expected all-zero capabilities for user without row, got %+v", cap)
	}
}

func TestUserCapabilities_UpsertAndRead(t *testing.T) {
	store := relay.NewTestStore(t)
	userID := "test-user-cap"
	if err := store.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	want := relay.UserCapabilities{
		UserID:        userID,
		DeviceLimit:   3,
		RetentionDays: 7,
		RateLimit:     100,
	}
	if err := store.UpsertUserCapabilities(want); err != nil {
		t.Fatalf("UpsertUserCapabilities: %v", err)
	}

	got, err := store.GetUserCapabilities(userID)
	if err != nil {
		t.Fatalf("GetUserCapabilities: %v", err)
	}
	if got.DeviceLimit != 3 || got.RetentionDays != 7 || got.RateLimit != 100 {
		t.Fatalf("unexpected capabilities: %+v", got)
	}
}

func TestDeviceLimit_BlocksNewDevice(t *testing.T) {
	store := relay.NewTestStore(t)

	// First OAuth login: creates user + device 1.
	userID, _, _, err := store.UpsertOAuthUser("github", "block-subject", "", false, "host1", "machine1")
	if err != nil {
		t.Fatalf("first login: %v", err)
	}

	// Set device_limit = 1 (user is now at the limit).
	if err := store.UpsertUserCapabilities(relay.UserCapabilities{
		UserID:      userID,
		DeviceLimit: 1,
	}); err != nil {
		t.Fatalf("UpsertUserCapabilities: %v", err)
	}

	// Second OAuth login with a NEW machine — same user (same github subject), different machineID.
	_, _, _, err = store.UpsertOAuthUser("github", "block-subject", "", false, "host2", "machine2")
	if err == nil {
		t.Fatal("expected device_limit_exceeded error, got nil")
	}
	if !strings.Contains(err.Error(), "device_limit_exceeded") {
		t.Fatalf("expected device_limit_exceeded in error, got: %v", err)
	}
}

func TestDeviceLimit_GracePeriodAllowsDevice(t *testing.T) {
	store := relay.NewTestStore(t)

	// First OAuth login: creates user + device 1.
	userID, _, _, err := store.UpsertOAuthUser("github", "grace-subject", "", false, "host1", "machine1")
	if err != nil {
		t.Fatalf("first login: %v", err)
	}

	// Set limit = 1 but grace expires in the future.
	if err := store.UpsertUserCapabilities(relay.UserCapabilities{
		UserID:         userID,
		DeviceLimit:    1,
		GraceExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("UpsertUserCapabilities: %v", err)
	}

	// Second device on new machine — should succeed because grace period is active.
	_, _, _, err = store.UpsertOAuthUser("github", "grace-subject", "", false, "host2", "machine2")
	if err != nil {
		t.Fatalf("expected success during grace period, got: %v", err)
	}
}

func TestDeviceLimit_ReauthAllowed(t *testing.T) {
	store := relay.NewTestStore(t)

	machineID := "same-machine-123"
	// First login on this machine: creates user + device.
	userID, _, _, err := store.UpsertOAuthUser("github", "reauth-subject", "", false, "my-mac", machineID)
	if err != nil {
		t.Fatalf("first login: %v", err)
	}

	// Set limit = 1 (exactly at the limit).
	if err := store.UpsertUserCapabilities(relay.UserCapabilities{
		UserID:      userID,
		DeviceLimit: 1,
	}); err != nil {
		t.Fatalf("UpsertUserCapabilities: %v", err)
	}

	// Re-auth from the SAME machine — should succeed (not a new device row).
	_, _, _, err = store.UpsertOAuthUser("github", "reauth-subject", "", false, "my-mac", machineID)
	if err != nil {
		t.Fatalf("re-auth from same machine should succeed, got: %v", err)
	}
}

func TestUpsertOAuthUser_SameProviderRelogin(t *testing.T) {
	store := relay.NewTestStore(t)

	uid1, _, _, err := store.UpsertOAuthUser("google", "google-sub-1", "alice@example.com", true, "mac", "m1")
	if err != nil {
		t.Fatalf("first login: %v", err)
	}
	uid2, _, _, err := store.UpsertOAuthUser("google", "google-sub-1", "alice@example.com", true, "mac", "m1")
	if err != nil {
		t.Fatalf("re-login: %v", err)
	}
	if uid1 != uid2 {
		t.Fatalf("same provider re-login produced different user_id: %s vs %s", uid1, uid2)
	}
}

func TestUpsertOAuthUser_CrossProviderVerifiedEmail(t *testing.T) {
	store := relay.NewTestStore(t)

	// First login via Google.
	googleUID, _, _, err := store.UpsertOAuthUser("google", "google-sub-2", "alice@example.com", true, "mac", "m1")
	if err != nil {
		t.Fatalf("google login: %v", err)
	}
	// Second login via GitHub with the same verified email → should link.
	githubUID, _, _, err := store.UpsertOAuthUser("github", "12345", "alice@example.com", true, "mac", "m2")
	if err != nil {
		t.Fatalf("github login: %v", err)
	}
	if googleUID != githubUID {
		t.Fatalf("cross-provider link failed: google_uid=%s github_uid=%s", googleUID, githubUID)
	}
}

func TestUpsertOAuthUser_CrossProviderUnverifiedEmail_NoLink(t *testing.T) {
	store := relay.NewTestStore(t)

	uid1, _, _, err := store.UpsertOAuthUser("google", "google-sub-3", "bob@example.com", true, "mac", "m1")
	if err != nil {
		t.Fatalf("google login: %v", err)
	}
	// GitHub login with same email but unverified → must NOT link.
	uid2, _, _, err := store.UpsertOAuthUser("github", "67890", "bob@example.com", false, "mac", "m2")
	if err != nil {
		t.Fatalf("github login: %v", err)
	}
	if uid1 == uid2 {
		t.Fatalf("unverified email should not link providers, but got same user_id: %s", uid1)
	}
}

func TestUpsertOAuthUser_EmailUpdate(t *testing.T) {
	store := relay.NewTestStore(t)

	uid1, _, _, err := store.UpsertOAuthUser("google", "google-sub-4", "old@example.com", true, "mac", "m1")
	if err != nil {
		t.Fatalf("first login: %v", err)
	}
	// Same provider+subject, but email changed at Google.
	uid2, _, _, err := store.UpsertOAuthUser("google", "google-sub-4", "new@example.com", true, "mac", "m1")
	if err != nil {
		t.Fatalf("email-update login: %v", err)
	}
	if uid1 != uid2 {
		t.Fatalf("email update should preserve user_id: %s vs %s", uid1, uid2)
	}
}

// ── Legacy-heal tests ────────────────────────────────────────────────────────
// These tests verify that UpsertOAuthUser claims (rather than duplicates) an
// existing device row that was created before machine_id support — i.e. rows
// with machine_id IS NULL and source_key = 'remote:unknown' (the desktop
// env-var fallback before the hostname normalization fix).

// TestUpsertOAuthUser_LegacyHeal_RemoteUnknown: a legacy row with
// machine_id=NULL and source_key='remote:unknown' must be claimed when a new
// login provides a real machine_id.  No second device row should appear.
func TestUpsertOAuthUser_LegacyHeal_RemoteUnknown(t *testing.T) {
	store := relay.NewTestStore(t)

	// Simulate a pre-fix desktop login: hostname="unknown", machineID="" (empty).
	userID, legacyDevID, _, err := store.UpsertOAuthUser("github", "heal-sub-1", "", false, "unknown", "")
	if err != nil {
		t.Fatalf("legacy login: %v", err)
	}

	// Now the fixed desktop (or CLI) re-logs in with the real hostname and machine_id.
	uid2, dev2, _, err := store.UpsertOAuthUser("github", "heal-sub-1", "", false, "my-mac", "machine-abc")
	if err != nil {
		t.Fatalf("healed login: %v", err)
	}
	if uid2 != userID {
		t.Fatalf("user_id changed after heal: was %s, got %s", userID, uid2)
	}
	if dev2 != legacyDevID {
		t.Fatalf("heal created a new device row instead of claiming the legacy one: legacy=%s new=%s", legacyDevID, dev2)
	}

	// Exactly one device row must exist for this user.
	var count int
	store.DB().QueryRow(`SELECT COUNT(*) FROM devices WHERE user_id = $1 AND revoked_at IS NULL`, userID).Scan(&count)
	if count != 1 {
		t.Fatalf("expected 1 device row after heal, got %d", count)
	}
}

// TestUpsertOAuthUser_LegacyHeal_SourceKeyUpdated: after the heal the device
// row's hostname and source_key must reflect the real host, not "unknown".
func TestUpsertOAuthUser_LegacyHeal_SourceKeyUpdated(t *testing.T) {
	store := relay.NewTestStore(t)

	_, devID, _, err := store.UpsertOAuthUser("github", "heal-sub-2", "", false, "unknown", "")
	if err != nil {
		t.Fatalf("legacy login: %v", err)
	}

	_, dev2, _, err := store.UpsertOAuthUser("github", "heal-sub-2", "", false, "real-host", "machine-xyz")
	if err != nil {
		t.Fatalf("healed login: %v", err)
	}
	if dev2 != devID {
		t.Fatalf("expected same device after heal, got new device %s", dev2)
	}

	var hostname, sourceKey string
	var machineID *string
	err = store.DB().QueryRow(
		`SELECT hostname, source_key, machine_id FROM devices WHERE id = $1`, devID,
	).Scan(&hostname, &sourceKey, &machineID)
	if err != nil {
		t.Fatalf("querying healed device: %v", err)
	}
	if hostname != "real-host" {
		t.Errorf("hostname not updated: got %q, want %q", hostname, "real-host")
	}
	if sourceKey != "remote:real-host" {
		t.Errorf("source_key not updated: got %q, want %q", sourceKey, "remote:real-host")
	}
	if machineID == nil || *machineID != "machine-xyz" {
		t.Errorf("machine_id not backfilled: got %v, want %q", machineID, "machine-xyz")
	}
}

// TestUpsertOAuthUser_LegacyHeal_NoCrossUserPollution: healing must never
// claim a NULL-machine_id row belonging to a different user.
func TestUpsertOAuthUser_LegacyHeal_NoCrossUserPollution(t *testing.T) {
	store := relay.NewTestStore(t)

	// User A has a legacy row.
	userA, devA, _, err := store.UpsertOAuthUser("github", "heal-sub-A", "", false, "unknown", "")
	if err != nil {
		t.Fatalf("user A legacy login: %v", err)
	}

	// User B logs in for the first time with a real machine_id.
	userB, devB, _, err := store.UpsertOAuthUser("github", "heal-sub-B", "", false, "real-host", "machine-xyz")
	if err != nil {
		t.Fatalf("user B first login: %v", err)
	}
	if userA == userB {
		t.Fatalf("test setup error: A and B got same user_id")
	}

	// User A's legacy device must not have been claimed by user B.
	var claimedBy string
	store.DB().QueryRow(`SELECT user_id FROM devices WHERE id = $1`, devA).Scan(&claimedBy)
	if claimedBy != userA {
		t.Errorf("user A's legacy device was stolen by user B: user_id=%s devA=%s devB=%s", claimedBy, devA, devB)
	}

	// User B must have its own distinct device row.
	if devA == devB {
		t.Fatalf("user B reused user A's device instead of creating its own")
	}
}

func TestRateLimit_BlocksAfterLimit(t *testing.T) {
	store := relay.NewTestStore(t)
	uid := "rate-user"
	if err := store.CreateUser(uid); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := store.UpsertUserCapabilities(relay.UserCapabilities{
		UserID:    uid,
		RateLimit: 2,
	}); err != nil {
		t.Fatalf("UpsertUserCapabilities: %v", err)
	}

	// Increment twice — both should be within limit.
	for i := 0; i < 2; i++ {
		count, err := store.IncrementDailyRequestCount(uid)
		if err != nil {
			t.Fatalf("increment %d: %v", i, err)
		}
		cap, _ := store.GetUserCapabilities(uid)
		if cap.RateLimit > 0 && count > cap.RateLimit {
			t.Fatalf("push %d blocked unexpectedly", i+1)
		}
	}

	// Third increment — count=3 exceeds limit=2.
	count, err := store.IncrementDailyRequestCount(uid)
	if err != nil {
		t.Fatalf("increment: %v", err)
	}
	cap, _ := store.GetUserCapabilities(uid)
	if cap.RateLimit == 0 || count <= cap.RateLimit {
		t.Fatalf("expected rate limit exceeded (count=%d limit=%d)", count, cap.RateLimit)
	}
}

func TestRateLimit_ZeroIsUnlimited(t *testing.T) {
	store := relay.NewTestStore(t)
	uid := "unlimited-user"
	if err := store.CreateUser(uid); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	// No capabilities row = rate_limit 0 = unlimited.
	cap, err := store.GetUserCapabilities(uid)
	if err != nil {
		t.Fatalf("GetUserCapabilities: %v", err)
	}
	if cap.RateLimit != 0 {
		t.Fatalf("expected rate_limit 0, got %d", cap.RateLimit)
	}
}

func TestPushClip_RateLimitHTTP(t *testing.T) {
	// Verifies that the rate limit check does not block pushes when no
	// capabilities row exists (self-host / no limit configured).
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	body, _ := json.Marshal(map[string]interface{}{
		"content":   "hello",
		"encrypted": true,
	})
	req, _ := http.NewRequest("POST", ts.URL+"/clips", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestPushClip_RateLimitEnforced(t *testing.T) {
	ts, _, store := setupTestServerWithStore(t)
	token, _, userID := login(t, ts.URL)

	// Set rate_limit = 2.
	if err := store.UpsertUserCapabilities(relay.UserCapabilities{
		UserID:    userID,
		RateLimit: 2,
	}); err != nil {
		t.Fatalf("UpsertUserCapabilities: %v", err)
	}

	push := func() int {
		body, _ := json.Marshal(map[string]interface{}{
			"content":   "hello",
			"encrypted": true,
		})
		req, _ := http.NewRequest("POST", ts.URL+"/clips", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("push: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if sc := push(); sc != http.StatusOK {
		t.Fatalf("push 1: expected 200, got %d", sc)
	}
	if sc := push(); sc != http.StatusOK {
		t.Fatalf("push 2: expected 200, got %d", sc)
	}
	if sc := push(); sc != http.StatusTooManyRequests {
		t.Fatalf("push 3: expected 429, got %d", sc)
	}
}

func TestSweepUsesCapabilitiesRetention(t *testing.T) {
	store := relay.NewTestStore(t)

	userID := "sweep-cap-user"
	if err := store.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	// Register a device with remote_retention_days = 30.
	if err := store.RegisterDeviceWithToken(userID, "dev1", "host1", "tok1"); err != nil {
		t.Fatalf("RegisterDeviceWithToken: %v", err)
	}
	if err := store.UpdateDeviceRetention("dev1", 30); err != nil {
		t.Fatalf("UpdateDeviceRetention: %v", err)
	}

	// Push a clip and backdate it to 5 days ago.
	if _, err := store.DB().Exec(
		`INSERT INTO clips (id, user_id, content, content_type, created_at)
		 VALUES ('clip-old', $1, 'hello', 'text', NOW() - INTERVAL '5 days')`, userID); err != nil {
		t.Fatalf("insert clip: %v", err)
	}

	// Set capabilities retention_days = 3 (stricter than device's 30).
	if err := store.UpsertUserCapabilities(relay.UserCapabilities{
		UserID:        userID,
		RetentionDays: 3,
	}); err != nil {
		t.Fatalf("UpsertUserCapabilities: %v", err)
	}

	// Sweep should use retention_days=3 from capabilities, not 30 from device.
	// The 5-day-old clip should be swept.
	if _, err := store.SweepAllUsersRetentionReturningMedia(); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	var count int
	store.DB().QueryRow("SELECT COUNT(*) FROM clips WHERE id = 'clip-old'").Scan(&count)
	if count != 0 {
		t.Fatal("expected clip to be swept by capabilities retention_days=3, but it still exists")
	}
}

func setupTestServerWithSecret(t *testing.T, secret string) (*httptest.Server, *relay.Store) {
	t.Helper()
	store := relay.NewTestStore(t)
	hub := relay.NewHub()
	go hub.Run()
	handler := relay.NewHandler(store, hub)
	handler.SetInternalServiceSecret(secret)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, store
}

func TestInternalQuota_WritesCapabilities(t *testing.T) {
	ts, store := setupTestServerWithSecret(t, "test-secret")

	// Create a user (quota endpoint requires user to exist in DB).
	userID := "quota-user-1"
	if err := store.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	body, _ := json.Marshal(map[string]interface{}{
		"user_id":        userID,
		"device_limit":   3,
		"retention_days": 7,
		"rate_limit":     100,
	})
	req, _ := http.NewRequest("POST", ts.URL+"/internal/quota", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("quota request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 204, got %d: %s", resp.StatusCode, body)
	}

	// Verify capabilities were written.
	cap, err := store.GetUserCapabilities(userID)
	if err != nil {
		t.Fatalf("GetUserCapabilities: %v", err)
	}
	if cap.DeviceLimit != 3 || cap.RetentionDays != 7 || cap.RateLimit != 100 {
		t.Fatalf("unexpected capabilities: %+v", cap)
	}
}

func TestInternalQuota_RejectsWrongSecret(t *testing.T) {
	ts, _ := setupTestServerWithSecret(t, "correct-secret")

	body, _ := json.Marshal(map[string]interface{}{
		"user_id":      "some-user",
		"device_limit": 3,
	})
	req, _ := http.NewRequest("POST", ts.URL+"/internal/quota", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer wrong-secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestInternalQuota_UnavailableWhenNoSecret(t *testing.T) {
	ts, _ := setupTestServer(t) // no secret set

	body, _ := json.Marshal(map[string]interface{}{"user_id": "x"})
	req, _ := http.NewRequest("POST", ts.URL+"/internal/quota", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer anything")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when no secret configured, got %d", resp.StatusCode)
	}
}

func TestInternalQuota_MissingUserID(t *testing.T) {
	ts, _ := setupTestServerWithSecret(t, "test-secret")

	body, _ := json.Marshal(map[string]interface{}{
		"device_limit": 3,
		// user_id intentionally omitted
	})
	req, _ := http.NewRequest("POST", ts.URL+"/internal/quota", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing user_id, got %d", resp.StatusCode)
	}
}

func TestInternalQuota_GraceExpiresAt(t *testing.T) {
	ts, store := setupTestServerWithSecret(t, "test-secret")

	userID := "grace-quota-user"
	if err := store.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Valid grace_expires_at — should store correctly.
	graceAt := time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	body, _ := json.Marshal(map[string]interface{}{
		"user_id":          userID,
		"device_limit":     3,
		"grace_expires_at": graceAt,
	})
	req, _ := http.NewRequest("POST", ts.URL+"/internal/quota", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}

	cap, err := store.GetUserCapabilities(userID)
	if err != nil {
		t.Fatalf("GetUserCapabilities: %v", err)
	}
	if cap.GraceExpiresAt.IsZero() {
		t.Fatal("expected GraceExpiresAt to be set, got zero")
	}

	// Invalid grace_expires_at — should return 400.
	body2, _ := json.Marshal(map[string]interface{}{
		"user_id":          userID,
		"grace_expires_at": "not-a-date",
	})
	req2, _ := http.NewRequest("POST", ts.URL+"/internal/quota", bytes.NewReader(body2))
	req2.Header.Set("Authorization", "Bearer test-secret")
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid grace_expires_at, got %d", resp2.StatusCode)
	}
}

func TestSweepOldRequestCounts(t *testing.T) {
	store := relay.NewTestStore(t)
	uid := "sweep-count-user"
	if err := store.CreateUser(uid); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Insert a count row for 10 days ago.
	if _, err := store.DB().Exec(
		`INSERT INTO api_request_counts (user_id, date, count) VALUES ($1, CURRENT_DATE - INTERVAL '10 days', 5)`,
		uid,
	); err != nil {
		t.Fatalf("insert old count: %v", err)
	}
	// Insert today's count.
	if _, err := store.DB().Exec(
		`INSERT INTO api_request_counts (user_id, date, count) VALUES ($1, CURRENT_DATE, 3)`,
		uid,
	); err != nil {
		t.Fatalf("insert today count: %v", err)
	}

	// Sweep rows older than 7 days.
	n, err := store.SweepOldRequestCounts(7)
	if err != nil {
		t.Fatalf("SweepOldRequestCounts: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 row swept, got %d", n)
	}

	// Today's row should remain.
	var remaining int
	store.DB().QueryRow(
		`SELECT COUNT(*) FROM api_request_counts WHERE user_id = $1`, uid,
	).Scan(&remaining)
	if remaining != 1 {
		t.Fatalf("expected 1 row remaining, got %d", remaining)
	}
}
