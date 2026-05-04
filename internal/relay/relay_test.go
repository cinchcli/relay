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

	cinchv1 "github.com/cinchcli/relay/internal/gen/cinch/v1"
	"github.com/cinchcli/relay/internal/media"
	"github.com/cinchcli/relay/internal/protocol"
	relay "github.com/cinchcli/relay/internal/relay"
	"github.com/gorilla/websocket"
)

// setupTestServer creates a relay with an in-memory SQLite DB and returns the test server URL.
func setupTestServer(t *testing.T) (*httptest.Server, *relay.Hub) {
	t.Helper()

	store, err := relay.NewStore(":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	hub := relay.NewHub()
	go hub.Run()

	handler := relay.NewHandler(store, hub)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	return ts, hub
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

// setupTestServerWithDisk creates a relay with a real disk-backed SQLite DB (needed for media tests).
func setupTestServerWithDisk(t *testing.T) *httptest.Server {
	t.Helper()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := relay.NewStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

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
	store, err := relay.NewStore(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

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
	if _, err := store.ExecForTest("UPDATE users SET created_at = datetime('now', '-11 minutes') WHERE id = ?", userID); err != nil {
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
