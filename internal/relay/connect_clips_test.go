package relay_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"

	cinchv1 "github.com/cinchcli/relay/internal/cinchv1"
	"github.com/cinchcli/relay/internal/cinchv1/cinchv1connect"
	"github.com/cinchcli/relay/internal/media"
	relay "github.com/cinchcli/relay/internal/relay"
)

// setupTestServerWithMediaDir is like setupTestServerWithDisk but also returns
// the absolute media directory path so callers can read back the objects the
// relay wrote (proving uploadImageMedia actually ran end-to-end).
func setupTestServerWithMediaDir(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	tmpDir := t.TempDir()
	mediaDir := filepath.Join(tmpDir, "media")
	mediaStore, err := media.NewLocalStore(mediaDir)
	if err != nil {
		t.Fatalf("create media store: %v", err)
	}
	store := relay.NewTestStore(t)
	installBootstrapInvite(t, store)
	hub := relay.NewHub()
	go hub.Run()
	handler := relay.NewHandler(store, hub)
	handler.SetMediaStore(mediaStore)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, mediaDir
}

func TestConnectPushClip_ImageRoutesToMediaStore(t *testing.T) {
	ts, mediaDir := setupTestServerWithMediaDir(t)
	token, _, _ := login(t, ts.URL)

	client := cinchv1connect.NewClipsServiceClient(http.DefaultClient, ts.URL)
	req := connect.NewRequest(&cinchv1.PushClipRequest{
		Content:     "encrypted-image-blob",
		ContentType: "image",
		Encrypted:   true,
	})
	req.Header().Set("Authorization", "Bearer "+token)

	resp, err := client.PushClip(t.Context(), req)
	if err != nil {
		t.Fatalf("PushClip: %v", err)
	}
	if resp.Msg.ClipId == "" {
		t.Fatal("expected clip_id in response")
	}

	// The relay should have written exactly one object into media/clips/.
	clipsDir := filepath.Join(mediaDir, "clips")
	entries, err := os.ReadDir(clipsDir)
	if err != nil {
		t.Fatalf("read media dir %s: %v", clipsDir, err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 media object in %s, got %d", clipsDir, len(entries))
	}

	objPath := filepath.Join(clipsDir, entries[0].Name())
	body, err := os.ReadFile(objPath)
	if err != nil {
		t.Fatalf("read media file: %v", err)
	}
	if string(body) != "encrypted-image-blob" {
		t.Errorf("media object content: got %q want %q", body, "encrypted-image-blob")
	}
}

func TestConnectPushClip_TextDoesNotTouchMediaStore(t *testing.T) {
	ts, mediaDir := setupTestServerWithMediaDir(t)
	token, _, _ := login(t, ts.URL)

	client := cinchv1connect.NewClipsServiceClient(http.DefaultClient, ts.URL)
	req := connect.NewRequest(&cinchv1.PushClipRequest{
		Content:     "hello",
		ContentType: "text",
		Encrypted:   true,
	})
	req.Header().Set("Authorization", "Bearer "+token)

	if _, err := client.PushClip(t.Context(), req); err != nil {
		t.Fatalf("PushClip: %v", err)
	}

	// The clips/ subdir must not exist (no upload happened) or be empty.
	clipsDir := filepath.Join(mediaDir, "clips")
	entries, err := os.ReadDir(clipsDir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read media dir: %v", err)
	}
	if len(entries) > 0 {
		t.Errorf("text clip wrote %d media objects; expected 0", len(entries))
	}
}

func TestConnectPushClip_RejectsPlaintext(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	client := cinchv1connect.NewClipsServiceClient(http.DefaultClient, ts.URL)
	req := connect.NewRequest(&cinchv1.PushClipRequest{
		Content:   "hi",
		Encrypted: false,
	})
	req.Header().Set("Authorization", "Bearer "+token)

	_, err := client.PushClip(t.Context(), req)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var connectErr *connect.Error
	if !isConnectError(err, &connectErr) || connectErr.Code() != connect.CodeFailedPrecondition {
		t.Fatalf("expected CodeFailedPrecondition, got %v", err)
	}
}

func TestConnectPushClip_AcceptsEncrypted(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	client := cinchv1connect.NewClipsServiceClient(http.DefaultClient, ts.URL)
	req := connect.NewRequest(&cinchv1.PushClipRequest{
		Content:   "encrypted-content",
		Encrypted: true,
	})
	req.Header().Set("Authorization", "Bearer "+token)

	resp, err := client.PushClip(t.Context(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Msg.ClipId == "" {
		t.Error("expected clip_id, got empty")
	}
}

func isConnectError(err error, target **connect.Error) bool {
	if err == nil {
		return false
	}
	ce, ok := err.(*connect.Error)
	if ok {
		*target = ce
	}
	return ok
}

// connectPushClip pushes a clip via Connect-RPC and returns the assigned clip ID.
func connectPushClip(t *testing.T, client cinchv1connect.ClipsServiceClient, token, content, contentType, source string) string {
	t.Helper()
	req := connect.NewRequest(&cinchv1.PushClipRequest{
		Content:     content,
		ContentType: contentType,
		Source:      source,
		Encrypted:   true,
	})
	req.Header().Set("Authorization", "Bearer "+token)
	resp, err := client.PushClip(t.Context(), req)
	if err != nil {
		t.Fatalf("connectPushClip: %v", err)
	}
	return resp.Msg.ClipId
}

func TestGetLatestClip_ExcludeSource(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	client := cinchv1connect.NewClipsServiceClient(http.DefaultClient, ts.URL)
	connectPushClip(t, client, token, "from-desktop", "text", "remote:desktop")
	connectPushClip(t, client, token, "from-phone", "text", "remote:phone")

	req := connect.NewRequest(&cinchv1.GetLatestClipRequest{
		ExcludeSource: "remote:phone",
	})
	req.Header().Set("Authorization", "Bearer "+token)

	resp, err := client.GetLatestClip(t.Context(), req)
	if err != nil {
		t.Fatalf("GetLatestClip: %v", err)
	}
	if resp.Msg.GetClip().Content != "from-desktop" {
		t.Fatalf("want from-desktop content, got %+v", resp.Msg.GetClip())
	}
}

func TestGetLatestClip_RejectsSourceAndExcludeSourceTogether(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	client := cinchv1connect.NewClipsServiceClient(http.DefaultClient, ts.URL)
	req := connect.NewRequest(&cinchv1.GetLatestClipRequest{
		Source:        "remote:desktop",
		ExcludeSource: "remote:phone",
	})
	req.Header().Set("Authorization", "Bearer "+token)

	_, err := client.GetLatestClip(t.Context(), req)
	if err == nil {
		t.Fatal("expected error when both source and exclude_source are set, got nil")
	}
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Fatalf("want CodeInvalidArgument, got %v: %v", got, err)
	}
}

func TestListClips_HonoursFilters(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	client := cinchv1connect.NewClipsServiceClient(http.DefaultClient, ts.URL)
	connectPushClip(t, client, token, "hello", "text", "remote:desktop")
	c2 := connectPushClip(t, client, token, "img", "image", "remote:phone")

	req := connect.NewRequest(&cinchv1.ListClipsRequest{
		Limit:        50,
		SourceFilter: "remote:phone",
	})
	req.Header().Set("Authorization", "Bearer "+token)

	resp, err := client.ListClips(t.Context(), req)
	if err != nil {
		t.Fatalf("ListClips: %v", err)
	}
	got := resp.Msg.GetClips()
	if len(got) != 1 || got[0].ClipId != c2 {
		t.Fatalf("expected only clip from remote:phone (id=%s), got %+v", c2, got)
	}
}
