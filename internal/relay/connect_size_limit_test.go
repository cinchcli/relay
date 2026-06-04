package relay_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"

	cinchv1 "github.com/cinchcli/relay/internal/cinchv1"
	"github.com/cinchcli/relay/internal/cinchv1/cinchv1connect"
	relay "github.com/cinchcli/relay/internal/relay"
)

// newConnectTestServer builds a relay whose Connect handlers enforce a small
// read limit, so the transport-level message cap can be exercised cheaply.
func newConnectTestServer(t *testing.T, readMax int) *httptest.Server {
	t.Helper()
	store := relay.NewTestStore(t)
	installBootstrapInvite(t, store)
	hub := relay.NewHub()
	go hub.Run()
	h := relay.NewHandler(store, hub)
	h.ConnectReadMaxBytes = readMax
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

// The Connect ClipsService must cap the inbound message size. Without
// connect.WithReadMaxBytes the default is unlimited, letting one authenticated
// device buffer a multi-gigabyte Content field into memory and OOM the relay.
func TestConnectPushClip_RejectsMessageOverReadLimit(t *testing.T) {
	ts := newConnectTestServer(t, 4096)
	token, _, _ := login(t, ts.URL)

	client := cinchv1connect.NewClipsServiceClient(http.DefaultClient, ts.URL)
	req := connect.NewRequest(&cinchv1.PushClipRequest{
		Content:   strings.Repeat("A", 64*1024), // 64 KiB, far over the 4 KiB cap
		Encrypted: true,
	})
	req.Header().Set("Authorization", "Bearer "+token)

	_, err := client.PushClip(t.Context(), req)
	if err == nil {
		t.Fatal("expected an oversize Connect message to be rejected, got nil error")
	}
	if code := connect.CodeOf(err); code != connect.CodeResourceExhausted {
		t.Errorf("expected CodeResourceExhausted, got %v (%v)", code, err)
	}
}

// The per-user MaxClipSizeKb quota must be enforced against the actual decoded
// content length, not the client-supplied ByteSize field — otherwise a client
// can claim ByteSize=0 and push content of any size up to the read limit.
func TestConnectPushClip_QuotaUsesDecodedContentLength(t *testing.T) {
	ts, _, store := setupTestServerWithStore(t)
	token, _, userID := login(t, ts.URL)

	if err := store.UpsertUserCapabilities(relay.UserCapabilities{
		UserID:        userID,
		MaxClipSizeKb: 1, // 1 KiB per-clip cap
	}); err != nil {
		t.Fatalf("UpsertUserCapabilities: %v", err)
	}

	client := cinchv1connect.NewClipsServiceClient(http.DefaultClient, ts.URL)
	req := connect.NewRequest(&cinchv1.PushClipRequest{
		Content:   strings.Repeat("B", 4096), // 4 KiB, over the 1 KiB cap
		Encrypted: true,
		ByteSize:  0, // client under-reports its size
	})
	req.Header().Set("Authorization", "Bearer "+token)

	_, err := client.PushClip(t.Context(), req)
	if err == nil {
		t.Fatal("expected a clip over MaxClipSizeKb to be rejected despite ByteSize=0")
	}
	if code := connect.CodeOf(err); code != connect.CodeInvalidArgument {
		t.Errorf("expected CodeInvalidArgument, got %v (%v)", code, err)
	}
}
