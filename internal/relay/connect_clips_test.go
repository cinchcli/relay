package relay_test

import (
	"net/http"
	"testing"

	"connectrpc.com/connect"

	cinchv1 "github.com/cinchcli/relay/internal/gen/cinch/v1"
	"github.com/cinchcli/relay/internal/gen/cinch/v1/cinchv1connect"
)

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
