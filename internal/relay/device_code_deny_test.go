package relay

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	cinchv1 "github.com/cinchcli/relay/internal/cinchv1"
)

func devDenyStrPtr(s string) *string { return &s }

// TestDeviceCodeDeny_RemoteSeesDenied verifies the end-to-end deny path:
// an already-signed-in user denies a pending device-code targeted at them,
// and a subsequent DeviceCodePoll from the remote returns status="denied".
func TestDeviceCodeDeny_RemoteSeesDenied(t *testing.T) {
	ts, store, hub := keyExchangeTestServer(t)
	defer ts.Close()

	userID, _, token, err := store.UpsertOAuthUser("google", "sub-1", "alice@example.com", true, "", "alice-mac", "m1")
	if err != nil {
		t.Fatalf("seed alice: %v", err)
	}

	server := &connectAuthServer{h: NewHandler(store, hub)}

	startResp, err := server.DeviceCodeStart(context.Background(),
		connect.NewRequest(&cinchv1.DeviceCodeStartRequest{
			Hostname: devDenyStrPtr("dev-box-3"),
			UserHint: devDenyStrPtr("alice@example.com"),
		}))
	if err != nil {
		t.Fatalf("DeviceCodeStart: %v", err)
	}

	denyReq := connect.NewRequest(&cinchv1.DeviceCodeDenyRequest{UserCode: startResp.Msg.UserCode})
	denyReq.Header().Set("X-User-ID", userID)
	denyReq.Header().Set("Authorization", "Bearer "+token)
	if _, err := server.DeviceCodeDeny(context.Background(), denyReq); err != nil {
		t.Fatalf("Deny: %v", err)
	}

	pollResp, err := server.DeviceCodePoll(context.Background(),
		connect.NewRequest(&cinchv1.DeviceCodePollRequest{Code: startResp.Msg.DeviceCode}))
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if pollResp.Msg.Status != "denied" {
		t.Errorf("status: got %q want denied", pollResp.Msg.Status)
	}
}

// TestDeviceCodeDeny_RequiresAuth verifies that DeviceCodeDeny called
// without X-User-ID returns Unauthenticated.
func TestDeviceCodeDeny_RequiresAuth(t *testing.T) {
	ts, store, hub := keyExchangeTestServer(t)
	defer ts.Close()

	server := &connectAuthServer{h: NewHandler(store, hub)}
	_, err := server.DeviceCodeDeny(context.Background(),
		connect.NewRequest(&cinchv1.DeviceCodeDenyRequest{UserCode: "anything"}))
	if err == nil {
		t.Fatalf("expected unauthenticated error")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) || connectErr.Code() != connect.CodeUnauthenticated {
		t.Errorf("code: got %v want Unauthenticated", err)
	}
}

// TestDeviceCodeDeny_OnlyAffectsOwnPending verifies that user A cannot
// deny a device code whose pending_user_id points to user B — the
// DenyDeviceCode UPDATE filter on pending_user_id must prevent it.
func TestDeviceCodeDeny_OnlyAffectsOwnPending(t *testing.T) {
	ts, store, hub := keyExchangeTestServer(t)
	defer ts.Close()

	aliceID, _, aliceTok, err := store.UpsertOAuthUser("google", "sub-a", "alice@example.com", true, "", "alice-mac", "m1")
	if err != nil {
		t.Fatalf("seed alice: %v", err)
	}
	if _, _, _, err := store.UpsertOAuthUser("google", "sub-b", "bob@example.com", true, "", "bob-mac", "m2"); err != nil {
		t.Fatalf("seed bob: %v", err)
	}

	server := &connectAuthServer{h: NewHandler(store, hub)}
	bobStart, err := server.DeviceCodeStart(context.Background(),
		connect.NewRequest(&cinchv1.DeviceCodeStartRequest{
			Hostname: devDenyStrPtr("bob-box"),
			UserHint: devDenyStrPtr("bob@example.com"),
		}))
	if err != nil {
		t.Fatalf("DeviceCodeStart: %v", err)
	}

	denyReq := connect.NewRequest(&cinchv1.DeviceCodeDenyRequest{UserCode: bobStart.Msg.UserCode})
	denyReq.Header().Set("X-User-ID", aliceID)
	denyReq.Header().Set("Authorization", "Bearer "+aliceTok)
	if _, err := server.DeviceCodeDeny(context.Background(), denyReq); err == nil {
		t.Errorf("alice should not be able to deny bob's code")
	}

	// And the code's status should still be pending (poll-side).
	pollResp, err := server.DeviceCodePoll(context.Background(),
		connect.NewRequest(&cinchv1.DeviceCodePollRequest{Code: bobStart.Msg.DeviceCode}))
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if pollResp.Msg.Status != "pending" {
		t.Errorf("status after failed cross-user deny: got %q want pending", pollResp.Msg.Status)
	}
}
