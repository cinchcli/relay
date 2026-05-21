package relay

import (
	"context"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"

	cinchv1 "github.com/cinchcli/relay/internal/cinchv1"
)

// TestDeviceCodeComplete_DeviceLimitExceeded_ReturnsResourceExhausted verifies
// the wire-level error contract: when CompleteDeviceCode rejects the approve
// flow because the user is at their device_limit, the Connect-RPC handler
// must map that error to connect.CodeResourceExhausted (HTTP 429), not the
// default CodeInvalidArgument. This is the contract the CLI's humane error
// rendering (Phase 5.0 Task 7) depends on.
func TestDeviceCodeComplete_DeviceLimitExceeded_ReturnsResourceExhausted(t *testing.T) {
	ts, store, hub := keyExchangeTestServer(t)
	defer ts.Close()

	const userID = "user-rpc-limit"
	if err := store.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := store.UpsertUserCapabilities(UserCapabilities{
		UserID:      userID,
		DeviceLimit: 1,
	}); err != nil {
		t.Fatalf("UpsertUserCapabilities: %v", err)
	}

	// First device fills the single allowed slot.
	if _, _, err := store.CreateDeviceForUser(userID, "host-1", "machine-1"); err != nil {
		t.Fatalf("CreateDeviceForUser #1: %v", err)
	}

	// Approve flow: a remote device asks to log in (device code), then an
	// already-signed-in device provisions a fresh device row and calls
	// CompleteDeviceCode to attach it. The cap should reject the second one.
	startResp, _, err := store.CreateDeviceCode("host-2", "machine-2", "", "")
	if err != nil {
		t.Fatalf("CreateDeviceCode: %v", err)
	}
	newDeviceID, newToken, err := store.CreateDeviceForUser(userID, "host-2", "machine-2")
	if err != nil {
		t.Fatalf("CreateDeviceForUser #2: %v", err)
	}

	server := &connectAuthServer{h: NewHandler(store, hub)}
	_, err = server.DeviceCodeComplete(context.Background(),
		connect.NewRequest(&cinchv1.DeviceCodeCompleteRequest{
			UserCode: startResp.UserCode,
			UserId:   userID,
			DeviceId: newDeviceID,
			Token:    newToken,
		}))
	if err == nil {
		t.Fatalf("DeviceCodeComplete: expected device_limit_exceeded error, got nil")
	}

	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatalf("DeviceCodeComplete: expected *connect.Error, got %T: %v", err, err)
	}
	if ce.Code() != connect.CodeResourceExhausted {
		t.Fatalf("DeviceCodeComplete: code = %v, want %v (full err: %v)",
			ce.Code(), connect.CodeResourceExhausted, err)
	}
	if !strings.Contains(ce.Message(), "device_limit_exceeded") {
		t.Fatalf("DeviceCodeComplete: message %q does not contain device_limit_exceeded",
			ce.Message())
	}
}
