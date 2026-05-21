package relay

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	cinchv1 "github.com/cinchcli/relay/internal/cinchv1"
)

// newConnectMeServerForTest builds a connectMeServer backed by a test
// store + hub. Returns the server + store so individual tests can seed
// users, capabilities, and devices before calling GetMe.
func newConnectMeServerForTest(t *testing.T) (*connectMeServer, *Store) {
	t.Helper()
	_, store, hub := keyExchangeTestServer(t)
	return &connectMeServer{h: NewHandler(store, hub)}, store
}

// callGetMe issues a GetMe RPC with the given X-User-ID header. An empty
// userID exercises the defensive auth check (interceptor bypass).
func callGetMe(t *testing.T, s *connectMeServer, userID string) (*cinchv1.GetMeResponse, error) {
	t.Helper()
	req := connect.NewRequest(&cinchv1.GetMeRequest{})
	if userID != "" {
		req.Header().Set("X-User-ID", userID)
	}
	resp, err := s.GetMe(context.Background(), req)
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// TestGetMe_FreePlan verifies the happy path for a user on the free tier:
// plan_name maps to "free", caps come through unchanged, and usage reports
// the number of non-revoked devices.
func TestGetMe_FreePlan(t *testing.T) {
	server, store := newConnectMeServerForTest(t)

	const userID = "user-getme-free"
	if err := store.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := store.UpsertUserCapabilities(UserCapabilities{
		UserID:        userID,
		DeviceLimit:   3,
		RetentionDays: 7,
	}); err != nil {
		t.Fatalf("UpsertUserCapabilities: %v", err)
	}
	if _, _, err := store.CreateDeviceForUser(userID, "host-1", "machine-1"); err != nil {
		t.Fatalf("CreateDeviceForUser #1: %v", err)
	}
	if _, _, err := store.CreateDeviceForUser(userID, "host-2", "machine-2"); err != nil {
		t.Fatalf("CreateDeviceForUser #2: %v", err)
	}

	resp, err := callGetMe(t, server, userID)
	if err != nil {
		t.Fatalf("GetMe: %v", err)
	}
	if resp.PlanName != "free" {
		t.Errorf("plan_name = %q, want %q", resp.PlanName, "free")
	}
	if resp.Plan.GetDeviceLimit() != 3 {
		t.Errorf("device_limit = %d, want 3", resp.Plan.GetDeviceLimit())
	}
	if resp.Plan.GetRetentionDays() != 7 {
		t.Errorf("retention_days = %d, want 7", resp.Plan.GetRetentionDays())
	}
	if resp.Usage.GetActiveDevices() != 2 {
		t.Errorf("active_devices = %d, want 2", resp.Usage.GetActiveDevices())
	}
}

// TestGetMe_NoCapsRow_IsFree verifies that a user without a
// user_capabilities row still gets a sensible "free" response with
// zero-valued caps (the self-host default surface).
func TestGetMe_NoCapsRow_IsFree(t *testing.T) {
	server, store := newConnectMeServerForTest(t)

	const userID = "user-getme-nocaps"
	if err := store.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, _, err := store.CreateDeviceForUser(userID, "host-1", "machine-1"); err != nil {
		t.Fatalf("CreateDeviceForUser: %v", err)
	}

	resp, err := callGetMe(t, server, userID)
	if err != nil {
		t.Fatalf("GetMe: %v", err)
	}
	if resp.PlanName != "free" {
		t.Errorf("plan_name = %q, want %q", resp.PlanName, "free")
	}
	if resp.Plan.GetDeviceLimit() != 0 {
		t.Errorf("device_limit = %d, want 0", resp.Plan.GetDeviceLimit())
	}
	if resp.Usage.GetActiveDevices() != 1 {
		t.Errorf("active_devices = %d, want 1", resp.Usage.GetActiveDevices())
	}
}

// TestGetMe_Unauthenticated verifies the defensive empty-X-User-ID branch:
// even if the auth interceptor is bypassed (or misconfigured), the handler
// itself must fail closed with CodeUnauthenticated.
func TestGetMe_Unauthenticated(t *testing.T) {
	server, _ := newConnectMeServerForTest(t)

	_, err := callGetMe(t, server, "")
	if err == nil {
		t.Fatalf("GetMe: expected unauthenticated error, got nil")
	}
	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatalf("GetMe: expected *connect.Error, got %T: %v", err, err)
	}
	if ce.Code() != connect.CodeUnauthenticated {
		t.Fatalf("GetMe: code = %v, want %v (full err: %v)",
			ce.Code(), connect.CodeUnauthenticated, err)
	}
}
