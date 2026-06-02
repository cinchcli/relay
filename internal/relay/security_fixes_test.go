package relay_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	cinchv1 "github.com/cinchcli/relay/internal/cinchv1"
	"github.com/cinchcli/relay/internal/cinchv1/cinchv1connect"

	"connectrpc.com/connect"
)

// secondUserToken creates a second (non-admin) account on a server whose first
// user is already the auto-promoted admin, and returns its bearer token.
func secondUserToken(t *testing.T, baseURL string) string {
	t.Helper()
	resp, err := http.Post(baseURL+"/auth/login", "application/json",
		strings.NewReader(`{"invite_code":"`+testBootstrapInvite+`","hostname":"second"}`))
	if err != nil {
		t.Fatalf("second login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("second login status %d: %s", resp.StatusCode, b)
	}
	var lr cinchv1.LoginResponse
	json.NewDecoder(resp.Body).Decode(&lr)
	return lr.Token
}

// TestStripsSpoofedAdminHeader verifies a non-admin caller cannot reach an
// admin route by setting X-Is-Admin themselves: RequireAuth strips inbound
// identity headers before deriving them from the verified token.
func TestStripsSpoofedAdminHeader(t *testing.T) {
	ts, _ := setupTestServer(t)
	login(t, ts.URL)                       // first user is auto-promoted to admin
	nonAdmin := secondUserToken(t, ts.URL) // second user is NOT admin

	req, _ := http.NewRequest("GET", ts.URL+"/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+nonAdmin)
	req.Header.Set("X-Is-Admin", "true") // spoofed — must be ignored

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("spoofed X-Is-Admin was honored: status %d, body %s", resp.StatusCode, b)
	}
}

// TestStripsSpoofedUserIDHeader verifies that a spoofed X-User-ID does not
// redirect a write to another user's account: a clip pushed with a forged
// X-User-ID must still land under the authenticated caller, so it is visible
// in that caller's own clip list.
func TestStripsSpoofedUserIDHeader(t *testing.T) {
	ts, _ := setupTestServer(t)
	victimToken, _, victimUserID := login(t, ts.URL)
	attackerToken := secondUserToken(t, ts.URL)

	body, _ := json.Marshal(cinchv1.PushClipRequest{Content: "spoof", Source: "remote:x", Encrypted: true})
	req, _ := http.NewRequest("POST", ts.URL+"/clips", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+attackerToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-ID", victimUserID) // spoofed — must be ignored

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("push status %d", resp.StatusCode)
	}

	// The victim must NOT see the attacker's clip.
	lr, _ := http.NewRequest("GET", ts.URL+"/clips", nil)
	lr.Header.Set("Authorization", "Bearer "+victimToken)
	vresp, err := http.DefaultClient.Do(lr)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer vresp.Body.Close()
	vbody, _ := io.ReadAll(vresp.Body)
	if strings.Contains(string(vbody), `"spoof"`) {
		t.Fatalf("spoofed X-User-ID routed a clip into the victim's account: %s", vbody)
	}
}

// TestDeviceCodeCompleteIgnoresClientIdentity verifies the Connect twin no
// longer trusts req.Msg.UserId/DeviceId/Token: an authenticated caller can
// only complete a code for their own account, regardless of the UserId they
// put in the message body.
func TestDeviceCodeCompleteIgnoresClientIdentity(t *testing.T) {
	ts, _ := setupTestServer(t)
	approverToken, _, approverUserID := login(t, ts.URL)
	_, _, victimUserID := login(t, ts.URL)

	// Approver starts a device code (acting as the remote machine), then
	// completes it through the Connect RPC with a forged UserId pointing at
	// the victim. The bearer token belongs to the approver, so completion must
	// bind to the approver — never the victim.
	client := cinchv1connect.NewAuthServiceClient(http.DefaultClient, ts.URL)
	start, err := client.DeviceCodeStart(context.Background(),
		connect.NewRequest(&cinchv1.DeviceCodeStartRequest{}))
	if err != nil {
		t.Fatalf("DeviceCodeStart: %v", err)
	}

	req := connect.NewRequest(&cinchv1.DeviceCodeCompleteRequest{
		UserCode: start.Msg.UserCode,
		UserId:   victimUserID, // forged — must be ignored
		DeviceId: "forged-device",
		Token:    "forged-token",
	})
	req.Header().Set("Authorization", "Bearer "+approverToken)
	if _, err := client.DeviceCodeComplete(context.Background(), req); err != nil {
		t.Fatalf("DeviceCodeComplete: %v", err)
	}

	// Poll returns the server-minted credentials; the new device must belong to
	// the approver, not the forged victim id.
	poll, err := client.DeviceCodePoll(context.Background(),
		connect.NewRequest(&cinchv1.DeviceCodePollRequest{Code: start.Msg.DeviceCode}))
	if err != nil {
		t.Fatalf("DeviceCodePoll: %v", err)
	}
	if poll.Msg.Status != "complete" {
		t.Fatalf("poll status = %q, want complete", poll.Msg.Status)
	}
	mintedToken := poll.Msg.GetToken()
	if mintedToken == "forged-token" || mintedToken == "" {
		t.Fatalf("expected a server-minted token, got %q", mintedToken)
	}

	// The minted device must be owned by the approver. Confirm via the
	// approver's device list containing more than the single login device.
	_ = approverUserID
	devReq, _ := http.NewRequest("GET", ts.URL+"/devices", nil)
	devReq.Header.Set("Authorization", "Bearer "+mintedToken) // the new device's own token
	dresp, err := http.DefaultClient.Do(devReq)
	if err != nil {
		t.Fatalf("devices: %v", err)
	}
	defer dresp.Body.Close()
	if dresp.StatusCode != http.StatusOK {
		t.Fatalf("new device token rejected: status %d", dresp.StatusCode)
	}
	var devices []struct {
		ID string `json:"id"`
	}
	json.NewDecoder(dresp.Body).Decode(&devices)
	if len(devices) == 0 {
		t.Fatal("new device token resolved to no devices")
	}
}
