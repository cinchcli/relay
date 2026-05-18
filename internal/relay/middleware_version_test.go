package relay

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

// TestVersionHeaders_PersistOnAuthedRequest verifies that an authenticated
// HTTP request carrying both X-Cinch-Client-Version and X-Cinch-Client-Type
// triggers an async UpdateDeviceVersion for the resolved device. The
// persistence happens fire-and-forget on a background goroutine, so the
// test polls GetDeviceVersion until the row lands or the deadline fires.
//
// Skips when TEST_DATABASE_URL is unset (keyExchangeTestServer →
// newTestStore handles the skip).
func TestVersionHeaders_PersistOnAuthedRequest(t *testing.T) {
	ts, store, _ := keyExchangeTestServer(t)
	token, _, deviceID := keyExchangeLogin(t, ts, "host-A")

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/devices", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Cinch-Client-Version", "0.1.8")
	req.Header.Set("X-Cinch-Client-Type", "cli")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /devices, got %d", resp.StatusCode)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		v, ty, _, _ := store.GetDeviceVersion(context.Background(), deviceID)
		if v == "0.1.8" && ty == "cli" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	v, ty, _, _ := store.GetDeviceVersion(context.Background(), deviceID)
	t.Fatalf("version not persisted from headers for device %s (got version=%q type=%q)", deviceID, v, ty)
}

// TestVersionHeaders_MissingHeaders_NoUpdate verifies that an authed
// request without the version headers does not write anything to the
// device's version columns — the columns must stay empty so admins can
// distinguish "never reported" from "actually reported a value".
func TestVersionHeaders_MissingHeaders_NoUpdate(t *testing.T) {
	ts, store, _ := keyExchangeTestServer(t)
	token, _, deviceID := keyExchangeLogin(t, ts, "host-B")

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/devices", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Give any rogue async write a chance to land, then assert empty.
	time.Sleep(200 * time.Millisecond)
	v, ty, _, _ := store.GetDeviceVersion(context.Background(), deviceID)
	if v != "" || ty != "" {
		t.Errorf("columns should remain empty without headers; got (%q, %q)", v, ty)
	}
}

// TestVersionHeaders_InvalidType_NoUpdate verifies the client-type
// allowlist: anything other than "cli" or "desktop" is silently dropped
// before the store call, so the device row stays empty.
func TestVersionHeaders_InvalidType_NoUpdate(t *testing.T) {
	ts, store, _ := keyExchangeTestServer(t)
	token, _, deviceID := keyExchangeLogin(t, ts, "host-C")

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/devices", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Cinch-Client-Version", "0.1.8")
	req.Header.Set("X-Cinch-Client-Type", "chrome")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	time.Sleep(200 * time.Millisecond)
	v, ty, _, _ := store.GetDeviceVersion(context.Background(), deviceID)
	if v != "" || ty != "" {
		t.Errorf("invalid type should be rejected; got (%q, %q)", v, ty)
	}
}
