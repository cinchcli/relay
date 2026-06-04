package relay_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	cinchv1 "github.com/cinchcli/relay/internal/cinchv1"
)

// media_path is server-owned: only uploadImageMedia / PushBinaryClip may set it,
// always to a freshly generated server key. A client must never be able to make
// a clip point at an arbitrary media key. If it could, the ownership check in
// GetClipMedia (clip belongs to caller) would not stop the relay from streaming
// another tenant's object out of the shared media store.
func TestPushClip_IgnoresClientSuppliedMediaPath(t *testing.T) {
	ts, mediaDir := setupTestServerWithMediaDir(t)
	token, _, _ := login(t, ts.URL)

	// Plant a "victim" object directly in the shared media store.
	const secret = "TOP-SECRET-VICTIM-CIPHERTEXT"
	if err := os.WriteFile(filepath.Join(mediaDir, "victim.bin"), []byte(secret), 0o600); err != nil {
		t.Fatalf("plant victim object: %v", err)
	}

	// Attacker pushes a plain TEXT clip but injects the victim's media key.
	victimKey := "media/victim.bin"
	body, _ := json.Marshal(cinchv1.PushClipRequest{
		Content:     "attacker text",
		ContentType: "text",
		Encrypted:   true,
		MediaPath:   &victimKey,
	})
	req, _ := http.NewRequest("POST", ts.URL+"/clips", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	var pr cinchv1.PushClipResponse
	json.NewDecoder(resp.Body).Decode(&pr)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || pr.ClipId == "" {
		t.Fatalf("push returned status=%d id=%q", resp.StatusCode, pr.ClipId)
	}

	// Fetching media for the attacker's own clip must NOT serve the victim object.
	mreq, _ := http.NewRequest("GET", ts.URL+"/clips/"+pr.ClipId+"/media", nil)
	mreq.Header.Set("Authorization", "Bearer "+token)
	mresp, err := http.DefaultClient.Do(mreq)
	if err != nil {
		t.Fatalf("media fetch: %v", err)
	}
	defer mresp.Body.Close()
	got, _ := io.ReadAll(mresp.Body)

	if mresp.StatusCode == http.StatusOK && bytes.Contains(got, []byte(secret)) {
		t.Fatalf("cross-tenant read: injected media_path served the victim object (status %d)", mresp.StatusCode)
	}
	if mresp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 (no server-owned media on a text clip), got %d", mresp.StatusCode)
	}
}
