package relay_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	cinchv1 "github.com/cinchcli/cinch-core/go/cinch/v1"
	"github.com/cinchcli/relay/internal/protocol"
	"github.com/oklog/ulid/v2"
)

// TestTwoDeviceBacklogFlushOrdering is the end-to-end gate for the backlog
// flush feature: when devA pushes a backlog of clips with explicit
// client_created_at + distinct idempotency_keys, devB (WS-connected) must
// receive them in chronological order and the relay must preserve the
// client-provided timestamps (not overwrite them with NOW()).
func TestTwoDeviceBacklogFlushOrdering(t *testing.T) {
	ts, _, store := setupTestServerWithStore(t)

	// devA: first device created by /auth/login.
	devAToken, _, userID := login(t, ts.URL)

	// devB: second device for the same user, registered directly via the
	// store so this test does not depend on a pairing flow.
	devBID := ulid.Make().String()
	devBToken := ulid.Make().String()
	if err := store.RegisterDeviceWithToken(userID, devBID, "devB-host", devBToken); err != nil {
		t.Fatalf("register devB: %v", err)
	}

	// Connect devB's WS BEFORE pushing so it receives every broadcast.
	devBConn := connectFakeAgent(t, ts.URL, devBToken)
	// Give Register() a moment to attach the conn to the hub before any
	// pushes fan out (matches the convention in revoke_test.go).
	time.Sleep(50 * time.Millisecond)

	// devA pushes 3 backlog clips with ascending client_created_at + unique
	// idempotency_keys. Using a base 30 minutes in the past makes it obvious
	// whether the relay preserved the client timestamps or stamped NOW().
	base := time.Now().UTC().Add(-30 * time.Minute).Truncate(time.Second)
	for i := 0; i < 3; i++ {
		ct := base.Add(time.Duration(i) * time.Second).Format(time.RFC3339)
		idem := fmt.Sprintf("local-test-%d", i)
		content := fmt.Sprintf("clip-%d", i)
		reqBody, _ := json.Marshal(cinchv1.PushClipRequest{
			Content:         content,
			ContentType:     "text",
			Source:          "remote:devA",
			ByteSize:        int64(len(content)),
			Encrypted:       true,
			ClientCreatedAt: &ct,
			IdempotencyKey:  &idem,
		})
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/clips", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+devAToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("push %d failed: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("push %d returned %d", i, resp.StatusCode)
		}
	}

	// Collect 3 WS messages on devB.
	devBConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	received := make([]*cinchv1.Clip, 0, 3)
	for i := 0; i < 3; i++ {
		var msg protocol.WSMessage
		if err := devBConn.ReadJSON(&msg); err != nil {
			t.Fatalf("devB read %d: %v", i, err)
		}
		if msg.Action != protocol.ActionNewClip {
			t.Fatalf("msg %d: expected action %q, got %q", i, protocol.ActionNewClip, msg.Action)
		}
		if msg.Clip == nil {
			t.Fatalf("msg %d: clip is nil", i)
		}
		received = append(received, msg.Clip)
	}

	// Each clip's CreatedAt must match the ClientCreatedAt we sent (relay
	// preserved it), and the contents must arrive in order clip-0..clip-2.
	times := make([]time.Time, 0, 3)
	for i, c := range received {
		tt, err := time.Parse(time.RFC3339, c.CreatedAt)
		if err != nil {
			t.Fatalf("clip %d: parse created_at %q: %v", i, c.CreatedAt, err)
		}
		times = append(times, tt)

		expectedTime := base.Add(time.Duration(i) * time.Second)
		if !tt.Equal(expectedTime) {
			t.Errorf("clip %d: expected created_at %v, got %v (raw=%q)", i, expectedTime, tt, c.CreatedAt)
		}

		expectedContent := fmt.Sprintf("clip-%d", i)
		if c.Content != expectedContent {
			t.Errorf("clip %d: expected content %q, got %q", i, expectedContent, c.Content)
		}
	}

	// And the timestamps must be strictly ascending.
	for i := 1; i < len(times); i++ {
		if !times[i-1].Before(times[i]) {
			t.Fatalf("clips out of chronological order: clip[%d]=%v then clip[%d]=%v",
				i-1, times[i-1], i, times[i])
		}
	}
}
