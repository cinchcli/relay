package relay

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	cinchv1 "github.com/cinchcli/relay/internal/cinchv1"
	"github.com/gorilla/websocket"
)

// TestReplayPending_NoConcurrentWriteRace guards the single-writer invariant on
// an AgentConn: the on-connect replay of pending key exchanges must NOT call
// conn.WriteJSON directly, because the per-conn writer() goroutine also writes
// to the same socket. Two goroutines calling a gorilla "write method" on one
// conn is a data race (and can interleave/corrupt frames). The replay must
// enqueue via ac.trySend so writer() stays the sole writer.
//
// Run under -race: pre-fix this flags a race between the replay goroutine's
// WriteJSON and writer()'s WriteJSON; post-fix every write funnels through
// writer() and it is clean. It reconnects a few times, hammering broadcasts for
// the duration of each on-connect replay window to make the overlap reliable.
func TestReplayPending_NoConcurrentWriteRace(t *testing.T) {
	ts, store, hub := keyExchangeTestServer(t)

	mainToken, _, _ := keyExchangeLogin(t, ts, "host-main")
	userID, err := store.DeviceOwner(deviceIDFromToken(t, store, mainToken))
	if err != nil {
		t.Fatalf("owner: %v", err)
	}

	// Several OTHER devices on the same account in the pending state (pubkey set,
	// no bundle) so the on-connect replay writes many frames — widening the
	// window that overlaps the concurrent broadcast below.
	const pending = 16
	for i := 0; i < pending; i++ {
		_, _, did := keyExchangeLogin(t, ts, fmt.Sprintf("pending-%d", i))
		if _, err := store.db.Exec("UPDATE devices SET user_id=$1 WHERE id=$2", userID, did); err != nil {
			t.Fatalf("reparent %d: %v", i, err)
		}
		if err := store.SetDevicePublicKey(did, "pk", "fp"); err != nil {
			t.Fatalf("set pubkey %d: %v", i, err)
		}
	}

	wsURL := strings.Replace(ts.URL, "http://", "ws://", 1) + "/ws?token=" + mainToken

	for iter := 0; iter < 4; iter++ {
		conn, _, derr := websocket.DefaultDialer.Dial(wsURL, nil)
		if derr != nil {
			t.Fatalf("dial %d: %v", iter, derr)
		}

		stop := make(chan struct{})
		var wg sync.WaitGroup

		// Drain the reader so writer() is never blocked by a full send buffer.
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if _, _, e := conn.ReadMessage(); e != nil {
					return
				}
			}
		}()

		// Hammer broadcasts: each SendClip enqueues to ac.send, drained by
		// writer()'s WriteJSON — concurrent with the on-connect replay's writes.
		wg.Add(1)
		go func() {
			defer wg.Done()
			i := 0
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = hub.SendClip(userID, &cinchv1.Clip{
						ClipId: fmt.Sprintf("c%d-%d", iter, i),
						UserId: userID,
					})
					i++
				}
			}
		}()

		time.Sleep(40 * time.Millisecond) // overlap window for the replay
		close(stop)
		conn.Close()
		wg.Wait()
	}
}
