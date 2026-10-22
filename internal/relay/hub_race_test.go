package relay_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cinchv1 "github.com/cinchcli/relay/internal/cinchv1"
	relay "github.com/cinchcli/relay/internal/relay"

	"github.com/gorilla/websocket"
)

// These tests are permanent regression guards for the WebSocket hub's teardown
// concurrency under `-race`. They reproduced a real data race before the
// Phase-2 fix: the hub closed a connection's send channel from three places
// (Register's "new conn wins" replacement, Remove, and heartbeat eviction) with
// no single owner, so a broadcast could `send on a closed channel` and Remove
// could delete / double-close an entry it no longer owned. The fix gives the
// writer goroutine sole teardown ownership (sync.Once + a never-closed send
// channel + ownership-checked RemoveConn), so these must stay green.
//
// Panics in the fan-out goroutines are recovered and counted so a regression
// surfaces as a failed assertion rather than a crashed binary; under `-race`
// the detector also flags any reintroduced concurrent close/send directly.

// newDrainWSServer returns an httptest server that upgrades to WebSocket and
// discards everything it reads, so client conns handed to the hub have a live
// peer and the hub's writer goroutine can actually write.
func newDrainWSServer(t *testing.T) *httptest.Server {
	t.Helper()
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		go func() {
			for {
				if _, _, err := c.ReadMessage(); err != nil {
					c.Close()
					return
				}
			}
		}()
	}))
	t.Cleanup(srv.Close)
	return srv
}

func dialWS(t *testing.T, srv *httptest.Server) *websocket.Conn {
	t.Helper()
	u := "ws" + strings.TrimPrefix(srv.URL, "http")
	c, _, err := websocket.DefaultDialer.Dial(u, nil)
	if err != nil {
		t.Fatalf("dial ws: %v", err)
	}
	return c
}

// goCount runs fn in a goroutine, recovering and counting any panic so one
// race does not crash the whole binary.
func goCount(wg *sync.WaitGroup, panics *atomic.Int64, fn func()) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				panics.Add(1)
			}
		}()
		fn()
	}()
}

const (
	raceUser   = "USERRACE000000000000000000"
	raceDevice = "DEVRACE0000000000000000000"
)

// TestHubRemoveBroadcastRace: a single registered conn, a broadcast storm, and a
// concurrent Remove. Remove closes the send channel while SendClip is mid
// fan-out (it copies the conn pointer under RLock, releases the lock, then
// sends) — a `send on closed channel`.
func TestHubRemoveBroadcastRace(t *testing.T) {
	srv := newDrainWSServer(t)
	hub := relay.NewHub()

	var wg sync.WaitGroup
	var panics atomic.Int64
	stop := make(chan struct{})

	hub.Register(raceUser, raceDevice, dialWS(t, srv))

	// Broadcast storm from several goroutines.
	for i := 0; i < 8; i++ {
		goCount(&wg, &panics, func() {
			for {
				select {
				case <-stop:
					return
				default:
					_ = hub.SendClip(raceUser, &cinchv1.Clip{ClipId: "x"})
				}
			}
		})
	}

	// Reconnect + remove churn: each Register replaces and closes the prior
	// send channel; each Remove closes and deletes. Both race the storm.
	goCount(&wg, &panics, func() {
		for {
			select {
			case <-stop:
				return
			default:
				hub.Register(raceUser, raceDevice, dialWS(t, srv))
				hub.Remove(raceUser, raceDevice)
			}
		}
	})

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	if n := panics.Load(); n > 0 {
		t.Fatalf("hub teardown race reproduced: %d send-on-closed-channel panic(s); "+
			"expected zero once the writer owns teardown", n)
	}
}

// TestHubEventSubReregisterRace: re-registering an event subscriber for the same
// (user,device) closes the previous channel while SendToUser fans out to it.
func TestHubEventSubReregisterRace(t *testing.T) {
	hub := relay.NewHub()

	var wg sync.WaitGroup
	var panics atomic.Int64
	stop := make(chan struct{})

	// Drain whatever channel is current so buffers don't wedge the senders.
	ch := hub.RegisterEventSub(raceUser, raceDevice)
	var chMu sync.Mutex
	drainStop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-drainStop:
				return
			default:
				chMu.Lock()
				c := ch
				chMu.Unlock()
				select {
				case <-c:
				case <-time.After(time.Millisecond):
				}
			}
		}
	}()

	// Fan-out storm.
	for i := 0; i < 4; i++ {
		goCount(&wg, &panics, func() {
			for {
				select {
				case <-stop:
					return
				default:
					hub.SendToUser(raceUser, &cinchv1.ServerEvent{
						Event: &cinchv1.ServerEvent_NewClip{
							NewClip: &cinchv1.NewClipEvent{Clip: &cinchv1.Clip{ClipId: "x"}},
						},
					})
				}
			}
		})
	}

	// Re-register churn: each call closes the previous subscriber channel.
	goCount(&wg, &panics, func() {
		for {
			select {
			case <-stop:
				return
			default:
				nc := hub.RegisterEventSub(raceUser, raceDevice)
				chMu.Lock()
				ch = nc
				chMu.Unlock()
			}
		}
	})

	time.Sleep(300 * time.Millisecond)
	close(stop)
	close(drainStop)
	wg.Wait()
	hub.UnregisterEventSub(raceUser, raceDevice)

	if n := panics.Load(); n > 0 {
		t.Fatalf("event-sub re-registration race reproduced: %d panic(s); expected zero after the fix", n)
	}
}

// TestHubShortIDNoPanic guards the `userID[:8]` slicing in the conns fan-out
// paths: a sub-8-char id must not panic. The eventSubs paths already use
// min(8,len); the conns paths (Register/Remove/SendClip log lines) do not.
func TestHubShortIDNoPanic(t *testing.T) {
	srv := newDrainWSServer(t)
	hub := relay.NewHub()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("short id panicked in hub conns path: %v", r)
		}
	}()

	hub.Register("u1", "d1", dialWS(t, srv)) // ids shorter than 8 chars
	_ = hub.SendClip("u1", &cinchv1.Clip{ClipId: "x"})
	hub.Remove("u1", "d1")
}
