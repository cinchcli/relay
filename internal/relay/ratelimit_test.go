package relay

import (
	"testing"
	"time"
)

func TestSlidingWindow_AllowsWithinLimit(t *testing.T) {
	rl := newSlidingWindowLimiter(5, time.Minute)
	for i := 0; i < 5; i++ {
		if !rl.Allow("alice") {
			t.Fatalf("hit %d should be allowed", i)
		}
	}
	if rl.Allow("alice") {
		t.Errorf("6th hit should be blocked")
	}
}

func TestSlidingWindow_PerKeyIsolated(t *testing.T) {
	rl := newSlidingWindowLimiter(2, time.Minute)
	rl.Allow("alice")
	rl.Allow("alice")
	if rl.Allow("alice") {
		t.Errorf("alice should be blocked")
	}
	if !rl.Allow("bob") {
		t.Errorf("bob should not be blocked")
	}
}

func TestSlidingWindow_EntriesExpire(t *testing.T) {
	rl := newSlidingWindowLimiter(2, 50*time.Millisecond)
	rl.Allow("k")
	rl.Allow("k")
	if rl.Allow("k") {
		t.Errorf("3rd should block")
	}
	time.Sleep(60 * time.Millisecond)
	if !rl.Allow("k") {
		t.Errorf("after window should allow again")
	}
}

// reap must delete keys whose entire window has elapsed, so attacker-chosen
// keys (e.g. spoofed IPs on public routes) cannot grow the map without bound.
func TestSlidingWindow_ReapRemovesStaleKeys(t *testing.T) {
	rl := newSlidingWindowLimiter(5, time.Minute)
	rl.Allow("a")
	rl.Allow("b")
	if len(rl.hits) != 2 {
		t.Fatalf("expected 2 tracked keys, got %d", len(rl.hits))
	}
	// Advance past the window: every recorded hit is now stale.
	rl.reap(time.Now().Add(2 * time.Minute))
	if len(rl.hits) != 0 {
		t.Errorf("expected all stale keys reaped, got %d", len(rl.hits))
	}
}

// reap must keep keys with hits still inside the window.
func TestSlidingWindow_ReapKeepsActiveKeys(t *testing.T) {
	rl := newSlidingWindowLimiter(5, time.Minute)
	rl.Allow("fresh")
	rl.reap(time.Now()) // window not elapsed
	if len(rl.hits) != 1 {
		t.Errorf("active key should be kept, got %d", len(rl.hits))
	}
}
