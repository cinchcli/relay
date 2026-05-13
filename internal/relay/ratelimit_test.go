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
