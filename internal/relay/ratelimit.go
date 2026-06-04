package relay

import (
	"sync"
	"time"
)

// slidingWindowLimiter caps actions per key inside a rolling time window.
// In-process only; not durable across restarts and not shared between
// relay replicas.
type slidingWindowLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string][]time.Time
}

func newSlidingWindowLimiter(limit int, window time.Duration) *slidingWindowLimiter {
	return &slidingWindowLimiter{limit: limit, window: window, hits: map[string][]time.Time{}}
}

// Allow returns true if the action for the given key is within the
// configured rate. Calls past the limit return false and do not record
// a new timestamp.
func (l *slidingWindowLimiter) Allow(key string) bool {
	now := time.Now()
	cutoff := now.Add(-l.window)
	l.mu.Lock()
	defer l.mu.Unlock()
	arr := l.hits[key]
	keep := arr[:0]
	for _, t := range arr {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	if len(keep) >= l.limit {
		l.hits[key] = keep
		return false
	}
	keep = append(keep, now)
	l.hits[key] = keep
	return true
}

// reap deletes every key whose entire window has elapsed as of now, and prunes
// stale timestamps from the rest. Without it the hits map only ever shrinks a
// key's slice when that exact key is seen again, so attacker-chosen keys (e.g.
// spoofable IPs on public routes) leave permanent entries that grow the map
// without bound. Safe to call concurrently with Allow.
func (l *slidingWindowLimiter) reap(now time.Time) {
	cutoff := now.Add(-l.window)
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, arr := range l.hits {
		keep := arr[:0]
		for _, t := range arr {
			if t.After(cutoff) {
				keep = append(keep, t)
			}
		}
		if len(keep) == 0 {
			delete(l.hits, key)
		} else {
			l.hits[key] = keep
		}
	}
}
