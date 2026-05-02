package relay

import (
	"context"
	"time"
)

const graceSweepInterval = time.Hour
const graceWindow = 7 * 24 * time.Hour

// RunGraceSweeper NULLs stale users.token rows on an hourly ticker.
// Runs until ctx is cancelled. Blocking — call via `go RunGraceSweeper(ctx, store)`.
func RunGraceSweeper(ctx context.Context, store *Store) {
	ticker := time.NewTicker(graceSweepInterval)
	defer ticker.Stop()
	// Run once on start — clears any stale tokens from a previous shutdown.
	sweepOnce(store)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweepOnce(store)
		}
	}
}

func sweepOnce(store *Store) {
	// No-op: the users.token column was dropped in the OAuth-only
	// migration, so there is nothing to sweep. Task 5 deletes this
	// file (and its tests) entirely.
	_ = store
	_ = graceWindow
}
