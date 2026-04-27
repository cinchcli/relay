package relay

import (
	"context"
	"log"
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
	cutoff := time.Now().Add(-graceWindow)
	count, err := store.SweepMigratedMasterTokens(cutoff)
	if err != nil {
		log.Printf("grace sweep error: %v", err)
		return
	}
	if count > 0 {
		log.Printf("grace sweep: invalidated %d stale master tokens", count)
	}
}
