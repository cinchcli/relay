package relay

import (
	"database/sql"
	"testing"
	"time"
)

// TestSweepStaleIdempotencyKeys verifies that rows older than the configured
// max age have their idempotency_key NULLed while rows inside the window are
// left untouched.
func TestSweepStaleIdempotencyKeys(t *testing.T) {
	s := newTestStore(t)
	userID := seedSaveClipUser(t, s)

	// Insert a clip with idempotency_key and created_at = 25h ago (outside the
	// 24h window).
	oldKey := "local-OLD"
	oldTime := time.Now().UTC().Add(-25 * time.Hour)
	if _, err := s.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, label, byte_size, created_at, encrypted, idempotency_key)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		"old-clip-id", userID, "x", "text", "s", "", 1, oldTime, true, oldKey,
	); err != nil {
		t.Fatalf("insert old clip: %v", err)
	}

	// Insert a clip with idempotency_key and created_at = 1h ago (inside the
	// window — must not be touched).
	freshKey := "local-FRESH"
	freshTime := time.Now().UTC().Add(-1 * time.Hour)
	if _, err := s.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, label, byte_size, created_at, encrypted, idempotency_key)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		"fresh-clip-id", userID, "y", "text", "s", "", 1, freshTime, true, freshKey,
	); err != nil {
		t.Fatalf("insert fresh clip: %v", err)
	}

	n, err := s.SweepStaleIdempotencyKeys(24 * time.Hour)
	if err != nil {
		t.Fatalf("SweepStaleIdempotencyKeys: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 row swept, got %d", n)
	}

	// Old row still exists; idempotency_key is now NULL.
	var oldKeyAfter sql.NullString
	if err := s.db.QueryRow(
		`SELECT idempotency_key FROM clips WHERE id = $1`, "old-clip-id",
	).Scan(&oldKeyAfter); err != nil {
		t.Fatalf("scan old key: %v", err)
	}
	if oldKeyAfter.Valid {
		t.Fatalf("expected old row's idempotency_key to be NULL, got %q", oldKeyAfter.String)
	}

	// Fresh row's idempotency_key untouched.
	var freshKeyAfter sql.NullString
	if err := s.db.QueryRow(
		`SELECT idempotency_key FROM clips WHERE id = $1`, "fresh-clip-id",
	).Scan(&freshKeyAfter); err != nil {
		t.Fatalf("scan fresh key: %v", err)
	}
	if !freshKeyAfter.Valid || freshKeyAfter.String != freshKey {
		t.Fatalf("expected fresh row's idempotency_key to be %q, got %q (valid=%v)",
			freshKey, freshKeyAfter.String, freshKeyAfter.Valid)
	}
}

// TestSweepStaleIdempotencyKeysIsIdempotent confirms that running the sweep
// twice in a row is a no-op the second time — the partial unique index only
// constrains non-null keys, so already-nulled rows are simply skipped.
func TestSweepStaleIdempotencyKeysIsIdempotent(t *testing.T) {
	s := newTestStore(t)
	userID := seedSaveClipUser(t, s)

	key := "local-K"
	if _, err := s.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, label, byte_size, created_at, encrypted, idempotency_key)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		"id-1", userID, "x", "text", "s", "", 1, time.Now().UTC().Add(-25*time.Hour), true, key,
	); err != nil {
		t.Fatalf("insert clip: %v", err)
	}

	n1, err := s.SweepStaleIdempotencyKeys(24 * time.Hour)
	if err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	if n1 != 1 {
		t.Fatalf("first sweep: expected 1, got %d", n1)
	}

	n2, err := s.SweepStaleIdempotencyKeys(24 * time.Hour)
	if err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	if n2 != 0 {
		t.Fatalf("second sweep: expected 0 (already nulled), got %d", n2)
	}
}
