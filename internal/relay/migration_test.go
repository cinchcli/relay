package relay

import (
	"strings"
	"testing"
)

// TestMigration_AddsPendingUserIDAndRequesterIP verifies the additive
// migration that adds the desktop-approval columns to device_codes.
// Skips when TEST_DATABASE_URL is unset (newTestStore handles the skip).
func TestMigration_AddsPendingUserIDAndRequesterIP(t *testing.T) {
	store := newTestStore(t)

	var col string
	err := store.DB().QueryRow(
		`SELECT column_name FROM information_schema.columns
		 WHERE table_name = 'device_codes' AND column_name = 'pending_user_id'`,
	).Scan(&col)
	if err != nil {
		t.Fatalf("expected pending_user_id column to exist after migration: %v", err)
	}

	err = store.DB().QueryRow(
		`SELECT column_name FROM information_schema.columns
		 WHERE table_name = 'device_codes' AND column_name = 'requester_ip'`,
	).Scan(&col)
	if err != nil {
		t.Fatalf("expected requester_ip column to exist after migration: %v", err)
	}
}

// TestMigration_OAuthIdentitiesHasDisplayName verifies that the migration adds
// the display_name TEXT column to oauth_identities.
// Skips when TEST_DATABASE_URL is unset (newTestStore handles the skip).
func TestMigration_OAuthIdentitiesHasDisplayName(t *testing.T) {
	store := newTestStore(t)

	var dataType string
	err := store.DB().QueryRow(`
		SELECT data_type FROM information_schema.columns
		WHERE table_name = 'oauth_identities' AND column_name = 'display_name'
	`).Scan(&dataType)
	if err != nil {
		t.Fatalf("display_name column missing on oauth_identities: %v", err)
	}
	if dataType != "text" {
		t.Fatalf("expected text, got %s", dataType)
	}
}

// TestMigration_ClipsHasIdempotencyKey verifies the additive migration adds
// the idempotency_key TEXT column to clips and the partial unique index used
// for backlog-flush dedup. Also asserts the partial-unique behavior end-to-end
// and that Migrate() is idempotent.
func TestMigration_ClipsHasIdempotencyKey(t *testing.T) {
	store := newTestStore(t)

	// (1) Column exists and is nullable TEXT.
	var dataType, isNullable string
	if err := store.DB().QueryRow(`
		SELECT data_type, is_nullable FROM information_schema.columns
		WHERE table_name = 'clips' AND column_name = 'idempotency_key'
	`).Scan(&dataType, &isNullable); err != nil {
		t.Fatalf("idempotency_key column missing on clips: %v", err)
	}
	if dataType != "text" {
		t.Fatalf("expected text, got %s", dataType)
	}
	if isNullable != "YES" {
		t.Fatalf("expected idempotency_key to be nullable, got is_nullable=%s", isNullable)
	}

	// (2) Partial unique index exists with the expected predicate.
	var indexDef string
	if err := store.DB().QueryRow(`
		SELECT indexdef FROM pg_indexes
		WHERE schemaname = 'public'
		  AND tablename = 'clips'
		  AND indexname = 'idx_clips_idempotency'
	`).Scan(&indexDef); err != nil {
		t.Fatalf("idx_clips_idempotency index missing: %v", err)
	}
	if !strings.Contains(indexDef, "UNIQUE") {
		t.Fatalf("expected UNIQUE in indexdef, got: %s", indexDef)
	}
	if !strings.Contains(indexDef, "user_id") || !strings.Contains(indexDef, "idempotency_key") {
		t.Fatalf("expected (user_id, idempotency_key) in indexdef, got: %s", indexDef)
	}
	if !strings.Contains(indexDef, "WHERE") || !strings.Contains(indexDef, "idempotency_key IS NOT NULL") {
		t.Fatalf("expected partial predicate WHERE idempotency_key IS NOT NULL, got: %s", indexDef)
	}

	// (3) Partial-unique behavior: same (user_id, idempotency_key) is rejected
	// on the second insert, but two NULL keys are allowed for the same user.
	userID := "user-idempotency-test"
	if err := store.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if _, err := store.DB().Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, byte_size, idempotency_key)
		 VALUES ($1, $2, $3, 'text', 'local', $4, $5)`,
		"clip-idem-1", userID, "first", 5, "local-ABCDEF",
	); err != nil {
		t.Fatalf("first idempotent insert: %v", err)
	}

	if _, err := store.DB().Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, byte_size, idempotency_key)
		 VALUES ($1, $2, $3, 'text', 'local', $4, $5)`,
		"clip-idem-2", userID, "second", 6, "local-ABCDEF",
	); err == nil {
		t.Fatal("expected duplicate (user_id, idempotency_key) insert to fail, got nil")
	} else if !strings.Contains(strings.ToLower(err.Error()), "duplicate") &&
		!strings.Contains(strings.ToLower(err.Error()), "unique") {
		t.Fatalf("expected unique-violation error, got: %v", err)
	}

	// Two NULL idempotency_keys for the same user must coexist.
	if _, err := store.DB().Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, byte_size, idempotency_key)
		 VALUES ($1, $2, $3, 'text', 'local', $4, NULL)`,
		"clip-null-1", userID, "no-key-a", 7,
	); err != nil {
		t.Fatalf("first NULL idempotency_key insert: %v", err)
	}
	if _, err := store.DB().Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, byte_size, idempotency_key)
		 VALUES ($1, $2, $3, 'text', 'local', $4, NULL)`,
		"clip-null-2", userID, "no-key-b", 8,
	); err != nil {
		t.Fatalf("second NULL idempotency_key insert: %v", err)
	}

	// (4) Migrate() must be idempotent — newTestStore already ran it once;
	// calling it again must not error and must not destroy the existing data.
	if err := store.Migrate(); err != nil {
		t.Fatalf("second Migrate() call errored: %v", err)
	}
	var count int
	if err := store.DB().QueryRow(
		`SELECT COUNT(*) FROM clips WHERE user_id = $1`, userID,
	).Scan(&count); err != nil {
		t.Fatalf("count clips after second migrate: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 clips after idempotent migrate, got %d", count)
	}
}
