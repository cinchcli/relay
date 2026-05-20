package relay

import "testing"

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
