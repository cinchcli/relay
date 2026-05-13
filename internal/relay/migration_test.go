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
