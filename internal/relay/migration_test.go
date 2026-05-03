package relay

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// TestMigrateDevicesToken was removed in the OAuth-only migration (Task 4).
// It asserted the Phase 2 additive migration left users.token_migrated_at
// in place, but Phase 6 (Task 3) drops that column along with the rest of
// the legacy auth machinery. TestMigrate_DropsLegacyColumns in
// store_test.go now covers the post-migration absence of pair_token /
// token / token_migrated_at, and the partial UNIQUE index on
// devices(token) is no longer relevant once devices.token is gone.

// TestMigrateIdempotent ensures running migrate twice succeeds (additive-only migrations).
func TestMigrateIdempotent(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := migrate(db); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := migrate(db); err != nil {
		t.Fatalf("second: %v", err)
	}
}

