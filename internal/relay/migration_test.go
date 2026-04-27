package relay

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// TestMigrateDevicesToken asserts the Phase 2 additive migration adds three columns
// and a partial unique index on devices(token).
func TestMigrateDevicesToken(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	assertCol(t, db, "devices", "token")
	assertCol(t, db, "devices", "revoked_at")
	assertCol(t, db, "users", "token_migrated_at")

	// Partial UNIQUE index on devices(token) WHERE token IS NOT NULL must exist.
	var idxCount int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_devices_token'`,
	).Scan(&idxCount); err != nil {
		t.Fatalf("idx check: %v", err)
	}
	if idxCount != 1 {
		t.Fatalf("idx_devices_token missing, got count %d", idxCount)
	}
}

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

// assertCol fails the test if the column is missing from the given table.
func assertCol(t *testing.T, db *sql.DB, table, col string) {
	t.Helper()
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		t.Fatalf("pragma: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		if name == col {
			return
		}
	}
	t.Fatalf("column %s.%s missing", table, col)
}
