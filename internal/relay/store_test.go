package relay

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// newTestStore creates an in-memory SQLite store for testing.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestSweepExpiredClips(t *testing.T) {
	store := newTestStore(t)

	// Create a test user
	userID := "user-sweep-test"
	if err := store.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Register device with retention days
	_, err := store.db.Exec(
		`INSERT INTO devices (id, user_id, hostname, source_key, remote_retention_days)
		 VALUES (?, ?, ?, ?, ?)`,
		"dev-1", userID, "laptop", "remote:laptop", 7,
	)
	if err != nil {
		t.Fatalf("insert device: %v", err)
	}

	// Insert clips with specific created_at timestamps
	// Clip A: remote, 10 days ago (should be swept)
	_, err = store.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, byte_size, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, datetime('now', '-10 days'))`,
		"clip-a", userID, "old remote clip", "text", "remote:laptop", 15,
	)
	if err != nil {
		t.Fatalf("insert clip A: %v", err)
	}

	// Clip B: remote, 3 days ago (should survive)
	_, err = store.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, byte_size, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, datetime('now', '-3 days'))`,
		"clip-b", userID, "recent remote clip", "text", "remote:laptop", 18,
	)
	if err != nil {
		t.Fatalf("insert clip B: %v", err)
	}

	// Clip C: local, 10 days ago (should survive — local clips are not swept)
	_, err = store.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, byte_size, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, datetime('now', '-10 days'))`,
		"clip-c", userID, "old local clip", "text", "local", 12,
	)
	if err != nil {
		t.Fatalf("insert clip C: %v", err)
	}

	// Run sweep with 7-day retention
	count, err := store.SweepExpiredClips(userID, 7)
	if err != nil {
		t.Fatalf("SweepExpiredClips: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 clip swept, got %d", count)
	}

	// Verify Clip A is gone
	var exists int
	store.db.QueryRow("SELECT COUNT(*) FROM clips WHERE id = 'clip-a'").Scan(&exists)
	if exists != 0 {
		t.Error("clip-a should have been deleted")
	}

	// Verify Clip B still exists
	store.db.QueryRow("SELECT COUNT(*) FROM clips WHERE id = 'clip-b'").Scan(&exists)
	if exists != 1 {
		t.Error("clip-b should still exist")
	}

	// Verify Clip C still exists (local clip)
	store.db.QueryRow("SELECT COUNT(*) FROM clips WHERE id = 'clip-c'").Scan(&exists)
	if exists != 1 {
		t.Error("clip-c (local) should still exist")
	}
}

func TestSweepAllUsersRetention(t *testing.T) {
	store := newTestStore(t)

	// Create two users
	user1 := "user-sweep-1"
	user2 := "user-sweep-2"
	if err := store.CreateUser(user1); err != nil {
		t.Fatalf("CreateUser 1: %v", err)
	}
	if err := store.CreateUser(user2); err != nil {
		t.Fatalf("CreateUser 2: %v", err)
	}

	// User 1: retention 5 days
	_, err := store.db.Exec(
		`INSERT INTO devices (id, user_id, hostname, source_key, remote_retention_days)
		 VALUES (?, ?, ?, ?, ?)`,
		"dev-u1", user1, "server1", "remote:server1", 5,
	)
	if err != nil {
		t.Fatalf("insert device u1: %v", err)
	}

	// User 2: retention 14 days
	_, err = store.db.Exec(
		`INSERT INTO devices (id, user_id, hostname, source_key, remote_retention_days)
		 VALUES (?, ?, ?, ?, ?)`,
		"dev-u2", user2, "server2", "remote:server2", 14,
	)
	if err != nil {
		t.Fatalf("insert device u2: %v", err)
	}

	// User 1 clips
	// 7 days ago — should be swept (> 5 days)
	_, err = store.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, byte_size, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, datetime('now', '-7 days'))`,
		"u1-old", user1, "old clip", "text", "remote:server1", 10,
	)
	if err != nil {
		t.Fatalf("insert u1-old: %v", err)
	}
	// 3 days ago — should survive (< 5 days)
	_, err = store.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, byte_size, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, datetime('now', '-3 days'))`,
		"u1-new", user1, "new clip", "text", "remote:server1", 10,
	)
	if err != nil {
		t.Fatalf("insert u1-new: %v", err)
	}

	// User 2 clips
	// 7 days ago — should survive (< 14 days)
	_, err = store.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, byte_size, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, datetime('now', '-7 days'))`,
		"u2-mid", user2, "mid clip", "text", "remote:server2", 10,
	)
	if err != nil {
		t.Fatalf("insert u2-mid: %v", err)
	}
	// 20 days ago — should be swept (> 14 days)
	_, err = store.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, byte_size, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, datetime('now', '-20 days'))`,
		"u2-old", user2, "very old clip", "text", "remote:server2", 10,
	)
	if err != nil {
		t.Fatalf("insert u2-old: %v", err)
	}

	// Run sweep
	if err := store.SweepAllUsersRetention(); err != nil {
		t.Fatalf("SweepAllUsersRetention: %v", err)
	}

	// Verify User 1: 1 clip remaining (u1-new)
	var u1Count int
	store.db.QueryRow("SELECT COUNT(*) FROM clips WHERE user_id = ?", user1).Scan(&u1Count)
	if u1Count != 1 {
		t.Errorf("user1: expected 1 clip remaining, got %d", u1Count)
	}
	var u1Remaining string
	store.db.QueryRow("SELECT id FROM clips WHERE user_id = ?", user1).Scan(&u1Remaining)
	if u1Remaining != "u1-new" {
		t.Errorf("user1: expected u1-new to survive, got %s", u1Remaining)
	}

	// Verify User 2: 1 clip remaining (u2-mid)
	var u2Count int
	store.db.QueryRow("SELECT COUNT(*) FROM clips WHERE user_id = ?", user2).Scan(&u2Count)
	if u2Count != 1 {
		t.Errorf("user2: expected 1 clip remaining, got %d", u2Count)
	}
	var u2Remaining string
	store.db.QueryRow("SELECT id FROM clips WHERE user_id = ?", user2).Scan(&u2Remaining)
	if u2Remaining != "u2-mid" {
		t.Errorf("user2: expected u2-mid to survive, got %s", u2Remaining)
	}
}

func TestMigrate_DropsLegacyColumns(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Create a DB with the OLD schema (pre-migration).
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, ddl := range []string{
		`CREATE TABLE users (
			id TEXT PRIMARY KEY,
			token TEXT,
			pair_token TEXT UNIQUE,
			token_migrated_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`INSERT INTO users (id, token, pair_token) VALUES ('u1', 'tok1', 'pt1')`,
	} {
		if _, err := raw.Exec(ddl); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	raw.Close()

	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore (runs Migrate): %v", err)
	}
	defer store.Close()

	for _, col := range []string{"pair_token", "token", "token_migrated_at"} {
		if columnExists(t, store, "users", col) {
			t.Errorf("column users.%s should be dropped", col)
		}
	}
	// User row survives.
	var id string
	if err := store.db.QueryRow(`SELECT id FROM users WHERE id='u1'`).Scan(&id); err != nil {
		t.Fatalf("seeded user lost: %v", err)
	}
}

func TestMigrate_Idempotent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	// Re-run migration — should be a no-op.
	if err := store.Migrate(); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
}

func TestMigrate_FreshDB(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, col := range []string{"pair_token", "token", "token_migrated_at"} {
		if columnExists(t, store, "users", col) {
			t.Errorf("fresh DB should not have legacy column users.%s", col)
		}
	}
}

func columnExists(t *testing.T, s *Store, table, col string) bool {
	t.Helper()
	rows, err := s.db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		t.Fatalf("table_info: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		if name == col {
			return true
		}
	}
	return false
}
