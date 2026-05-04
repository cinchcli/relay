package relay

import (
	"database/sql"
	"path/filepath"
	"strings"
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

	// Clip C: local, 10 days ago (should be swept in relay-as-pipe architecture)
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
	if count != 2 {
		t.Errorf("expected 2 clips swept (remote A + local C), got %d", count)
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

	// Verify Clip C is now deleted (local clips are also swept in relay-as-pipe)
	store.db.QueryRow("SELECT COUNT(*) FROM clips WHERE id = 'clip-c'").Scan(&exists)
	if exists != 0 {
		t.Error("clip-c (local, expired) should have been deleted")
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

func TestDeleteClipReturningMedia(t *testing.T) {
	s := newTestStore(t)

	userID := "u1"
	if err := s.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	mediaPath := "media/abc.png"
	_, err := s.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, label, byte_size, media_path, created_at)
		 VALUES ('c1', ?, '', 'image/png', 'test', '', 100, ?, datetime('now'))`,
		userID, mediaPath,
	)
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.DeleteClipReturningMedia(userID, "c1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != mediaPath {
		t.Errorf("got %q, want %q", got, mediaPath)
	}

	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM clips WHERE id = 'c1'").Scan(&count)
	if count != 0 {
		t.Error("clip row still exists after delete")
	}
}

func TestDeleteClipReturningMediaNoMedia(t *testing.T) {
	s := newTestStore(t)
	userID := "u1"
	if err := s.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	_, err := s.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, label, byte_size, created_at)
		 VALUES ('c2', ?, 'hello', 'text', 'test', '', 5, datetime('now'))`,
		userID,
	)
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.DeleteClipReturningMedia(userID, "c2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty media path, got %q", got)
	}
}

func TestDeleteClipReturningMediaNotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.DeleteClipReturningMedia("nobody", "nonexistent")
	if err == nil {
		t.Error("expected error for missing clip, got nil")
	}
}

func TestSweepExpiredClipsReturningMedia(t *testing.T) {
	s := newTestStore(t)
	userID := "u1"
	if err := s.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// old clip with media, should be swept
	_, err := s.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, label, byte_size, media_path, created_at)
		 VALUES ('old1', ?, '', 'image/png', 'remote:x', '', 50, 'media/old.png', datetime('now', '-10 days'))`,
		userID,
	)
	if err != nil {
		t.Fatal(err)
	}
	// recent clip, should survive
	_, err = s.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, label, byte_size, created_at)
		 VALUES ('new1', ?, 'fresh', 'text', 'remote:x', '', 5, datetime('now'))`,
		userID,
	)
	if err != nil {
		t.Fatal(err)
	}

	count, mediaPaths, err := s.SweepExpiredClipsReturningMedia(userID, 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 1 {
		t.Errorf("got count=%d, want 1", count)
	}
	if len(mediaPaths) != 1 || mediaPaths[0] != "media/old.png" {
		t.Errorf("got mediaPaths=%v, want [media/old.png]", mediaPaths)
	}

	var remaining int
	s.db.QueryRow("SELECT COUNT(*) FROM clips WHERE id='new1'").Scan(&remaining)
	if remaining != 1 {
		t.Error("recent clip should not be swept")
	}
}

func TestSweepAllUsersRetentionReturningMedia(t *testing.T) {
	s := newTestStore(t)
	userID := "u-retain"
	if err := s.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	// Register device with 7-day retention
	if _, err := s.db.Exec(
		`INSERT INTO devices (id, user_id, hostname, source_key, remote_retention_days)
		 VALUES ('dev-r1', ?, 'host', 'remote:host', 7)`,
		userID,
	); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	// Old clip with media
	if _, err := s.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, label, byte_size, media_path, created_at)
		 VALUES ('old-r1', ?, '', 'image/png', 'remote:host', '', 50, 'media/retain.png', datetime('now', '-10 days'))`,
		userID,
	); err != nil {
		t.Fatalf("insert clip: %v", err)
	}

	mediaPaths, err := s.SweepAllUsersRetentionReturningMedia()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mediaPaths) != 1 || mediaPaths[0] != "media/retain.png" {
		t.Errorf("got mediaPaths=%v, want [media/retain.png]", mediaPaths)
	}

	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM clips WHERE id='old-r1'").Scan(&count)
	if count != 0 {
		t.Error("old clip should be swept")
	}
}

func TestUpdateDeviceRetention(t *testing.T) {
	store := newTestStore(t)

	// Create a test user
	userID := "user-retention-test"
	if err := store.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Create a test device
	deviceID := "dev-retention-test"
	_, err := store.db.Exec(
		`INSERT INTO devices (id, user_id, hostname, source_key, remote_retention_days)
		 VALUES (?, ?, ?, ?, ?)`,
		deviceID, userID, "test-host", "test-key", 30,
	)
	if err != nil {
		t.Fatalf("insert device: %v", err)
	}

	tests := []struct {
		name      string
		days      int
		wantError bool
		errMsg    string
	}{
		{
			name:      "valid 1 day (new minimum)",
			days:      1,
			wantError: false,
		},
		{
			name:      "valid 7 days",
			days:      7,
			wantError: false,
		},
		{
			name:      "valid 365 days (maximum)",
			days:      365,
			wantError: false,
		},
		{
			name:      "invalid 0 days (below minimum)",
			days:      0,
			wantError: true,
			errMsg:    "between 1 and 365",
		},
		{
			name:      "invalid 366 days (above maximum)",
			days:      366,
			wantError: true,
			errMsg:    "between 1 and 365",
		},
		{
			name:      "invalid -1 days (negative)",
			days:      -1,
			wantError: true,
			errMsg:    "between 1 and 365",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.UpdateDeviceRetention(deviceID, tt.days)
			if tt.wantError {
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}

				// Verify the retention days were actually updated in the database
				var stored int
				err = store.db.QueryRow(
					"SELECT remote_retention_days FROM devices WHERE id = ?",
					deviceID,
				).Scan(&stored)
				if err != nil {
					t.Fatalf("failed to query stored retention: %v", err)
				}
				if stored != tt.days {
					t.Errorf("expected stored retention %d, got %d", tt.days, stored)
				}
			}
		})
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
