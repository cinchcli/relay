package relay

import (
	"database/sql"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// testBootstrapInviteCode is a pre-baked invite code used by internal-package
// test server builders so that /auth/login succeeds without a real invite flow.
// The value must match the one used in relay_test.go (package relay_test).
const testBootstrapInviteCode = "cinch_inv_test_bootstrap"

// installTestBootstrapInvite seeds a multi-use long-lived invite into s so that
// helper login calls succeed even after the invite gate is active.
// Idempotent: tolerates a leftover row when an earlier test panicked before
// its t.Cleanup truncated invites.
func installTestBootstrapInvite(t *testing.T, s *Store) {
	t.Helper()
	err := s.CreateInvite(
		HashInviteCode(testBootstrapInviteCode),
		nil,
		"test-bootstrap",
		1000,
		time.Now().Add(365*24*time.Hour),
	)
	if err != nil && !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("install test bootstrap invite: %v", err)
	}
}

// newTestStore connects to TEST_DATABASE_URL and skips if it is not set.
// Registered cleanup truncates all tables so tests do not bleed into each other.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL integration test")
	}
	store, err := NewStore(dsn)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() {
		store.db.Exec(`TRUNCATE clips, devices, device_codes, clip_tombstones,
			oauth_identities, user_capabilities, api_request_counts,
			demo_stats, settings, invites, users CASCADE`)
		store.Close()
	})
	return store
}

func TestSweepExpiredClips(t *testing.T) {
	store := newTestStore(t)

	userID := "user-sweep-test"
	if err := store.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, err := store.db.Exec(
		`INSERT INTO devices (id, user_id, hostname, source_key, remote_retention_days)
		 VALUES ($1, $2, $3, $4, $5)`,
		"dev-1", userID, "laptop", "remote:laptop", 7,
	)
	if err != nil {
		t.Fatalf("insert device: %v", err)
	}

	// Clip A: 10 days ago — should be swept
	_, err = store.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, byte_size, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, NOW() - INTERVAL '10 days')`,
		"clip-a", userID, "old remote clip", "text", "remote:laptop", 15,
	)
	if err != nil {
		t.Fatalf("insert clip A: %v", err)
	}

	// Clip B: 3 days ago — should survive
	_, err = store.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, byte_size, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, NOW() - INTERVAL '3 days')`,
		"clip-b", userID, "recent remote clip", "text", "remote:laptop", 18,
	)
	if err != nil {
		t.Fatalf("insert clip B: %v", err)
	}

	// Clip C: local, 10 days ago — should be swept (relay-as-pipe architecture sweeps all)
	_, err = store.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, byte_size, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, NOW() - INTERVAL '10 days')`,
		"clip-c", userID, "old local clip", "text", "local", 12,
	)
	if err != nil {
		t.Fatalf("insert clip C: %v", err)
	}

	count, err := store.SweepExpiredClips(userID, 7)
	if err != nil {
		t.Fatalf("SweepExpiredClips: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 clips swept, got %d", count)
	}

	var exists int
	store.db.QueryRow("SELECT COUNT(*) FROM clips WHERE id = 'clip-a'").Scan(&exists)
	if exists != 0 {
		t.Error("clip-a should have been deleted")
	}
	store.db.QueryRow("SELECT COUNT(*) FROM clips WHERE id = 'clip-b'").Scan(&exists)
	if exists != 1 {
		t.Error("clip-b should still exist")
	}
	store.db.QueryRow("SELECT COUNT(*) FROM clips WHERE id = 'clip-c'").Scan(&exists)
	if exists != 0 {
		t.Error("clip-c (local, expired) should have been deleted")
	}
}

func TestSweepAllUsersRetention(t *testing.T) {
	store := newTestStore(t)

	user1 := "user-sweep-1"
	user2 := "user-sweep-2"
	if err := store.CreateUser(user1); err != nil {
		t.Fatalf("CreateUser 1: %v", err)
	}
	if err := store.CreateUser(user2); err != nil {
		t.Fatalf("CreateUser 2: %v", err)
	}

	if _, err := store.db.Exec(
		`INSERT INTO devices (id, user_id, hostname, source_key, remote_retention_days)
		 VALUES ($1, $2, $3, $4, $5)`,
		"dev-u1", user1, "server1", "remote:server1", 5,
	); err != nil {
		t.Fatalf("insert device u1: %v", err)
	}
	if _, err := store.db.Exec(
		`INSERT INTO devices (id, user_id, hostname, source_key, remote_retention_days)
		 VALUES ($1, $2, $3, $4, $5)`,
		"dev-u2", user2, "server2", "remote:server2", 14,
	); err != nil {
		t.Fatalf("insert device u2: %v", err)
	}

	for _, c := range []struct {
		id, userID, src string
		agoDays         int
	}{
		{"u1-old", user1, "remote:server1", 7},
		{"u1-new", user1, "remote:server1", 3},
		{"u2-mid", user2, "remote:server2", 7},
		{"u2-old", user2, "remote:server2", 20},
	} {
		if _, err := store.db.Exec(
			`INSERT INTO clips (id, user_id, content, content_type, source, byte_size, created_at)
			 VALUES ($1, $2, $3, $4, $5, $6, NOW() - $7 * INTERVAL '1 day')`,
			c.id, c.userID, "clip", "text", c.src, 10, c.agoDays,
		); err != nil {
			t.Fatalf("insert %s: %v", c.id, err)
		}
	}

	if err := store.SweepAllUsersRetention(); err != nil {
		t.Fatalf("SweepAllUsersRetention: %v", err)
	}

	var u1Count int
	store.db.QueryRow("SELECT COUNT(*) FROM clips WHERE user_id = $1", user1).Scan(&u1Count)
	if u1Count != 1 {
		t.Errorf("user1: expected 1 clip remaining, got %d", u1Count)
	}
	var u1Remaining string
	store.db.QueryRow("SELECT id FROM clips WHERE user_id = $1", user1).Scan(&u1Remaining)
	if u1Remaining != "u1-new" {
		t.Errorf("user1: expected u1-new to survive, got %s", u1Remaining)
	}

	var u2Count int
	store.db.QueryRow("SELECT COUNT(*) FROM clips WHERE user_id = $1", user2).Scan(&u2Count)
	if u2Count != 1 {
		t.Errorf("user2: expected 1 clip remaining, got %d", u2Count)
	}
	var u2Remaining string
	store.db.QueryRow("SELECT id FROM clips WHERE user_id = $1", user2).Scan(&u2Remaining)
	if u2Remaining != "u2-mid" {
		t.Errorf("user2: expected u2-mid to survive, got %s", u2Remaining)
	}
}

func TestMigrate_DropsLegacyColumns(t *testing.T) {
	store := newTestStore(t)

	// Seed legacy columns that migration should drop.
	for _, ddl := range []string{
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS pair_token TEXT`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS token TEXT`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS token_migrated_at TIMESTAMPTZ`,
		`INSERT INTO users (id) VALUES ('u1-legacy') ON CONFLICT DO NOTHING`,
	} {
		if _, err := store.db.Exec(ddl); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	// Re-run migration to trigger the DROP COLUMN IF EXISTS path.
	if err := store.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	for _, col := range []string{"pair_token", "token", "token_migrated_at"} {
		if columnExists(t, store, "users", col) {
			t.Errorf("column users.%s should be dropped after migration", col)
		}
	}

	var id string
	if err := store.db.QueryRow(`SELECT id FROM users WHERE id='u1-legacy'`).Scan(&id); err != nil {
		t.Fatalf("seeded user lost after migration: %v", err)
	}
}

func TestMigrate_Idempotent(t *testing.T) {
	store := newTestStore(t)
	if err := store.Migrate(); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
}

func TestMigrate_FreshDB(t *testing.T) {
	store := newTestStore(t)
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
	if _, err := s.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, label, byte_size, media_path, created_at)
		 VALUES ('c1', $1, '', 'image/png', 'test', '', 100, $2, NOW())`,
		userID, mediaPath,
	); err != nil {
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
	if _, err := s.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, label, byte_size, created_at)
		 VALUES ('c2', $1, 'hello', 'text', 'test', '', 5, NOW())`,
		userID,
	); err != nil {
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

	if _, err := s.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, label, byte_size, media_path, created_at)
		 VALUES ('old1', $1, '', 'image/png', 'remote:x', '', 50, 'media/old.png', NOW() - INTERVAL '10 days')`,
		userID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, label, byte_size, created_at)
		 VALUES ('new1', $1, 'fresh', 'text', 'remote:x', '', 5, NOW())`,
		userID,
	); err != nil {
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
	if _, err := s.db.Exec(
		`INSERT INTO devices (id, user_id, hostname, source_key, remote_retention_days)
		 VALUES ('dev-r1', $1, 'host', 'remote:host', 7)`,
		userID,
	); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	if _, err := s.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, label, byte_size, media_path, created_at)
		 VALUES ('old-r1', $1, '', 'image/png', 'remote:host', '', 50, 'media/retain.png', NOW() - INTERVAL '10 days')`,
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

	userID := "user-retention-test"
	if err := store.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	deviceID := "dev-retention-test"
	if _, err := store.db.Exec(
		`INSERT INTO devices (id, user_id, hostname, source_key, remote_retention_days)
		 VALUES ($1, $2, $3, $4, $5)`,
		deviceID, userID, "test-host", "test-key", 30,
	); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	tests := []struct {
		name      string
		days      int
		wantError bool
		errMsg    string
	}{
		{"valid 1 day", 1, false, ""},
		{"valid 7 days", 7, false, ""},
		{"valid 365 days", 365, false, ""},
		{"invalid 0 days", 0, true, "between 1 and 365"},
		{"invalid 366 days", 366, true, "between 1 and 365"},
		{"invalid -1 days", -1, true, "between 1 and 365"},
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
				var stored int
				store.db.QueryRow(
					"SELECT remote_retention_days FROM devices WHERE id = $1", deviceID,
				).Scan(&stored)
				if stored != tt.days {
					t.Errorf("expected stored retention %d, got %d", tt.days, stored)
				}
			}
		})
	}
}

// columnExists checks information_schema instead of SQLite PRAGMA.
func TestUpsertOAuthUser_StoresDisplayName(t *testing.T) {
	s := newTestStore(t)
	_, _, _, err := s.UpsertOAuthUser("github", "42", "alice@example.com", true, "Alice Example", "alice-host", "")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	var got sql.NullString
	if err := s.db.QueryRow(`
		SELECT display_name FROM oauth_identities WHERE provider = 'github' AND subject = '42'
	`).Scan(&got); err != nil {
		t.Fatalf("query: %v", err)
	}
	if !got.Valid || got.String != "Alice Example" {
		t.Fatalf("display_name = %q, want %q", got.String, "Alice Example")
	}
}

func TestUpsertOAuthUser_UpdatesDisplayNameOnReSignIn(t *testing.T) {
	s := newTestStore(t)
	_, _, _, _ = s.UpsertOAuthUser("github", "42", "alice@example.com", true, "Alice Old", "host1", "")
	_, _, _, err := s.UpsertOAuthUser("github", "42", "alice@example.com", true, "Alice New", "host2", "")
	if err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	var got string
	_ = s.db.QueryRow(`SELECT display_name FROM oauth_identities WHERE provider='github' AND subject='42'`).Scan(&got)
	if got != "Alice New" {
		t.Fatalf("display_name = %q, want %q", got, "Alice New")
	}
}

func TestUpsertOAuthUser_BlankDisplayNamePreservesExisting(t *testing.T) {
	s := newTestStore(t)
	_, _, _, _ = s.UpsertOAuthUser("github", "42", "alice@example.com", true, "Alice Original", "host1", "")
	_, _, _, err := s.UpsertOAuthUser("github", "42", "alice@example.com", true, "", "host2", "")
	if err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	var got string
	_ = s.db.QueryRow(`SELECT display_name FROM oauth_identities WHERE provider='github' AND subject='42'`).Scan(&got)
	if got != "Alice Original" {
		t.Fatalf("display_name = %q, want %q (blank should not clobber)", got, "Alice Original")
	}
}

func columnExists(t *testing.T, s *Store, table, col string) bool {
	t.Helper()
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM information_schema.columns
		 WHERE table_name = $1 AND column_name = $2`,
		table, col,
	).Scan(&count)
	if err != nil {
		t.Fatalf("information_schema query: %v", err)
	}
	return count > 0
}

func TestCreateDeviceCode_KnownEmailSetsPendingUserID(t *testing.T) {
	store := newTestStore(t)

	userID, _, _, err := store.UpsertOAuthUser("google", "sub-123", "alice@example.com", true, "", "alice-mbp", "machine-1")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	resp, gotUserID, err := store.CreateDeviceCode("dev-box-3", "machine-2", "alice@example.com", "203.0.113.10")
	if err != nil {
		t.Fatalf("CreateDeviceCode: %v", err)
	}
	if resp.DeviceCode == "" || resp.UserCode == "" {
		t.Fatalf("missing codes")
	}
	if gotUserID != userID {
		t.Errorf("pending_user_id mismatch: got %q want %q", gotUserID, userID)
	}
}

func TestCreateDeviceCode_UnknownEmailReturnsEmptyUserID(t *testing.T) {
	store := newTestStore(t)

	_, gotUserID, err := store.CreateDeviceCode("dev-box-3", "machine-2", "nobody@nowhere.com", "203.0.113.10")
	if err != nil {
		t.Fatalf("CreateDeviceCode: %v", err)
	}
	if gotUserID != "" {
		t.Errorf("expected empty pending_user_id for unknown email, got %q", gotUserID)
	}
}

func TestCreateDeviceCode_PersistsRequesterIP(t *testing.T) {
	store := newTestStore(t)

	resp, _, err := store.CreateDeviceCode("dev-box-3", "machine-2", "", "203.0.113.10")
	if err != nil {
		t.Fatalf("CreateDeviceCode: %v", err)
	}

	var ip sql.NullString
	err = store.DB().QueryRow(
		`SELECT requester_ip FROM device_codes WHERE user_code = $1`, resp.UserCode,
	).Scan(&ip)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if ip.String != "203.0.113.10" {
		t.Errorf("requester_ip mismatch: got %q want %q", ip.String, "203.0.113.10")
	}
}

// mustInsertClip inserts a clip row directly into the database for testing.
func mustInsertClip(t *testing.T, store *Store, userID, clipID, content, contentType, source string, createdAt time.Time) {
	t.Helper()
	if err := store.CreateUser(userID); err != nil {
		// Ignore duplicate user errors — multiple clips may share the same userID.
		if !strings.Contains(err.Error(), "duplicate") && !strings.Contains(err.Error(), "unique") {
			t.Fatalf("mustInsertClip CreateUser %q: %v", userID, err)
		}
	}
	_, err := store.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, byte_size, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		clipID, userID, content, contentType, source, len(content), createdAt.UTC(),
	)
	if err != nil {
		t.Fatalf("mustInsertClip %q: %v", clipID, err)
	}
}

func TestGetLatestClip_ExcludeSource(t *testing.T) {
	store := newTestStore(t)
	uid := "user1"
	mustInsertClip(t, store, uid, "c1", "from-desktop", "text", "remote:desktop", time.Now().Add(-2*time.Minute))
	mustInsertClip(t, store, uid, "c2", "from-phone", "text", "remote:phone", time.Now().Add(-1*time.Minute))

	got, err := store.GetLatestClipExcludingSource(uid, "remote:phone")
	if err != nil {
		t.Fatalf("GetLatestClipExcludingSource: %v", err)
	}
	if got.ClipId != "c1" {
		t.Fatalf("want c1, got %s", got.ClipId)
	}
}

func TestListClipsFiltered_AllFilters(t *testing.T) {
	store := newTestStore(t)
	uid := "user1"

	// Three clips: two text from distinct sources, one image.
	mustInsertClip(t, store, uid, "c1", "hello", "text", "remote:desktop", time.Now().Add(-3*time.Minute))
	mustInsertClip(t, store, uid, "c2", "world", "text", "remote:phone", time.Now().Add(-2*time.Minute))
	mustInsertClip(t, store, uid, "c3", "<image-bytes>", "image", "remote:phone", time.Now().Add(-1*time.Minute))

	cases := []struct {
		name string
		opts ListFilter
		want []string // expected clip IDs in returned order (newest first)
	}{
		{"all", ListFilter{Limit: 50}, []string{"c3", "c2", "c1"}},
		{"source filter", ListFilter{Limit: 50, SourceFilter: "remote:phone"}, []string{"c3", "c2"}},
		{"exclude source", ListFilter{Limit: 50, ExcludeSource: "remote:phone"}, []string{"c1"}},
		{"text only", ListFilter{Limit: 50, ExcludeImage: true}, []string{"c2", "c1"}},
		{"image only", ListFilter{Limit: 50, ExcludeText: true}, []string{"c3"}},
		{"clip ids", ListFilter{Limit: 50, ClipIDs: []string{"c2"}}, []string{"c2"}},
		{"clip ids miss", ListFilter{Limit: 50, ClipIDs: []string{"nope"}}, []string{}},
		{"limit", ListFilter{Limit: 2}, []string{"c3", "c2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := store.ListClipsFiltered(uid, tc.opts)
			if err != nil {
				t.Fatalf("ListClipsFiltered: %v", err)
			}
			ids := make([]string, 0, len(got))
			for _, c := range got {
				ids = append(ids, c.ClipId)
			}
			if !reflect.DeepEqual(ids, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, ids)
			}
		})
	}
}

func TestListInternalUserAggregates_EmptyStore(t *testing.T) {
	store := NewTestStore(t)
	page, err := store.ListInternalUserAggregates(InternalUsersFilter{Limit: 100})
	if err != nil {
		t.Fatalf("ListInternalUserAggregates: %v", err)
	}
	if len(page.Rows) != 0 {
		t.Fatalf("expected 0 rows on empty store, got %d", len(page.Rows))
	}
	if page.NextCursor != "" {
		t.Fatalf("expected empty cursor, got %q", page.NextCursor)
	}
}

func TestListInternalUserAggregates_AggregatesDevices(t *testing.T) {
	store := NewTestStore(t)
	if err := store.CreateUser("user-a"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	// 3 paired devices, 1 already revoked, only 2 with last_push_at.
	if _, err := store.db.Exec(`
		INSERT INTO devices (id, user_id, hostname, source_key, last_push_at, revoked_at)
		VALUES ('d1','user-a','h1','sk1', NOW() - interval '1 hour',    NULL),
		       ('d2','user-a','h2','sk2', NOW() - interval '5 minutes', NULL),
		       ('d3','user-a','h3','sk3', NULL,                         NOW())
	`); err != nil {
		t.Fatalf("seed devices: %v", err)
	}

	page, err := store.ListInternalUserAggregates(InternalUsersFilter{Limit: 100})
	if err != nil {
		t.Fatalf("ListInternalUserAggregates: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(page.Rows))
	}
	row := page.Rows[0]
	if row.UserID != "user-a" {
		t.Fatalf("user_id = %q, want user-a", row.UserID)
	}
	if row.DeviceCount != 3 {
		t.Fatalf("device_count = %d, want 3", row.DeviceCount)
	}
	if row.ActiveDeviceCount != 2 {
		t.Fatalf("active_device_count = %d, want 2", row.ActiveDeviceCount)
	}
	if row.LastActiveAt == nil {
		t.Fatal("last_active_at should be non-nil when at least one device has last_push_at")
	}
	if row.Capabilities != nil {
		t.Fatalf("capabilities should be nil when no user_capabilities row exists, got %+v", row.Capabilities)
	}
}

func TestListInternalUserAggregates_IncludesCapabilities(t *testing.T) {
	store := NewTestStore(t)
	if err := store.CreateUser("user-cap"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := store.UpsertUserCapabilities(UserCapabilities{
		UserID: "user-cap", DeviceLimit: 10, RetentionDays: 90, RateLimit: 0,
	}); err != nil {
		t.Fatalf("UpsertUserCapabilities: %v", err)
	}

	page, err := store.ListInternalUserAggregates(InternalUsersFilter{Limit: 100})
	if err != nil {
		t.Fatalf("ListInternalUserAggregates: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(page.Rows))
	}
	c := page.Rows[0].Capabilities
	if c == nil || c.DeviceLimit != 10 || c.RetentionDays != 90 {
		t.Fatalf("unexpected capabilities: %+v", c)
	}
}

func TestListInternalUserAggregates_UpdatedSinceFiltersOlderUsers(t *testing.T) {
	store := NewTestStore(t)

	// Old user: created 2 days ago, no devices, no capabilities.
	if err := store.CreateUser("old-user"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := store.db.Exec(
		`UPDATE users SET created_at = NOW() - interval '2 days' WHERE id = 'old-user'`,
	); err != nil {
		t.Fatalf("backdate user: %v", err)
	}

	// Fresh user: created just now.
	if err := store.CreateUser("fresh-user"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	cutoff := time.Now().Add(-1 * time.Hour)
	page, err := store.ListInternalUserAggregates(InternalUsersFilter{
		Limit:        100,
		UpdatedSince: &cutoff,
	})
	if err != nil {
		t.Fatalf("ListInternalUserAggregates: %v", err)
	}
	if len(page.Rows) != 1 || page.Rows[0].UserID != "fresh-user" {
		t.Fatalf("expected only fresh-user, got %+v", page.Rows)
	}
}

func TestListInternalUserAggregates_UpdatedSinceCatchesDeviceActivity(t *testing.T) {
	store := NewTestStore(t)

	// User and its row are old, but a device just pushed.
	if err := store.CreateUser("user-with-active-device"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := store.db.Exec(
		`UPDATE users SET created_at = NOW() - interval '30 days' WHERE id = 'user-with-active-device'`,
	); err != nil {
		t.Fatalf("backdate user: %v", err)
	}
	if _, err := store.db.Exec(`
		INSERT INTO devices (id, user_id, hostname, source_key, paired_at, last_push_at)
		VALUES ('dev-active','user-with-active-device','h','sk', NOW() - interval '30 days', NOW())
	`); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	cutoff := time.Now().Add(-1 * time.Hour)
	page, err := store.ListInternalUserAggregates(InternalUsersFilter{
		Limit:        100,
		UpdatedSince: &cutoff,
	})
	if err != nil {
		t.Fatalf("ListInternalUserAggregates: %v", err)
	}
	if len(page.Rows) != 1 || page.Rows[0].UserID != "user-with-active-device" {
		t.Fatalf("expected user-with-active-device to be included via device activity, got %+v", page.Rows)
	}
}

func TestListInternalUserAggregates_ExcludesDemoByDefault(t *testing.T) {
	store := NewTestStore(t)
	if err := store.CreateUser("real-user"); err != nil {
		t.Fatalf("CreateUser real: %v", err)
	}
	if err := store.CreateUser("demo-user"); err != nil {
		t.Fatalf("CreateUser demo: %v", err)
	}
	if _, err := store.db.Exec(
		`UPDATE users SET is_demo = TRUE WHERE id = 'demo-user'`,
	); err != nil {
		t.Fatalf("flag demo: %v", err)
	}

	// Default (IncludeDemo=false) excludes demo.
	page, err := store.ListInternalUserAggregates(InternalUsersFilter{Limit: 100})
	if err != nil {
		t.Fatalf("default: %v", err)
	}
	if len(page.Rows) != 1 || page.Rows[0].UserID != "real-user" {
		t.Fatalf("expected only real-user, got %+v", page.Rows)
	}

	// IncludeDemo=true brings demo back.
	page2, err := store.ListInternalUserAggregates(InternalUsersFilter{Limit: 100, IncludeDemo: true})
	if err != nil {
		t.Fatalf("include demo: %v", err)
	}
	if len(page2.Rows) != 2 {
		t.Fatalf("expected 2 rows with IncludeDemo, got %d", len(page2.Rows))
	}
}

func TestListInternalUserAggregates_PaginatesByCursor(t *testing.T) {
	store := NewTestStore(t)
	// Seed 5 users with monotonically increasing created_at.
	for i := 0; i < 5; i++ {
		uid := fmt.Sprintf("u%d", i)
		if err := store.CreateUser(uid); err != nil {
			t.Fatalf("CreateUser %s: %v", uid, err)
		}
		if _, err := store.db.Exec(
			`UPDATE users SET created_at = $1 WHERE id = $2`,
			time.Date(2026, 5, 1+i, 0, 0, 0, 0, time.UTC), uid,
		); err != nil {
			t.Fatalf("backdate %s: %v", uid, err)
		}
	}

	// Page 1: limit 2.
	p1, err := store.ListInternalUserAggregates(InternalUsersFilter{Limit: 2})
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if len(p1.Rows) != 2 || p1.Rows[0].UserID != "u0" || p1.Rows[1].UserID != "u1" {
		t.Fatalf("page 1 unexpected: %+v", p1.Rows)
	}
	if p1.NextCursor == "" {
		t.Fatal("page 1 should have a NextCursor")
	}

	// Page 2 via cursor.
	cur, err := DecodeInternalCursor(p1.NextCursor)
	if err != nil {
		t.Fatalf("decode cursor: %v", err)
	}
	p2, err := store.ListInternalUserAggregates(InternalUsersFilter{
		Limit:  2,
		Cursor: &cur,
	})
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if len(p2.Rows) != 2 || p2.Rows[0].UserID != "u2" || p2.Rows[1].UserID != "u3" {
		t.Fatalf("page 2 unexpected: %+v", p2.Rows)
	}
	if p2.NextCursor == "" {
		t.Fatal("page 2 should still have a NextCursor (1 row left)")
	}

	// Page 3: last row, no further cursor.
	cur2, err := DecodeInternalCursor(p2.NextCursor)
	if err != nil {
		t.Fatalf("decode cursor 2: %v", err)
	}
	p3, err := store.ListInternalUserAggregates(InternalUsersFilter{
		Limit:  2,
		Cursor: &cur2,
	})
	if err != nil {
		t.Fatalf("page 3: %v", err)
	}
	if len(p3.Rows) != 1 || p3.Rows[0].UserID != "u4" {
		t.Fatalf("page 3 unexpected: %+v", p3.Rows)
	}
	if p3.NextCursor != "" {
		t.Fatalf("page 3 should not have a NextCursor, got %q", p3.NextCursor)
	}
}

// mustIssueAndCompleteDeviceCode issues a device code, completes it for the
// given userID/deviceID, and returns the device_code string ready for
// PollDeviceCode.
func mustIssueAndCompleteDeviceCode(t *testing.T, s *Store, userID, deviceID string) string {
	t.Helper()
	startResp, _, err := s.CreateDeviceCode("test-host", "", "", "")
	if err != nil {
		t.Fatalf("mustIssueAndCompleteDeviceCode CreateDeviceCode: %v", err)
	}
	token := generateStoreToken()
	if err := s.CompleteDeviceCode(startResp.UserCode, userID, deviceID, token); err != nil {
		t.Fatalf("mustIssueAndCompleteDeviceCode CompleteDeviceCode: %v", err)
	}
	return startResp.DeviceCode
}

func TestPollDeviceCode_ReturnsDisplayName(t *testing.T) {
	s := newTestStore(t)
	userID, deviceID, _, err := s.UpsertOAuthUser("github", "42", "alice@example.com", true, "Alice Example", "host", "")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	cases := []struct {
		name             string
		usersDisplayName string
		want             string
	}{
		{"oauth_name_when_user_unset", "", "Alice Example"},
		{"user_override_wins", "Custom", "Custom"},
		{"user_blank_falls_back_to_oauth", "", "Alice Example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Issue a fresh device code per sub-test so polling is always valid.
			code := mustIssueAndCompleteDeviceCode(t, s, userID, deviceID)

			if tc.usersDisplayName == "" {
				_, _ = s.DB().Exec(`UPDATE users SET display_name = NULL WHERE id = $1`, userID)
			} else {
				_, _ = s.DB().Exec(`UPDATE users SET display_name = $1 WHERE id = $2`, tc.usersDisplayName, userID)
			}
			resp, err := s.PollDeviceCode(code)
			if err != nil {
				t.Fatalf("poll: %v", err)
			}
			if resp.DisplayName == nil {
				t.Fatalf("DisplayName is nil; want %q", tc.want)
			}
			if *resp.DisplayName != tc.want {
				t.Fatalf("display_name = %q, want %q", *resp.DisplayName, tc.want)
			}
		})
	}
}
