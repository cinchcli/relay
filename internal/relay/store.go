package relay

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	cinchv1 "github.com/cinchcli/relay/internal/gen/cinch/v1"
	"github.com/cinchcli/relay/internal/protocol"
	"github.com/oklog/ulid/v2"
	_ "modernc.org/sqlite"
)

type Store struct {
	db       *sql.DB
	MediaDir string // directory for media files (images)
}

func NewStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}
	// SQLite is single-writer. Cap the connection pool to 1 so that in-memory
	// databases (used in tests) share a single connection — preventing the case
	// where a second pool connection sees a separate empty in-memory DB.
	db.SetMaxOpenConns(1)

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating db: %w", err)
	}

	mediaDir := filepath.Join(filepath.Dir(path), "media")
	if err := os.MkdirAll(mediaDir, 0755); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating media dir: %w", err)
	}

	return &Store{db: db, MediaDir: mediaDir}, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id          TEXT PRIMARY KEY,
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
			is_demo     INTEGER DEFAULT 0
			-- pair_token, token, token_migrated_at intentionally absent (OAuth-only)
		);

		CREATE TABLE IF NOT EXISTS clips (
			id           TEXT PRIMARY KEY,
			user_id      TEXT NOT NULL,
			content      TEXT NOT NULL,
			content_type TEXT DEFAULT 'text',
			source       TEXT DEFAULT 'local',
			label        TEXT DEFAULT '',
			byte_size    INTEGER DEFAULT 0,
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
			ttl          INTEGER DEFAULT 0,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);

		CREATE INDEX IF NOT EXISTS idx_clips_user_created ON clips(user_id, created_at DESC);

		CREATE TABLE IF NOT EXISTS devices (
			id           TEXT PRIMARY KEY,
			user_id      TEXT NOT NULL,
			hostname     TEXT NOT NULL,
			source_key   TEXT NOT NULL,
			clip_count   INTEGER DEFAULT 0,
			paired_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_push_at DATETIME,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);

		CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_user_source ON devices(user_id, source_key);

		CREATE TABLE IF NOT EXISTS settings (
			key   TEXT PRIMARY KEY,
			value TEXT
		);

		CREATE TABLE IF NOT EXISTS demo_stats (
			date       TEXT PRIMARY KEY,
			push_count INTEGER DEFAULT 0
		);

		CREATE TABLE IF NOT EXISTS device_codes (
			device_code TEXT PRIMARY KEY,
			user_code   TEXT UNIQUE NOT NULL,
			hostname    TEXT DEFAULT '',
			user_id     TEXT,
			device_id   TEXT,
			token       TEXT,
			status      TEXT DEFAULT 'pending',
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at  DATETIME NOT NULL
		);
	`)
	if err != nil {
		return err
	}

	// Add media_path column if not exists (Phase 2 migration)
	var hasMediaPath bool
	rows, err := db.Query("PRAGMA table_info(clips)")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dfltValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return err
		}
		if name == "media_path" {
			hasMediaPath = true
		}
	}
	if !hasMediaPath {
		_, err = db.Exec("ALTER TABLE clips ADD COLUMN media_path TEXT DEFAULT NULL")
		if err != nil {
			return err
		}
	}

	// Add is_demo column if not exists
	var hasIsDemo bool
	uRows, err := db.Query("PRAGMA table_info(users)")
	if err != nil {
		return err
	}
	defer uRows.Close()
	for uRows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dfltValue sql.NullString
		var pk int
		if err := uRows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return err
		}
		if name == "is_demo" {
			hasIsDemo = true
		}
	}
	if !hasIsDemo {
		_, err = db.Exec("ALTER TABLE users ADD COLUMN is_demo INTEGER DEFAULT 0")
		if err != nil {
			return err
		}
	}

	// Phase 2 migrations: per-device tokens + revocation.

	// devices.token — nullable during the 7-day migration window.
	var hasDeviceToken bool
	dRows, err := db.Query("PRAGMA table_info(devices)")
	if err != nil {
		return err
	}
	defer dRows.Close()
	for dRows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dfltValue sql.NullString
		var pk int
		if err := dRows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return err
		}
		if name == "token" {
			hasDeviceToken = true
		}
	}
	if !hasDeviceToken {
		if _, err = db.Exec("ALTER TABLE devices ADD COLUMN token TEXT"); err != nil {
			return err
		}
	}

	// devices.revoked_at
	var hasRevokedAt bool
	dRows2, err := db.Query("PRAGMA table_info(devices)")
	if err != nil {
		return err
	}
	defer dRows2.Close()
	for dRows2.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dfltValue sql.NullString
		var pk int
		if err := dRows2.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return err
		}
		if name == "revoked_at" {
			hasRevokedAt = true
		}
	}
	if !hasRevokedAt {
		if _, err = db.Exec("ALTER TABLE devices ADD COLUMN revoked_at DATETIME"); err != nil {
			return err
		}
	}

	// users.token_migrated_at
	var hasTokenMigratedAt bool
	uRows2, err := db.Query("PRAGMA table_info(users)")
	if err != nil {
		return err
	}
	defer uRows2.Close()
	for uRows2.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dfltValue sql.NullString
		var pk int
		if err := uRows2.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return err
		}
		if name == "token_migrated_at" {
			hasTokenMigratedAt = true
		}
	}
	if !hasTokenMigratedAt {
		if _, err = db.Exec("ALTER TABLE users ADD COLUMN token_migrated_at DATETIME"); err != nil {
			return err
		}
	}

	// Partial unique index: only enforce uniqueness for non-NULL device tokens.
	if _, err = db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_token ON devices(token) WHERE token IS NOT NULL`); err != nil {
		return err
	}

	// Phase 4 migration: remote_retention_days on devices
	var hasRetentionDays bool
	dRows3, err := db.Query("PRAGMA table_info(devices)")
	if err != nil {
		return err
	}
	defer dRows3.Close()
	for dRows3.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dfltValue sql.NullString
		var pk int
		if err := dRows3.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return err
		}
		if name == "remote_retention_days" {
			hasRetentionDays = true
		}
	}
	if !hasRetentionDays {
		if _, err = db.Exec("ALTER TABLE devices ADD COLUMN remote_retention_days INTEGER DEFAULT 30"); err != nil {
			return err
		}
	}

	// Phase 4.5 migration: encrypted column on clips (stores ciphertext flag; relay never inspects content)
	var hasEncrypted bool
	e1Rows, err := db.Query("PRAGMA table_info(clips)")
	if err != nil {
		return err
	}
	defer e1Rows.Close()
	for e1Rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dfltValue sql.NullString
		var pk int
		if err := e1Rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return err
		}
		if name == "encrypted" {
			hasEncrypted = true
		}
	}
	if !hasEncrypted {
		if _, err = db.Exec("ALTER TABLE clips ADD COLUMN encrypted INTEGER DEFAULT 0"); err != nil {
			return err
		}
	}

	// Phase 4.5 migration: public_key on devices (ECDH public key; safe to store — it's public)
	var hasPublicKey bool
	e2Rows, err := db.Query("PRAGMA table_info(devices)")
	if err != nil {
		return err
	}
	defer e2Rows.Close()
	for e2Rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dfltValue sql.NullString
		var pk int
		if err := e2Rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return err
		}
		if name == "public_key" {
			hasPublicKey = true
		}
	}
	if !hasPublicKey {
		if _, err = db.Exec("ALTER TABLE devices ADD COLUMN public_key TEXT"); err != nil {
			return err
		}
	}

	// Phase 4.5 migration: encrypted_key_bundle on devices (AES-GCM ciphertext of user_key; relay stores ciphertext only)
	var hasEncryptedKeyBundle bool
	e3Rows, err := db.Query("PRAGMA table_info(devices)")
	if err != nil {
		return err
	}
	defer e3Rows.Close()
	for e3Rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dfltValue sql.NullString
		var pk int
		if err := e3Rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return err
		}
		if name == "encrypted_key_bundle" {
			hasEncryptedKeyBundle = true
		}
	}
	if !hasEncryptedKeyBundle {
		if _, err = db.Exec("ALTER TABLE devices ADD COLUMN encrypted_key_bundle TEXT"); err != nil {
			return err
		}
	}

	// Phase 4.5 migration: ephemeral_public_key on devices (ECDH ephemeral public key; public, safe to store)
	var hasEphemeralPublicKey bool
	e4Rows, err := db.Query("PRAGMA table_info(devices)")
	if err != nil {
		return err
	}
	defer e4Rows.Close()
	for e4Rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dfltValue sql.NullString
		var pk int
		if err := e4Rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return err
		}
		if name == "ephemeral_public_key" {
			hasEphemeralPublicKey = true
		}
	}
	if !hasEphemeralPublicKey {
		if _, err = db.Exec("ALTER TABLE devices ADD COLUMN ephemeral_public_key TEXT"); err != nil {
			return err
		}
	}

	// Phase 4.5 migration: public_key_fingerprint on devices (first 8 bytes of SHA-256 of public key, hex)
	var hasPublicKeyFingerprint bool
	e5Rows, err := db.Query("PRAGMA table_info(devices)")
	if err != nil {
		return err
	}
	defer e5Rows.Close()
	for e5Rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dfltValue sql.NullString
		var pk int
		if err := e5Rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return err
		}
		if name == "public_key_fingerprint" {
			hasPublicKeyFingerprint = true
		}
	}
	if !hasPublicKeyFingerprint {
		if _, err = db.Exec("ALTER TABLE devices ADD COLUMN public_key_fingerprint TEXT"); err != nil {
			return err
		}
	}

	// Phase 5 migration: nickname on devices
	var hasNickname bool
	nkRows, err := db.Query("PRAGMA table_info(devices)")
	if err != nil {
		return err
	}
	defer nkRows.Close()
	for nkRows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dfltValue sql.NullString
		var pk int
		if err := nkRows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return err
		}
		if name == "nickname" {
			hasNickname = true
		}
	}
	if !hasNickname {
		if _, err = db.Exec("ALTER TABLE devices ADD COLUMN nickname TEXT"); err != nil {
			return err
		}
	}

	// OAuth migration: identity_provider and identity_subject on users.
	var hasIdentityProvider bool
	oaRows, err := db.Query("PRAGMA table_info(users)")
	if err != nil {
		return err
	}
	defer oaRows.Close()
	for oaRows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dfltValue sql.NullString
		var pk int
		if err := oaRows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return err
		}
		if name == "identity_provider" {
			hasIdentityProvider = true
		}
	}
	if !hasIdentityProvider {
		if _, err = db.Exec("ALTER TABLE users ADD COLUMN identity_provider TEXT"); err != nil {
			return err
		}
		if _, err = db.Exec("ALTER TABLE users ADD COLUMN identity_subject TEXT"); err != nil {
			return err
		}
	}
	if _, err = db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_identity
		ON users(identity_provider, identity_subject)
		WHERE identity_provider IS NOT NULL`); err != nil {
		return err
	}

	// Phase 2 migration: remove NOT NULL from users.token so the grace sweeper can NULL it.
	// SQLite requires a table rebuild to change column constraints.
	// Detect by reading the CREATE TABLE SQL; rebuild only if NOT NULL is present.
	var usersSQL string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='users'`).Scan(&usersSQL); err == nil {
		if strings.Contains(usersSQL, "token       TEXT UNIQUE NOT NULL") {
			if err := migrateDropUsersTokenNotNull(db); err != nil {
				return fmt.Errorf("users.token NOT NULL migration: %w", err)
			}
		}
	}

	// Login unification migration: machine_id on devices and device_codes.
	// Same Mac signing in via CLI and desktop should reuse one device row;
	// the dedup key is (user_id, machine_id) when machine_id is non-empty.
	if err := addColumnIfMissing(db, "devices", "machine_id", "TEXT"); err != nil {
		return err
	}
	if err := addColumnIfMissing(db, "device_codes", "machine_id", "TEXT"); err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_devices_user_machine
		ON devices(user_id, machine_id)
		WHERE machine_id IS NOT NULL AND revoked_at IS NULL`); err != nil {
		return err
	}

	// Phase 6: OAuth-only — drop legacy auth columns.
	// SQLite refuses ALTER TABLE DROP COLUMN on a column referenced by a
	// UNIQUE / non-partial index (e.g. the inline `pair_token TEXT UNIQUE`
	// from the legacy schema produces an `sqlite_autoindex_*` index). The
	// only portable workaround is a full table rebuild. This branch runs
	// only when at least one legacy column is still present, so it is a
	// no-op on fresh DBs.
	hasLegacy := false
	for _, col := range []string{"pair_token", "token", "token_migrated_at"} {
		exists, err := userColumnExists(db, col)
		if err != nil {
			return fmt.Errorf("check users.%s: %w", col, err)
		}
		if exists {
			hasLegacy = true
			break
		}
	}
	if hasLegacy {
		if err := migrateDropLegacyUserColumns(db); err != nil {
			return fmt.Errorf("dropping legacy user columns: %w", err)
		}
	}

	return nil
}

// migrateDropLegacyUserColumns rebuilds the users table with only the
// post-OAuth schema (id, created_at, is_demo, identity_provider,
// identity_subject), preserving rows. Used by the Phase 6 migration when
// any of the legacy auth columns (pair_token / token / token_migrated_at)
// are still present — those carried inline UNIQUE constraints that
// SQLite refuses to drop in place.
func migrateDropLegacyUserColumns(db *sql.DB) error {
	// Detect which optional columns are present BEFORE opening a
	// transaction — db.SetMaxOpenConns(1) means a probe inside the txn
	// would deadlock waiting for the only connection.
	hasIdentityProvider, err := userColumnExists(db, "identity_provider")
	if err != nil {
		return err
	}
	hasIdentitySubject, err := userColumnExists(db, "identity_subject")
	if err != nil {
		return err
	}
	hasIsDemo, err := userColumnExists(db, "is_demo")
	if err != nil {
		return err
	}

	_, _ = db.Exec("PRAGMA foreign_keys=OFF")
	defer db.Exec("PRAGMA foreign_keys=ON")

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`
		CREATE TABLE users_new (
			id                TEXT PRIMARY KEY,
			created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
			is_demo           INTEGER DEFAULT 0,
			identity_provider TEXT,
			identity_subject  TEXT
		)`); err != nil {
		return err
	}

	isDemoCol := "0"
	if hasIsDemo {
		isDemoCol = "COALESCE(is_demo, 0)"
	}
	identityProviderCol := "NULL"
	if hasIdentityProvider {
		identityProviderCol = "identity_provider"
	}
	identitySubjectCol := "NULL"
	if hasIdentitySubject {
		identitySubjectCol = "identity_subject"
	}
	copyStmt := fmt.Sprintf(
		`INSERT INTO users_new (id, created_at, is_demo, identity_provider, identity_subject)
		 SELECT id, created_at, %s, %s, %s FROM users`,
		isDemoCol, identityProviderCol, identitySubjectCol,
	)
	if _, err := tx.Exec(copyStmt); err != nil {
		return err
	}

	if _, err := tx.Exec(`DROP TABLE users`); err != nil {
		return err
	}
	if _, err := tx.Exec(`ALTER TABLE users_new RENAME TO users`); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_identity
		 ON users(identity_provider, identity_subject)
		 WHERE identity_provider IS NOT NULL`,
	); err != nil {
		return err
	}

	return tx.Commit()
}

// userColumnExists returns true when the named column is present on the users table.
// Used by the Phase 6 column-drop migration to keep DROP COLUMN idempotent.
func userColumnExists(db *sql.DB, col string) (bool, error) {
	rows, err := db.Query(`PRAGMA table_info(users)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == col {
			return true, nil
		}
	}
	return false, rows.Err()
}

// addColumnIfMissing inspects PRAGMA table_info(table) and runs ALTER TABLE
// only when `column` is absent. Used for idempotent forward migrations.
func addColumnIfMissing(db *sql.DB, table, column, columnType string) error {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	_, err = db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, columnType))
	return err
}

// migrateDropUsersTokenNotNull rebuilds the users table without NOT NULL on token.
// SQLite does not support ALTER COLUMN — the 12-step DDL process is required.
func migrateDropUsersTokenNotNull(db *sql.DB) error {
	// Enable foreign keys off for the rebuild.
	_, _ = db.Exec("PRAGMA foreign_keys=OFF")
	defer db.Exec("PRAGMA foreign_keys=ON")

	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users_new (
			id                  TEXT PRIMARY KEY,
			created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
			is_demo             INTEGER DEFAULT 0,
			identity_provider   TEXT,
			identity_subject    TEXT
		);
		INSERT INTO users_new (id, created_at, is_demo, identity_provider, identity_subject)
			SELECT id, created_at, COALESCE(is_demo,0), NULL, NULL
			FROM users;
		DROP TABLE users;
		ALTER TABLE users_new RENAME TO users;
	`)
	return err
}

func (s *Store) Close() error {
	return s.db.Close()
}

// Migrate runs all schema migration steps against the underlying database.
// NewStore already invokes this; it is exposed so tests can verify
// idempotence by re-running migrations against an open Store.
func (s *Store) Migrate() error {
	return migrate(s.db)
}

// CreateUser inserts a new user row. Tokens live on the devices table
// after the OAuth-only migration; users carries identity columns only.
func (s *Store) CreateUser(id string) error {
	_, err := s.db.Exec("INSERT INTO users (id) VALUES (?)", id)
	return err
}

// UpsertOAuthUser finds or creates a user by OAuth identity and provisions a device token.
// provider is "github" or "google"; subject is the stable provider-side user ID.
// machineID, when non-empty, deduplicates same-machine sign-ins (CLI + desktop on
// the same Mac) onto a single device row, rotating its token on each sign-in.
// Returns (userID, deviceID, deviceToken) ready to pass to CompleteDeviceCode.
func (s *Store) UpsertOAuthUser(provider, subject, hostname, machineID string) (string, string, string, error) {
	if hostname == "" {
		hostname = "unknown"
	}

	// Try to find existing user.
	var userID string
	err := s.db.QueryRow(
		"SELECT id FROM users WHERE identity_provider = ? AND identity_subject = ?",
		provider, subject,
	).Scan(&userID)

	if err == sql.ErrNoRows {
		// New OAuth user — create account. The users.token column was
		// dropped in the OAuth-only migration; tokens live on devices.
		userID = ulid.Make().String()
		_, err = s.db.Exec(
			`INSERT INTO users (id, identity_provider, identity_subject) VALUES (?, ?, ?)`,
			userID, provider, subject,
		)
		if err != nil {
			return "", "", "", fmt.Errorf("creating oauth user: %w", err)
		}
	} else if err != nil {
		return "", "", "", fmt.Errorf("looking up oauth user: %w", err)
	}

	// Reuse an existing device row when this machine has signed in before
	// (CLI + desktop on the same Mac). Falls back to source_key matching
	// for backward compatibility with rows that pre-date the machine_id
	// migration. New rows get the current machine_id backfilled.
	deviceToken := generateStoreToken()
	sourceKey := "remote:" + hostname

	var existingID string
	if machineID != "" {
		_ = s.db.QueryRow(
			`SELECT id FROM devices WHERE user_id = ? AND machine_id = ? AND revoked_at IS NULL
			 ORDER BY paired_at DESC LIMIT 1`,
			userID, machineID,
		).Scan(&existingID)
	}
	if existingID == "" {
		// Legacy path: dedup on (user_id, source_key) and backfill machine_id
		// onto the matched row so future sign-ins prefer the new key.
		_ = s.db.QueryRow(
			`SELECT id FROM devices WHERE user_id = ? AND source_key = ? AND revoked_at IS NULL
			 ORDER BY paired_at DESC LIMIT 1`,
			userID, sourceKey,
		).Scan(&existingID)
	}

	if existingID != "" {
		var args []interface{}
		query := `UPDATE devices SET token = ?, hostname = ?`
		args = append(args, deviceToken, hostname)
		if machineID != "" {
			query += `, machine_id = ?`
			args = append(args, machineID)
		}
		query += ` WHERE id = ?`
		args = append(args, existingID)
		if _, err := s.db.Exec(query, args...); err != nil {
			return "", "", "", fmt.Errorf("rotating device token: %w", err)
		}
		return userID, existingID, deviceToken, nil
	}

	// Fresh device row.
	deviceID := ulid.Make().String()
	var insertMachineID interface{}
	if machineID != "" {
		insertMachineID = machineID
	}
	_, err = s.db.Exec(
		`INSERT INTO devices (id, user_id, hostname, source_key, token, machine_id)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(user_id, source_key) DO UPDATE SET
		   token = excluded.token,
		   machine_id = COALESCE(excluded.machine_id, devices.machine_id),
		   revoked_at = NULL`,
		deviceID, userID, hostname, sourceKey, deviceToken, insertMachineID,
	)
	if err != nil {
		return "", "", "", fmt.Errorf("provisioning device: %w", err)
	}
	// On conflict the INSERT doesn't return the existing row id; fetch it.
	_ = s.db.QueryRow(
		"SELECT id FROM devices WHERE user_id = ? AND source_key = ?", userID, sourceKey,
	).Scan(&deviceID)

	return userID, deviceID, deviceToken, nil
}

// UserByToken returns the user ID for a given device token.
// After the OAuth-only migration, the users table no longer carries a
// token column — every active token lives on devices.token. Demo
// users are still gated by the 10-minute TTL via the joined users row.
func (s *Store) UserByToken(token string) (string, error) {
	var id string
	err := s.db.QueryRow(
		`SELECT u.id FROM users u
		 JOIN devices d ON d.user_id = u.id
		 WHERE d.token = ? AND d.revoked_at IS NULL
		 AND (u.is_demo = 0 OR u.created_at > datetime('now', '-10 minutes'))`,
		token,
	).Scan(&id)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("invalid token")
	}
	return id, err
}

// IsDemoUser checks if a user ID belongs to a demo session.
func (s *Store) IsDemoUser(userID string) (bool, error) {
	var isDemo int
	err := s.db.QueryRow("SELECT is_demo FROM users WHERE id = ?", userID).Scan(&isDemo)
	if err != nil {
		return false, err
	}
	return isDemo == 1, nil
}

// ── Phase 2: per-device token methods ──────────────────────────────────────

// DeviceIDByToken returns the device_id for an active or revoked per-device token.
// If err == sql.ErrNoRows, the token is not a per-device token (caller falls back to users.token).
func (s *Store) DeviceIDByToken(token string) (deviceID string, revoked bool, err error) {
	var revokedAt sql.NullTime
	err = s.db.QueryRow(
		`SELECT id, revoked_at FROM devices WHERE token = ?`, token,
	).Scan(&deviceID, &revokedAt)
	if err != nil {
		return "", false, err
	}
	return deviceID, revokedAt.Valid, nil
}

// DeviceOwner returns the user_id owning a device.
// Returns sql.ErrNoRows if device does not exist (handler maps to 404, NOT 403).
func (s *Store) DeviceOwner(deviceID string) (userID string, err error) {
	err = s.db.QueryRow("SELECT user_id FROM devices WHERE id = ?", deviceID).Scan(&userID)
	return
}

// RevokeDevice soft-deletes a device by setting revoked_at. Idempotent.
func (s *Store) RevokeDevice(deviceID string) (revokedAt time.Time, err error) {
	_, err = s.db.Exec(
		`UPDATE devices SET revoked_at = CURRENT_TIMESTAMP WHERE id = ? AND revoked_at IS NULL`,
		deviceID,
	)
	if err != nil {
		return time.Time{}, err
	}
	var rt time.Time
	err = s.db.QueryRow(`SELECT revoked_at FROM devices WHERE id = ?`, deviceID).Scan(&rt)
	return rt, err
}

// RegisterDeviceWithToken inserts a new device row with a pre-generated deviceID and token.
// Used by the lazy-migration WS upgrade path. Fails loudly if called twice for the same ID.
func (s *Store) RegisterDeviceWithToken(userID, deviceID, hostname, token string) error {
	if hostname == "" {
		hostname = "unknown"
	}
	sourceKey := "remote:" + hostname
	_, err := s.db.Exec(
		`INSERT INTO devices (id, user_id, hostname, source_key, token, paired_at)
		 VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		deviceID, userID, hostname, sourceKey, token,
	)
	return err
}

// SaveClip persists a clip and returns it.
//
// `req.MediaPath` and `req.Ttl` are proto3 `optional` fields and arrive as
// `*string` / `*int64`; the SQLite columns store the underlying value (or
// NULL when nil). `created_at` is rendered as RFC 3339 to match the wire
// shape the proto emits — the column type is TEXT so this round-trips
// cleanly.
func (s *Store) SaveClip(userID string, req *cinchv1.PushClipRequest) (*cinchv1.Clip, error) {
	id := ulid.Make().String()
	now := time.Now().UTC()

	contentType := req.ContentType
	if contentType == "" {
		contentType = protocol.ContentText
	}

	byteSize := int64(len(req.Content))
	if byteSize == 0 && req.ByteSize > 0 {
		byteSize = req.ByteSize
	}

	mediaPath := ""
	if req.MediaPath != nil {
		mediaPath = *req.MediaPath
	}

	clip := &cinchv1.Clip{
		ClipId:      id,
		UserId:      userID,
		Content:     req.Content,
		ContentType: contentType,
		Source:      req.Source,
		Label:       req.Label,
		ByteSize:    byteSize,
		CreatedAt:   protocol.FormatRFC3339(now),
		Encrypted:   req.Encrypted,
	}
	if mediaPath != "" {
		clip.MediaPath = &mediaPath
	}

	var ttl int64
	if req.Ttl != nil {
		ttl = *req.Ttl
	}

	_, err := s.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, label, byte_size, media_path, created_at, ttl, encrypted)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		clip.ClipId, clip.UserId, clip.Content, clip.ContentType,
		clip.Source, clip.Label, clip.ByteSize, sql.NullString{String: mediaPath, Valid: mediaPath != ""},
		now, ttl, clip.Encrypted,
	)
	if err != nil {
		return nil, fmt.Errorf("saving clip: %w", err)
	}

	return clip, nil
}

// ListClips returns recent clips for a user.
func (s *Store) ListClips(userID string, limit int) ([]*cinchv1.Clip, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	rows, err := s.db.Query(
		`SELECT id, user_id, content, content_type, source, label, byte_size, media_path, created_at, encrypted
		 FROM clips WHERE user_id = ? ORDER BY created_at DESC LIMIT ?`,
		userID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	clips := make([]*cinchv1.Clip, 0)
	for rows.Next() {
		c := &cinchv1.Clip{}
		var mediaPath sql.NullString
		var createdAt time.Time
		if err := rows.Scan(&c.ClipId, &c.UserId, &c.Content, &c.ContentType, &c.Source, &c.Label, &c.ByteSize, &mediaPath, &createdAt, &c.Encrypted); err != nil {
			return nil, err
		}
		if mediaPath.Valid && mediaPath.String != "" {
			s := mediaPath.String
			c.MediaPath = &s
		}
		c.CreatedAt = protocol.FormatRFC3339(createdAt)
		clips = append(clips, c)
	}
	return clips, rows.Err()
}

// DeleteClip removes a clip by ID, scoped to the user.
func (s *Store) DeleteClip(userID, clipID string) error {
	res, err := s.db.Exec("DELETE FROM clips WHERE id = ? AND user_id = ?", clipID, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("clip not found")
	}
	return nil
}

// DeleteClipReturningMedia removes a clip and returns its media_path key (or ""
// if none). The caller is responsible for deleting the key from the object store.
func (s *Store) DeleteClipReturningMedia(userID, clipID string) (mediaPath string, err error) {
	_ = s.db.QueryRow(
		"SELECT COALESCE(media_path, '') FROM clips WHERE id = ? AND user_id = ?",
		clipID, userID,
	).Scan(&mediaPath)

	res, err := s.db.Exec("DELETE FROM clips WHERE id = ? AND user_id = ?", clipID, userID)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", fmt.Errorf("clip not found")
	}
	return mediaPath, nil
}

// GetLatestClipBySource returns the most recent clip from a specific source.
func (s *Store) GetLatestClipBySource(userID, source string) (*cinchv1.Clip, error) {
	c := &cinchv1.Clip{}
	var mediaPath sql.NullString
	var createdAt time.Time
	err := s.db.QueryRow(
		`SELECT id, user_id, content, content_type, source, label, byte_size, media_path, created_at, encrypted
		 FROM clips WHERE user_id = ? AND source = ?
		 ORDER BY created_at DESC LIMIT 1`,
		userID, source,
	).Scan(&c.ClipId, &c.UserId, &c.Content, &c.ContentType, &c.Source, &c.Label, &c.ByteSize, &mediaPath, &createdAt, &c.Encrypted)
	if mediaPath.Valid && mediaPath.String != "" {
		s := mediaPath.String
		c.MediaPath = &s
	}
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no clips from source %s", source)
	}
	if err != nil {
		return nil, err
	}
	c.CreatedAt = protocol.FormatRFC3339(createdAt)
	return c, nil
}

// UpdateDeviceActivity increments clip count and updates last_push_at.
func (s *Store) UpdateDeviceActivity(userID, source string) error {
	_, err := s.db.Exec(
		`UPDATE devices SET clip_count = clip_count + 1, last_push_at = CURRENT_TIMESTAMP
		 WHERE user_id = ? AND source_key = ?`,
		userID, source,
	)
	return err
}

// GetSetting reads a value from the settings table.
func (s *Store) GetSetting(key string) (string, error) {
	var val string
	err := s.db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&val)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return val, err
}

// SetSetting writes a value to the settings table.
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", key, value)
	return err
}

// GetMediaTotalBytes returns the tracked cumulative media size.
func (s *Store) GetMediaTotalBytes() (int64, error) {
	val, err := s.GetSetting("media_total_bytes")
	if err != nil || val == "" {
		return 0, err
	}
	return strconv.ParseInt(val, 10, 64)
}

// AddMediaBytes increments the tracked media size.
func (s *Store) AddMediaBytes(n int64) error {
	current, _ := s.GetMediaTotalBytes()
	return s.SetSetting("media_total_bytes", strconv.FormatInt(current+n, 10))
}

// SubMediaBytes decrements the tracked media size.
func (s *Store) SubMediaBytes(n int64) error {
	current, _ := s.GetMediaTotalBytes()
	newVal := current - n
	if newVal < 0 {
		newVal = 0
	}
	return s.SetSetting("media_total_bytes", strconv.FormatInt(newVal, 10))
}

// GetClipMediaPath returns the media_path for a clip (for cascade delete).
func (s *Store) GetClipMediaPath(userID, clipID string) (string, error) {
	var mp sql.NullString
	err := s.db.QueryRow("SELECT media_path FROM clips WHERE id = ? AND user_id = ?", clipID, userID).Scan(&mp)
	if err != nil {
		return "", err
	}
	if mp.Valid {
		return mp.String, nil
	}
	return "", nil
}

// CleanupMediaOverLimit deletes oldest media files until under the threshold.
func (s *Store) CleanupMediaOverLimit(maxBytes int64) error {
	total, err := s.GetMediaTotalBytes()
	if err != nil || total <= maxBytes {
		return err
	}

	rows, err := s.db.Query(
		`SELECT id, user_id, media_path, byte_size FROM clips
		 WHERE media_path IS NOT NULL AND media_path != ''
		 ORDER BY created_at ASC`,
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	target := maxBytes * 80 / 100 // clean down to 80%
	for rows.Next() && total > target {
		var id, userID, mediaPath string
		var byteSize int
		if err := rows.Scan(&id, &userID, &mediaPath, &byteSize); err != nil {
			continue
		}
		fullPath := filepath.Join(s.MediaDir, filepath.Base(mediaPath))
		os.Remove(fullPath)
		s.db.Exec("DELETE FROM clips WHERE id = ?", id)
		total -= int64(byteSize)
	}

	s.SetSetting("media_total_bytes", strconv.FormatInt(total, 10))
	return nil
}

// ReconcileMedia deletes orphaned media files on startup.
func (s *Store) ReconcileMedia() error {
	entries, err := os.ReadDir(s.MediaDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		var count int
		s.db.QueryRow("SELECT COUNT(*) FROM clips WHERE media_path = ?", "media/"+name).Scan(&count)
		if count == 0 {
			os.Remove(filepath.Join(s.MediaDir, name))
		}
	}
	return nil
}

// ListDevices returns all non-revoked devices for a user.
//
// Timestamps come out of SQLite as `time.Time` and are converted to RFC
// 3339 strings to match the proto wire shape. `clip_count` is widened from
// SQLite's int into the proto's `int32`.
func (s *Store) ListDevices(userID string) ([]*cinchv1.Device, error) {
	rows, err := s.db.Query(
		`SELECT id, hostname, source_key, clip_count, paired_at, last_push_at, COALESCE(public_key, ''), COALESCE(nickname, '')
		 FROM devices WHERE user_id = ? AND revoked_at IS NULL ORDER BY last_push_at DESC NULLS LAST`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []*cinchv1.Device
	for rows.Next() {
		d := &cinchv1.Device{}
		var pairedAt time.Time
		var lastPush sql.NullTime
		var clipCount int
		if err := rows.Scan(&d.Id, &d.Hostname, &d.SourceKey, &clipCount, &pairedAt, &lastPush, &d.PublicKey, &d.Nickname); err != nil {
			return nil, err
		}
		d.ClipCount = int32(clipCount)
		d.PairedAt = protocol.FormatRFC3339(pairedAt)
		if lastPush.Valid {
			d.LastPushAt = protocol.FormatRFC3339Ptr(&lastPush.Time)
		}
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

// SetDeviceNickname sets or clears the nickname for a device.
// Empty string clears the nickname (stores NULL — falls back to hostname display).
func (s *Store) SetDeviceNickname(deviceID, nickname string) error {
	var val interface{}
	if nickname != "" {
		val = nickname
	}
	_, err := s.db.Exec("UPDATE devices SET nickname = ? WHERE id = ?", val, deviceID)
	return err
}

// ── Demo session methods ────────────────────────────────────────────

// CreateDemoUser creates a temporary demo user with a 10-minute TTL.
// It also cleans up expired demo sessions as a side effect. The token
// lives on a paired device row (the users.token column was dropped in
// the OAuth-only migration); the device row is reaped together with
// the user via foreign-key cascade in CleanupDemoSessions.
func (s *Store) CreateDemoUser(id, token string) error {
	s.CleanupDemoSessions()
	if _, err := s.db.Exec(
		"INSERT INTO users (id, is_demo) VALUES (?, 1)", id,
	); err != nil {
		return err
	}
	deviceID := ulid.Make().String()
	return s.RegisterDeviceWithToken(id, deviceID, "demo", token)
}

// CleanupDemoSessions deletes expired demo users and their clips
// (and devices, now that the demo token lives on a device row).
func (s *Store) CleanupDemoSessions() {
	s.db.Exec("DELETE FROM clips WHERE user_id IN (SELECT id FROM users WHERE is_demo = 1 AND created_at <= datetime('now', '-10 minutes'))")
	s.db.Exec("DELETE FROM devices WHERE user_id IN (SELECT id FROM users WHERE is_demo = 1 AND created_at <= datetime('now', '-10 minutes'))")
	s.db.Exec("DELETE FROM users WHERE is_demo = 1 AND created_at <= datetime('now', '-10 minutes')")
}

// DemoClipCount returns the number of clips for a demo user.
func (s *Store) DemoClipCount(userID string) (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM clips WHERE user_id = ?", userID).Scan(&count)
	return count, err
}

// ── Phase 4: device-code flow methods ──────────────────────────────────────

// generateStoreToken creates a 32-byte hex token (duplicates handler.go's generateToken
// to avoid import cycles).
func generateStoreToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// generateUserCode creates an 8-char uppercase alphanumeric code formatted as XXXX-XXXX.
// Uses rejection sampling to eliminate modular bias (256 % 36 == 4 would bias A-D without it).
func generateUserCode() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const n = len(chars)        // 36
	const max = 256 - (256 % n) // 252 — reject values >= this to eliminate bias
	var result [8]byte
	i := 0
	for i < 8 {
		var b [1]byte
		rand.Read(b[:])
		if int(b[0]) < max {
			result[i] = chars[int(b[0])%n]
			i++
		}
	}
	return string(result[:4]) + "-" + string(result[4:])
}

// CreateDeviceCode generates a device code and user code, inserts into device_codes,
// and returns the response (without VerificationURI — caller sets that).
// machineID is opaque and optional; the OAuth callback reads it back via
// DeviceCodeContext when upserting the device row so the same Mac signing
// in via CLI and desktop reuses one row.
func (s *Store) CreateDeviceCode(hostname, machineID string) (*cinchv1.DeviceCodeStartResponse, error) {
	deviceCode := generateStoreToken()
	userCode := generateUserCode()
	expiresAt := time.Now().UTC().Add(5 * time.Minute)

	var mi interface{}
	if machineID != "" {
		mi = machineID
	}

	_, err := s.db.Exec(
		`INSERT INTO device_codes (device_code, user_code, hostname, machine_id, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		deviceCode, userCode, hostname, mi, expiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("creating device code: %w", err)
	}

	intervalMs := int64(1000)
	return &cinchv1.DeviceCodeStartResponse{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ExpiresIn:  300,
		Interval:   3,
		IntervalMs: &intervalMs,
	}, nil
}

// CompleteDeviceCode marks a device code as complete with the provided credentials.
// Called when browser auth succeeds for a device-code flow.
func (s *Store) CompleteDeviceCode(userCode, userID, deviceID, token string) error {
	res, err := s.db.Exec(
		`UPDATE device_codes SET status = 'complete', user_id = ?, device_id = ?, token = ?
		 WHERE user_code = ? AND status = 'pending' AND expires_at > datetime('now')`,
		userID, deviceID, token, userCode,
	)
	if err != nil {
		return fmt.Errorf("completing device code: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("device code not found, already used, or expired")
	}
	return nil
}

// PollDeviceCode checks the status of a device code.
// Returns expired if past expiry, complete with credentials if done, pending otherwise.
func (s *Store) PollDeviceCode(deviceCode string) (*cinchv1.DeviceCodePollResponse, error) {
	var status, userID, deviceID, token sql.NullString
	var expiresAt time.Time

	err := s.db.QueryRow(
		`SELECT status, user_id, device_id, token, expires_at FROM device_codes WHERE device_code = ?`,
		deviceCode,
	).Scan(&status, &userID, &deviceID, &token, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("device code not found")
	}
	if err != nil {
		return nil, fmt.Errorf("polling device code: %w", err)
	}

	if time.Now().UTC().After(expiresAt) {
		return &cinchv1.DeviceCodePollResponse{Status: "expired"}, nil
	}

	if status.String == "complete" {
		t := token.String
		u := userID.String
		d := deviceID.String
		return &cinchv1.DeviceCodePollResponse{
			Status:   "complete",
			Token:    &t,
			UserId:   &u,
			DeviceId: &d,
		}, nil
	}

	return &cinchv1.DeviceCodePollResponse{Status: "pending"}, nil
}

// DeviceCodeHostname returns the hostname stored in a device_codes row by user_code.
// Used by the OAuth callback to pre-populate the device name.
// Kept for backward compatibility — prefer DeviceCodeContext for new code paths.
func (s *Store) DeviceCodeHostname(userCode string) (string, error) {
	hostname, _, err := s.DeviceCodeContext(userCode)
	return hostname, err
}

// DeviceCodeContext returns the hostname and machine_id stored when the
// device code was issued. The OAuth callback uses both: hostname for the
// device row label, machine_id for cross-app dedup on the same Mac.
func (s *Store) DeviceCodeContext(userCode string) (string, string, error) {
	var hostname string
	var machineID sql.NullString
	err := s.db.QueryRow(
		"SELECT hostname, machine_id FROM device_codes WHERE user_code = ?", userCode,
	).Scan(&hostname, &machineID)
	if err != nil {
		return "", "", err
	}
	return hostname, machineID.String, nil
}

// CleanupExpiredDeviceCodes removes device codes that expired more than 1 hour ago.
func (s *Store) CleanupExpiredDeviceCodes() error {
	_, err := s.db.Exec("DELETE FROM device_codes WHERE expires_at < datetime('now', '-1 hour')")
	return err
}

// SweepExpiredClips deletes remote clips older than retentionDays for a given user.
// Only remote clips (source LIKE 'remote:%') are swept; local clips are preserved.
func (s *Store) SweepExpiredClips(userID string, retentionDays int) (int, error) {
	result, err := s.db.Exec(
		`DELETE FROM clips WHERE user_id = ? AND source LIKE 'remote:%'
		 AND created_at < datetime('now', '-' || ? || ' days')`,
		userID, retentionDays,
	)
	if err != nil {
		return 0, err
	}
	n, _ := result.RowsAffected()
	return int(n), nil
}

// SweepAllUsersRetention iterates all users with remote_retention_days set
// and sweeps their expired remote clips.
func (s *Store) SweepAllUsersRetention() error {
	rows, err := s.db.Query(
		`SELECT DISTINCT d.user_id, d.remote_retention_days
		 FROM devices d
		 WHERE d.remote_retention_days IS NOT NULL
		 AND d.revoked_at IS NULL`,
	)
	if err != nil {
		return err
	}

	// Collect all user retention configs first to avoid holding a read lock
	// while SweepExpiredClips attempts writes (SQLite deadlock).
	type userRetention struct {
		userID string
		days   int
	}
	var users []userRetention
	for rows.Next() {
		var ur userRetention
		if err := rows.Scan(&ur.userID, &ur.days); err != nil {
			continue
		}
		users = append(users, ur)
	}
	rows.Close()

	for _, ur := range users {
		if count, err := s.SweepExpiredClips(ur.userID, ur.days); err == nil && count > 0 {
			log.Printf("retention sweep: deleted %d clips for user %s (>%d days)", count, ur.userID, ur.days)
		}
	}
	return nil
}

// SweepExpiredClipsReturningMedia deletes remote clips older than retentionDays
// for a user and returns the object store keys of any media that was removed.
func (s *Store) SweepExpiredClipsReturningMedia(userID string, retentionDays int) (count int, mediaPaths []string, err error) {
	rows, err := s.db.Query(
		`SELECT id, COALESCE(media_path, '') FROM clips
		  WHERE user_id = ? AND source LIKE 'remote:%'
		    AND created_at < datetime('now', '-' || ? || ' days')`,
		userID, retentionDays,
	)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()

	type row struct{ id, key string }
	var toDelete []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.key); err != nil {
			continue
		}
		toDelete = append(toDelete, r)
	}
	rows.Close()

	for _, r := range toDelete {
		if _, err := s.db.Exec("DELETE FROM clips WHERE id = ?", r.id); err != nil {
			continue
		}
		count++
		if r.key != "" {
			mediaPaths = append(mediaPaths, r.key)
		}
	}
	return count, mediaPaths, nil
}

// SweepAllUsersRetentionReturningMedia sweeps all users' expired clips and
// collects the media keys that were deleted so callers can remove them from
// the object store.
func (s *Store) SweepAllUsersRetentionReturningMedia() (mediaPaths []string, err error) {
	rows, err := s.db.Query(
		`SELECT DISTINCT d.user_id, d.remote_retention_days
		  FROM devices d
		  WHERE d.remote_retention_days IS NOT NULL AND d.revoked_at IS NULL`,
	)
	if err != nil {
		return nil, err
	}

	type ur struct {
		userID string
		days   int
	}
	var users []ur
	for rows.Next() {
		var u ur
		if err := rows.Scan(&u.userID, &u.days); err != nil {
			continue
		}
		users = append(users, u)
	}
	rows.Close()

	for _, u := range users {
		count, paths, err := s.SweepExpiredClipsReturningMedia(u.userID, u.days)
		if err == nil && count > 0 {
			log.Printf("retention sweep: deleted %d clips for user %s (>%d days)", count, u.userID, u.days)
		}
		mediaPaths = append(mediaPaths, paths...)
	}
	return mediaPaths, nil
}

// UpdateDeviceRetention sets the remote_retention_days for a specific device.
// days must be between 7 and 365 inclusive.
func (s *Store) UpdateDeviceRetention(deviceID string, days int) error {
	if days < 7 || days > 365 {
		return fmt.Errorf("retention days must be between 7 and 365, got %d", days)
	}
	result, err := s.db.Exec(
		"UPDATE devices SET remote_retention_days = ? WHERE id = ? AND revoked_at IS NULL",
		days, deviceID,
	)
	if err != nil {
		return fmt.Errorf("updating retention: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("device not found or revoked: %s", deviceID)
	}
	return nil
}

// GetDemoStats returns today's demo push count.
func (s *Store) GetDemoStats() (int, error) {
	var count int
	today := time.Now().UTC().Format("2006-01-02")
	err := s.db.QueryRow("SELECT push_count FROM demo_stats WHERE date = ?", today).Scan(&count)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return count, err
}

// IncrementDemoCounter increments today's demo push counter.
func (s *Store) IncrementDemoCounter() error {
	today := time.Now().UTC().Format("2006-01-02")
	_, err := s.db.Exec(
		`INSERT INTO demo_stats (date, push_count) VALUES (?, 1)
		 ON CONFLICT(date) DO UPDATE SET push_count = push_count + 1`,
		today,
	)
	return err
}

// ── Phase 4.5: E2EE key exchange store methods ─────────────────────────────

// SetDevicePublicKey stores the X25519 public key and its fingerprint for a device.
// The public key is safe to store — it is not secret material.
// fingerprint is the first 4 bytes of SHA-256(raw_public_key_bytes), hex-encoded
// (8 chars). Returns sql.ErrNoRows when the device does not exist — callers map
// this to 404/NotFound so a stale token can't silently no-op the registration.
func (s *Store) SetDevicePublicKey(deviceID, pubKeyB64, fingerprint string) error {
	res, err := s.db.Exec(
		"UPDATE devices SET public_key = ?, public_key_fingerprint = ? WHERE id = ?",
		pubKeyB64, fingerprint, deviceID,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// GetDevicePublicKey returns the stored X25519 public key for a device.
// Returns an error if no public key has been registered for the device.
func (s *Store) GetDevicePublicKey(deviceID string) (string, error) {
	var key sql.NullString
	err := s.db.QueryRow("SELECT public_key FROM devices WHERE id = ?", deviceID).Scan(&key)
	if err != nil {
		return "", err
	}
	if !key.Valid || key.String == "" {
		return "", fmt.Errorf("no public key for device %s", deviceID)
	}
	return key.String, nil
}

// SaveKeyBundle persists the ECDH key bundle for a device.
// ephPubKeyB64 is the desktop's ephemeral X25519 public key.
// encryptedBundleB64 is the AES-GCM ciphertext of the user_key — relay stores ciphertext only.
func (s *Store) SaveKeyBundle(deviceID, ephPubKeyB64, encryptedBundleB64 string) error {
	_, err := s.db.Exec(
		"UPDATE devices SET ephemeral_public_key = ?, encrypted_key_bundle = ? WHERE id = ?",
		ephPubKeyB64, encryptedBundleB64, deviceID,
	)
	return err
}

// GetKeyBundle retrieves the stored ECDH key bundle for a device.
// Returns empty strings (no error) if the bundle is not yet available.
func (s *Store) GetKeyBundle(deviceID string) (ephPubKeyB64, encryptedBundleB64 string, err error) {
	var eph, bundle sql.NullString
	err = s.db.QueryRow(
		"SELECT ephemeral_public_key, encrypted_key_bundle FROM devices WHERE id = ?", deviceID,
	).Scan(&eph, &bundle)
	if err != nil {
		return "", "", err
	}
	if eph.Valid && bundle.Valid {
		return eph.String, bundle.String, nil
	}
	return "", "", nil // not yet available
}

// GetDeviceHostnameAndPubKey returns the hostname and X25519 public key
// for a device. Returns sql.ErrNoRows when the device is unknown.
// Empty pubKey means the device has not yet registered its key.
func (s *Store) GetDeviceHostnameAndPubKey(deviceID string) (hostname, pubKey string, err error) {
	var nullKey sql.NullString
	err = s.db.QueryRow(
		`SELECT hostname, public_key FROM devices WHERE id = ?`,
		deviceID,
	).Scan(&hostname, &nullKey)
	if err != nil {
		return "", "", err
	}
	if nullKey.Valid {
		pubKey = nullKey.String
	}
	return hostname, pubKey, nil
}

// GetKeyBundlePendingSince returns when the device first registered a
// public key without a corresponding key bundle. Used by clients to
// surface "awaiting key for X seconds" UX. Returns zero time when the
// bundle is present (not pending) or the device doesn't qualify.
func (s *Store) GetKeyBundlePendingSince(deviceID string) (time.Time, error) {
	var t time.Time
	err := s.db.QueryRow(
		`SELECT paired_at FROM devices
		 WHERE id = ? AND public_key IS NOT NULL AND encrypted_key_bundle IS NULL`,
		deviceID,
	).Scan(&t)
	if err == sql.ErrNoRows {
		return time.Time{}, nil
	}
	return t, err
}

// ListPendingKeyExchanges returns devices that have a public_key but no encrypted_key_bundle yet.
// These are devices waiting for the desktop to complete the ECDH key exchange.
// Each returned DeviceInfo includes PublicKey and PublicKeyFingerprint for relay-to-desktop delivery.
func (s *Store) ListPendingKeyExchanges(userID string) ([]*cinchv1.Device, error) {
	rows, err := s.db.Query(
		`SELECT id, hostname, COALESCE(public_key,''), COALESCE(public_key_fingerprint,'') FROM devices
		 WHERE user_id = ? AND public_key IS NOT NULL AND encrypted_key_bundle IS NULL
		 AND (revoked_at IS NULL)`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var devices []*cinchv1.Device
	for rows.Next() {
		d := &cinchv1.Device{}
		if err := rows.Scan(&d.Id, &d.Hostname, &d.PublicKey, &d.PublicKeyFingerprint); err != nil {
			return nil, err
		}
		devices = append(devices, d)
	}
	return devices, rows.Err()
}
