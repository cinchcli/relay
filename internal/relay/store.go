package relay

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	cinchv1 "github.com/cinchcli/relay/internal/cinchv1"
	"github.com/cinchcli/relay/internal/protocol"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/oklog/ulid/v2"
)

// idxClipsIdempotency is the name of the partial unique index on
// clips(user_id, idempotency_key). Keep in sync with the
// `CREATE UNIQUE INDEX IF NOT EXISTS idx_clips_idempotency` statement
// in migrate(); the race-recovery branch in SaveClip uses this exact
// name to identify 23505 unique_violation errors from that index.
const idxClipsIdempotency = "idx_clips_idempotency"

// Tombstone records that a clip was deleted, for offline-device sync.
type Tombstone struct {
	ClipID    string `json:"clip_id"`
	DeletedAt string `json:"deleted_at"`
}

// UserCapabilities stores plan-derived limits for a user.
// All zero values mean unlimited (self-host default).
type UserCapabilities struct {
	UserID         string
	DeviceLimit    int
	RetentionDays  int
	RateLimit      int       // requests per day; 0 = unlimited
	GraceExpiresAt time.Time // zero = no active grace period
}

type Store struct {
	db *sql.DB
}

func NewStore(dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}

	// Without an explicit cap, database/sql opens connections on demand up to
	// MaxOpenConns=0 (unlimited). Under traffic spikes that lets us blow past
	// Postgres' `max_connections` (typically 100–200 on managed instances
	// shared with other services), which surfaces as cascading "too many
	// clients" errors. 25 leaves headroom for the retention sweeper, the
	// grace sweeper, and the demo cleanup running alongside user traffic.
	// SetConnMaxLifetime forces stale conns to be recycled so long-running
	// processes don't accumulate connections that Postgres has already
	// closed server-side.
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("connecting to db: %w", err)
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating db: %w", err)
	}

	return &Store{db: db}, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id                TEXT PRIMARY KEY,
			created_at        TIMESTAMPTZ DEFAULT NOW(),
			is_demo           BOOLEAN DEFAULT FALSE,
			identity_provider TEXT,
			identity_subject  TEXT
		);

		CREATE TABLE IF NOT EXISTS clips (
			id           TEXT PRIMARY KEY,
			user_id      TEXT NOT NULL,
			content      TEXT NOT NULL,
			content_type TEXT DEFAULT 'text',
			source       TEXT DEFAULT 'local',
			label        TEXT DEFAULT '',
			byte_size    INTEGER DEFAULT 0,
			media_path   TEXT,
			created_at   TIMESTAMPTZ DEFAULT NOW(),
			encrypted    BOOLEAN DEFAULT FALSE,
			is_pinned    BOOLEAN NOT NULL DEFAULT FALSE,
			pin_note     TEXT,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);

		CREATE INDEX IF NOT EXISTS idx_clips_user_created ON clips(user_id, created_at DESC);

		CREATE TABLE IF NOT EXISTS devices (
			id                       TEXT PRIMARY KEY,
			user_id                  TEXT NOT NULL,
			hostname                 TEXT NOT NULL,
			source_key               TEXT NOT NULL,
			clip_count               INTEGER DEFAULT 0,
			paired_at                TIMESTAMPTZ DEFAULT NOW(),
			last_push_at             TIMESTAMPTZ,
			token                    TEXT,
			revoked_at               TIMESTAMPTZ,
			remote_retention_days    INTEGER DEFAULT 1,
			public_key               TEXT,
			public_key_fingerprint   TEXT,
			encrypted_key_bundle     TEXT,
			ephemeral_public_key     TEXT,
			nickname                 TEXT,
			machine_id               TEXT,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);

		CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_user_source ON devices(user_id, source_key);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_token ON devices(token) WHERE token IS NOT NULL;

		CREATE TABLE IF NOT EXISTS settings (
			key   TEXT PRIMARY KEY,
			value TEXT
		);

		CREATE TABLE IF NOT EXISTS demo_stats (
			date       TEXT PRIMARY KEY,
			push_count INTEGER DEFAULT 0
		);

		CREATE TABLE IF NOT EXISTS device_codes (
			device_code     TEXT PRIMARY KEY,
			user_code       TEXT UNIQUE NOT NULL,
			hostname        TEXT DEFAULT '',
			machine_id      TEXT,
			user_id         TEXT,
			device_id       TEXT,
			token           TEXT,
			status          TEXT DEFAULT 'pending',
			created_at      TIMESTAMPTZ DEFAULT NOW(),
			expires_at      TIMESTAMPTZ NOT NULL,
			pending_user_id TEXT,
			requester_ip    TEXT
		);

		CREATE TABLE IF NOT EXISTS clip_tombstones (
			clip_id    TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			deleted_at TIMESTAMPTZ DEFAULT NOW()
		);

		CREATE INDEX IF NOT EXISTS idx_tombstones_user_deleted ON clip_tombstones(user_id, deleted_at);

		CREATE TABLE IF NOT EXISTS user_capabilities (
			user_id          TEXT PRIMARY KEY REFERENCES users(id),
			device_limit     INTEGER NOT NULL DEFAULT 0,
			retention_days   INTEGER NOT NULL DEFAULT 0,
			rate_limit       INTEGER NOT NULL DEFAULT 0,
			grace_expires_at TIMESTAMPTZ,
			updated_at       TIMESTAMPTZ DEFAULT NOW()
		);

		CREATE TABLE IF NOT EXISTS api_request_counts (
			user_id TEXT NOT NULL,
			date    TEXT NOT NULL,
			count   INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (user_id, date)
		);

		CREATE TABLE IF NOT EXISTS oauth_identities (
			id             TEXT PRIMARY KEY,
			user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			provider       TEXT NOT NULL,
			subject        TEXT NOT NULL,
			email          TEXT,
			email_verified BOOLEAN NOT NULL DEFAULT FALSE,
			created_at     TIMESTAMPTZ DEFAULT NOW(),
			last_seen_at   TIMESTAMPTZ DEFAULT NOW()
		);

		CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_identities_provider_subject
			ON oauth_identities(provider, subject);
	`)
	if err != nil {
		return err
	}

	// Add invites table and new columns on users (invite-auth phase 2A).
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS invites (
			code_hash   TEXT PRIMARY KEY,
			created_by  TEXT REFERENCES users(id) ON DELETE SET NULL,
			label       TEXT,
			max_uses    INTEGER     NOT NULL DEFAULT 1,
			used_count  INTEGER     NOT NULL DEFAULT 0,
			created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			expires_at  TIMESTAMPTZ NOT NULL,
			revoked_at  TIMESTAMPTZ
		);

		CREATE INDEX IF NOT EXISTS idx_invites_created_by ON invites(created_by);

		ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin     BOOLEAN NOT NULL DEFAULT FALSE;
		ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT;

		ALTER TABLE oauth_identities ADD COLUMN IF NOT EXISTS display_name TEXT;
	`)
	if err != nil {
		return fmt.Errorf("invites + user columns migration: %w", err)
	}

	// Drop the partial index on email_verified before any type conversion — the old index
	// predicate uses "email_verified = 1" (integer) which blocks ALTER COLUMN TYPE BOOLEAN.
	if _, err = db.Exec(`DROP INDEX IF EXISTS idx_oauth_identities_email`); err != nil {
		return fmt.Errorf("dropping idx_oauth_identities_email: %w", err)
	}

	// Convert legacy INTEGER boolean columns to BOOLEAN (idempotent — skipped if already BOOLEAN).
	// Must run before partial indexes that reference these columns with boolean comparisons.
	boolCols := []struct{ table, col string }{
		{"users", "is_demo"},
		{"clips", "encrypted"},
		{"oauth_identities", "email_verified"},
	}
	for _, bc := range boolCols {
		var dataType string
		err := db.QueryRow(
			`SELECT data_type FROM information_schema.columns
			 WHERE table_name = $1 AND column_name = $2`, bc.table, bc.col,
		).Scan(&dataType)
		if err != nil {
			return fmt.Errorf("checking %s.%s type: %w", bc.table, bc.col, err)
		}
		if dataType == "integer" {
			// Drop DEFAULT first (PostgreSQL can't auto-cast integer default to boolean).
			if _, err := db.Exec(fmt.Sprintf(
				`ALTER TABLE %s ALTER COLUMN %s DROP DEFAULT`,
				bc.table, bc.col,
			)); err != nil {
				return fmt.Errorf("dropping default on %s.%s: %w", bc.table, bc.col, err)
			}
			if _, err := db.Exec(fmt.Sprintf(
				`ALTER TABLE %s ALTER COLUMN %s TYPE BOOLEAN USING %s::BOOLEAN`,
				bc.table, bc.col, bc.col,
			)); err != nil {
				return fmt.Errorf("converting %s.%s to BOOLEAN: %w", bc.table, bc.col, err)
			}
			if _, err := db.Exec(fmt.Sprintf(
				`ALTER TABLE %s ALTER COLUMN %s SET DEFAULT FALSE`,
				bc.table, bc.col,
			)); err != nil {
				return fmt.Errorf("restoring default on %s.%s: %w", bc.table, bc.col, err)
			}
		}
	}

	// Partial index: only index non-NULL emails that are verified.
	if _, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_oauth_identities_email
			ON oauth_identities(email) WHERE email IS NOT NULL AND email_verified = TRUE
	`); err != nil {
		return err
	}

	// Partial index for machine_id lookup on active devices.
	if _, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_devices_user_machine
			ON devices(user_id, machine_id)
			WHERE machine_id IS NOT NULL AND revoked_at IS NULL
	`); err != nil {
		return err
	}

	// Partial unique index on users identity (allows multiple NULLs).
	if _, err = db.Exec(`
		CREATE UNIQUE INDEX IF NOT EXISTS idx_users_identity
			ON users(identity_provider, identity_subject)
			WHERE identity_provider IS NOT NULL
	`); err != nil {
		return err
	}

	// Drop legacy auth columns from users if they exist (Phase 6 migration).
	for _, col := range []string{"pair_token", "token", "token_migrated_at"} {
		if _, err := db.Exec(fmt.Sprintf("ALTER TABLE users DROP COLUMN IF EXISTS %s", col)); err != nil {
			return fmt.Errorf("dropping users.%s: %w", col, err)
		}
	}

	// Add pin columns to clips table for existing databases.
	for _, stmt := range []string{
		`ALTER TABLE clips ADD COLUMN IF NOT EXISTS is_pinned BOOLEAN NOT NULL DEFAULT FALSE`,
		`ALTER TABLE clips ADD COLUMN IF NOT EXISTS pin_note TEXT`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("adding pin columns to clips: %w", err)
		}
	}

	// Add idempotency_key column + partial unique index for backlog-flush dedup.
	// The client backlog flusher (in cinchcli/cinch) sets idempotency_key on retried offline
	// captures; normal online pushes leave it NULL. The partial unique index
	// enforces (user_id, idempotency_key) uniqueness only when the key is set,
	// so unconstrained NULLs from online pushes remain allowed.
	for _, stmt := range []string{
		`ALTER TABLE clips ADD COLUMN IF NOT EXISTS idempotency_key TEXT`,
		// Index name must stay in sync with idxClipsIdempotency above.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_clips_idempotency
			ON clips(user_id, idempotency_key)
			WHERE idempotency_key IS NOT NULL`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("adding idempotency_key to clips: %w", err)
		}
	}

	// Add desktop-approval push columns to device_codes for existing databases.
	for _, stmt := range []string{
		`ALTER TABLE device_codes ADD COLUMN IF NOT EXISTS pending_user_id TEXT`,
		`ALTER TABLE device_codes ADD COLUMN IF NOT EXISTS requester_ip TEXT`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("adding desktop-approval columns to device_codes: %w", err)
		}
	}

	// Backfill oauth_identities from legacy users.identity_provider/identity_subject.
	bfRows, err := db.Query(`
		SELECT id, identity_provider, identity_subject FROM users
		WHERE identity_provider IS NOT NULL AND identity_subject IS NOT NULL`)
	if err != nil {
		return fmt.Errorf("backfill oauth_identities query: %w", err)
	}
	var bfUsers []struct{ id, provider, subject string }
	for bfRows.Next() {
		var u struct{ id, provider, subject string }
		if err := bfRows.Scan(&u.id, &u.provider, &u.subject); err != nil {
			bfRows.Close()
			return fmt.Errorf("backfill scan: %w", err)
		}
		bfUsers = append(bfUsers, u)
	}
	bfRows.Close()
	if err := bfRows.Err(); err != nil {
		return fmt.Errorf("backfill rows: %w", err)
	}
	for _, u := range bfUsers {
		if _, err := db.Exec(
			`INSERT INTO oauth_identities(id, user_id, provider, subject, email_verified)
			 VALUES ($1, $2, $3, $4, FALSE) ON CONFLICT(provider, subject) DO NOTHING`,
			ulid.Make().String(), u.id, u.provider, u.subject,
		); err != nil {
			return fmt.Errorf("backfill oauth_identities insert: %w", err)
		}
	}

	return nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// Migrate runs all schema migration steps against the underlying database.
// NewStore already invokes this; exposed so tests can verify idempotence.
func (s *Store) Migrate() error {
	return migrate(s.db)
}

// CreateUser inserts a new user row.
func (s *Store) CreateUser(id string) error {
	_, err := s.db.Exec("INSERT INTO users (id) VALUES ($1)", id)
	return err
}

// UpsertOAuthUser finds or creates a user by OAuth identity and provisions a device token.
// provider is "github" or "google"; subject is the stable provider-side user ID.
// machineID, when non-empty, deduplicates same-machine sign-ins onto a single device row.
// Returns (userID, deviceID, deviceToken).
func (s *Store) UpsertOAuthUser(provider, subject, email string, emailVerified bool, displayName, hostname, machineID string) (string, string, string, error) {
	if hostname == "" {
		hostname = "unknown"
	}

	var userID string
	var identityRowID string

	err := s.db.QueryRow(
		`SELECT id, user_id FROM oauth_identities WHERE provider = $1 AND subject = $2`,
		provider, subject,
	).Scan(&identityRowID, &userID)

	if err == sql.ErrNoRows {
		if emailVerified && email != "" {
			var linkedUserID string
			linkErr := s.db.QueryRow(
				`SELECT user_id FROM oauth_identities WHERE email = $1 AND email_verified = TRUE LIMIT 1`,
				email,
			).Scan(&linkedUserID)
			if linkErr == nil {
				userID = linkedUserID
				identityRowID = ulid.Make().String()
				var displayNameArg interface{}
				if displayName != "" {
					displayNameArg = displayName
				}
				if _, err := s.db.Exec(
					`INSERT INTO oauth_identities(id, user_id, provider, subject, email, email_verified, display_name)
					 VALUES ($1, $2, $3, $4, $5, TRUE, $6) ON CONFLICT(provider, subject) DO NOTHING`,
					identityRowID, userID, provider, subject, email, displayNameArg,
				); err != nil {
					return "", "", "", fmt.Errorf("linking cross-provider identity: %w", err)
				}
			} else {
				userID = ulid.Make().String()
				if _, err := s.db.Exec(`INSERT INTO users (id) VALUES ($1)`, userID); err != nil {
					return "", "", "", fmt.Errorf("creating oauth user: %w", err)
				}
				identityRowID = ulid.Make().String()
				var displayNameArg interface{}
				if displayName != "" {
					displayNameArg = displayName
				}
				if _, err := s.db.Exec(
					`INSERT INTO oauth_identities(id, user_id, provider, subject, email, email_verified, display_name)
					 VALUES ($1, $2, $3, $4, $5, TRUE, $6) ON CONFLICT(provider, subject) DO NOTHING`,
					identityRowID, userID, provider, subject, email, displayNameArg,
				); err != nil {
					return "", "", "", fmt.Errorf("inserting oauth identity: %w", err)
				}
			}
		} else {
			userID = ulid.Make().String()
			if _, err := s.db.Exec(`INSERT INTO users (id) VALUES ($1)`, userID); err != nil {
				return "", "", "", fmt.Errorf("creating oauth user: %w", err)
			}
			identityRowID = ulid.Make().String()
			var emailArg interface{}
			if email != "" {
				emailArg = email
			}
			var displayNameArg interface{}
			if displayName != "" {
				displayNameArg = displayName
			}
			if _, err := s.db.Exec(
				`INSERT INTO oauth_identities(id, user_id, provider, subject, email, email_verified, display_name)
				 VALUES ($1, $2, $3, $4, $5, FALSE, $6) ON CONFLICT(provider, subject) DO NOTHING`,
				identityRowID, userID, provider, subject, emailArg, displayNameArg,
			); err != nil {
				return "", "", "", fmt.Errorf("inserting oauth identity: %w", err)
			}
		}
	} else if err != nil {
		return "", "", "", fmt.Errorf("looking up oauth identity: %w", err)
	} else {
		var emailArg interface{}
		if email != "" {
			emailArg = email
		}
		if _, err := s.db.Exec(
			`UPDATE oauth_identities SET email = $1, email_verified = $2, last_seen_at = NOW()
			 WHERE id = $3`,
			emailArg, emailVerified, identityRowID,
		); err != nil {
			return "", "", "", fmt.Errorf("updating oauth identity: %w", err)
		}
		if displayName != "" {
			if _, err := s.db.Exec(
				`UPDATE oauth_identities SET display_name = $1 WHERE provider = $2 AND subject = $3`,
				displayName, provider, subject,
			); err != nil {
				return "", "", "", fmt.Errorf("refreshing oauth display_name: %w", err)
			}
		}
	}

	deviceToken := generateStoreToken()
	sourceKey := "remote:" + hostname

	var existingID string
	if machineID != "" {
		_ = s.db.QueryRow(
			`SELECT id FROM devices WHERE user_id = $1 AND machine_id = $2 AND revoked_at IS NULL
			 ORDER BY paired_at DESC LIMIT 1`,
			userID, machineID,
		).Scan(&existingID)
	}
	if existingID == "" {
		_ = s.db.QueryRow(
			`SELECT id FROM devices WHERE user_id = $1 AND source_key = $2 AND revoked_at IS NULL
			 ORDER BY paired_at DESC LIMIT 1`,
			userID, sourceKey,
		).Scan(&existingID)
	}
	// Heal legacy rows that have machine_id IS NULL — typically desktop rows created
	// before machine_id support, which landed with source_key='remote:unknown' because
	// the desktop's env-var hostname detection always produced "unknown" on macOS.
	// Match by the current source_key (same hostname) OR the sentinel 'remote:unknown'
	// so that a re-login from either the fixed desktop or the CLI can claim the row.
	if existingID == "" && machineID != "" {
		_ = s.db.QueryRow(
			`SELECT id FROM devices
			 WHERE user_id = $1
			   AND machine_id IS NULL
			   AND revoked_at IS NULL
			   AND source_key IN ($2, 'remote:unknown')
			 ORDER BY paired_at DESC LIMIT 1`,
			userID, sourceKey,
		).Scan(&existingID)
	}

	if existingID != "" {
		var args []interface{}
		query := `UPDATE devices SET token = $1, hostname = $2, source_key = $3`
		args = append(args, deviceToken, hostname, sourceKey)
		paramIdx := 4
		if machineID != "" {
			query += fmt.Sprintf(`, machine_id = $%d`, paramIdx)
			args = append(args, machineID)
			paramIdx++
		}
		query += fmt.Sprintf(` WHERE id = $%d`, paramIdx)
		args = append(args, existingID)
		if _, err := s.db.Exec(query, args...); err != nil {
			return "", "", "", fmt.Errorf("rotating device token: %w", err)
		}
		return userID, existingID, deviceToken, nil
	}

	cap, err := s.GetUserCapabilities(userID)
	if err != nil {
		return "", "", "", fmt.Errorf("checking device capabilities: %w", err)
	}
	if cap.DeviceLimit > 0 {
		count, err := s.CountActiveDevices(userID)
		if err != nil {
			return "", "", "", fmt.Errorf("counting active devices: %w", err)
		}
		if count >= cap.DeviceLimit {
			if cap.GraceExpiresAt.IsZero() || time.Now().After(cap.GraceExpiresAt) {
				return "", "", "", fmt.Errorf("device_limit_exceeded: user has %d/%d active devices", count, cap.DeviceLimit)
			}
		}
	}

	deviceID := ulid.Make().String()
	var insertMachineID interface{}
	if machineID != "" {
		insertMachineID = machineID
	}
	_, err = s.db.Exec(
		`INSERT INTO devices (id, user_id, hostname, source_key, token, machine_id)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT(user_id, source_key) DO UPDATE SET
		   token = EXCLUDED.token,
		   machine_id = COALESCE(EXCLUDED.machine_id, devices.machine_id),
		   revoked_at = NULL`,
		deviceID, userID, hostname, sourceKey, deviceToken, insertMachineID,
	)
	if err != nil {
		return "", "", "", fmt.Errorf("provisioning device: %w", err)
	}
	_ = s.db.QueryRow(
		"SELECT id FROM devices WHERE user_id = $1 AND source_key = $2", userID, sourceKey,
	).Scan(&deviceID)

	return userID, deviceID, deviceToken, nil
}

// UserByToken returns the user ID for a given device token.
func (s *Store) UserByToken(token string) (string, error) {
	var id string
	err := s.db.QueryRow(
		`SELECT u.id FROM users u
		 JOIN devices d ON d.user_id = u.id
		 WHERE d.token = $1 AND d.revoked_at IS NULL
		 AND (u.is_demo = FALSE OR u.created_at > NOW() - INTERVAL '10 minutes')`,
		token,
	).Scan(&id)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("invalid token")
	}
	return id, err
}

// IsDemoUser checks if a user ID belongs to a demo session.
func (s *Store) IsDemoUser(userID string) (bool, error) {
	var isDemo bool
	err := s.db.QueryRow("SELECT is_demo FROM users WHERE id = $1", userID).Scan(&isDemo)
	if err != nil {
		return false, err
	}
	return isDemo, nil
}

// DeviceIDByToken returns the device_id for an active or revoked per-device token.
func (s *Store) DeviceIDByToken(token string) (deviceID string, revoked bool, err error) {
	var revokedAt sql.NullTime
	err = s.db.QueryRow(
		`SELECT id, revoked_at FROM devices WHERE token = $1`, token,
	).Scan(&deviceID, &revokedAt)
	if err != nil {
		return "", false, err
	}
	return deviceID, revokedAt.Valid, nil
}

// DeviceOwner returns the user_id owning a device.
func (s *Store) DeviceOwner(deviceID string) (userID string, err error) {
	err = s.db.QueryRow("SELECT user_id FROM devices WHERE id = $1", deviceID).Scan(&userID)
	return
}

// RevokeDevice soft-deletes a device by setting revoked_at. Idempotent.
func (s *Store) RevokeDevice(deviceID string) (revokedAt time.Time, err error) {
	_, err = s.db.Exec(
		`UPDATE devices SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL`,
		deviceID,
	)
	if err != nil {
		return time.Time{}, err
	}
	var rt time.Time
	err = s.db.QueryRow(`SELECT revoked_at FROM devices WHERE id = $1`, deviceID).Scan(&rt)
	return rt, err
}

// RegisterDeviceWithToken inserts a new device row with a pre-generated deviceID and token.
func (s *Store) RegisterDeviceWithToken(userID, deviceID, hostname, token string) error {
	if hostname == "" {
		hostname = "unknown"
	}
	sourceKey := "remote:" + hostname
	_, err := s.db.Exec(
		`INSERT INTO devices (id, user_id, hostname, source_key, token, paired_at)
		 VALUES ($1, $2, $3, $4, $5, NOW())`,
		deviceID, userID, hostname, sourceKey, token,
	)
	return err
}

// SaveClip persists a clip and returns it. When PushClipRequest carries a
// non-empty IdempotencyKey, SaveClip first looks up an existing row by
// (user_id, idempotency_key) and returns it on hit without inserting; the
// returned bool is true on a duplicate-hit so callers can skip WS fanout.
// The partial unique index idx_clips_idempotency backs this up: if a race
// slips past the SELECT, the INSERT's unique-violation triggers a re-fetch
// of the winning row.
func (s *Store) SaveClip(userID string, req *cinchv1.PushClipRequest) (*cinchv1.Clip, bool, error) {
	// Idempotency pre-check: if the client supplied a key and we already have
	// a row for (user_id, key), return it unmodified. This is the hot path
	// for backlog-flush retries where the original response was lost.
	if req.IdempotencyKey != nil && *req.IdempotencyKey != "" {
		existing, err := s.findClipByIdempotencyKey(userID, *req.IdempotencyKey)
		if err != nil {
			return nil, false, fmt.Errorf("idempotency lookup: %w", err)
		}
		if existing != nil {
			return existing, true, nil
		}
	}

	id := ulid.Make().String()
	createdAt := time.Now().UTC()
	if req.ClientCreatedAt != nil && *req.ClientCreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, *req.ClientCreatedAt); err == nil {
			// Clamp to [now - 90d, now]. Outside window or unparseable → fall back to NOW().
			ninetyDaysAgo := createdAt.Add(-90 * 24 * time.Hour)
			if !t.Before(ninetyDaysAgo) && !t.After(createdAt) {
				createdAt = t.UTC()
			}
		}
	}

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

	idempotencyKey := ""
	if req.IdempotencyKey != nil {
		idempotencyKey = *req.IdempotencyKey
	}

	clip := &cinchv1.Clip{
		ClipId:      id,
		UserId:      userID,
		Content:     req.Content,
		ContentType: contentType,
		Source:      req.Source,
		Label:       req.Label,
		ByteSize:    byteSize,
		CreatedAt:   protocol.FormatRFC3339(createdAt),
		Encrypted:   req.Encrypted,
	}
	if mediaPath != "" {
		clip.MediaPath = &mediaPath
	}

	_, err := s.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, label, byte_size, media_path, created_at, encrypted, idempotency_key)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		clip.ClipId, clip.UserId, clip.Content, clip.ContentType,
		clip.Source, clip.Label, clip.ByteSize, sql.NullString{String: mediaPath, Valid: mediaPath != ""},
		createdAt, clip.Encrypted,
		sql.NullString{String: idempotencyKey, Valid: idempotencyKey != ""},
	)
	if err != nil {
		// Race recovery: two concurrent retries with the same idempotency_key
		// may both miss the pre-check and race into INSERT. The partial unique
		// index rejects the loser with 23505 unique_violation referencing
		// idx_clips_idempotency. Fetch the winner and report duplicate.
		var pgErr *pgconn.PgError
		if idempotencyKey != "" && errors.As(err, &pgErr) &&
			pgErr.Code == "23505" && pgErr.ConstraintName == idxClipsIdempotency {
			winner, lookupErr := s.findClipByIdempotencyKey(userID, idempotencyKey)
			if lookupErr != nil {
				return nil, false, fmt.Errorf("idempotency race recovery lookup: %w", lookupErr)
			}
			if winner != nil {
				return winner, true, nil
			}
		}
		return nil, false, fmt.Errorf("saving clip: %w", err)
	}

	return clip, false, nil
}

// findClipByIdempotencyKey returns the clip row (if any) matching
// (user_id, idempotency_key). Returns (nil, nil) when no row exists.
// Column order matches scanClips for consistency.
func (s *Store) findClipByIdempotencyKey(userID, key string) (*cinchv1.Clip, error) {
	row := s.db.QueryRow(
		`SELECT id, user_id, content, content_type, source, label, byte_size,
		        media_path, created_at, encrypted, is_pinned, pin_note
		 FROM clips
		 WHERE user_id = $1 AND idempotency_key = $2
		 LIMIT 1`,
		userID, key,
	)
	c := &cinchv1.Clip{}
	var mediaPath sql.NullString
	var pinNote sql.NullString
	var createdAt time.Time
	if err := row.Scan(&c.ClipId, &c.UserId, &c.Content, &c.ContentType, &c.Source, &c.Label, &c.ByteSize, &mediaPath, &createdAt, &c.Encrypted, &c.IsPinned, &pinNote); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if mediaPath.Valid && mediaPath.String != "" {
		v := mediaPath.String
		c.MediaPath = &v
	}
	if pinNote.Valid && pinNote.String != "" {
		v := pinNote.String
		c.PinNote = &v
	}
	c.CreatedAt = protocol.FormatRFC3339(createdAt)
	return c, nil
}

// scanClips reads clip rows produced by a query that selects:
//
//	id, user_id, content, content_type, source, label, byte_size,
//	media_path, created_at, encrypted, is_pinned, pin_note
//
// (in that order). Used by ListClips, ListClipsSince, and ListClipsFiltered.
func scanClips(rows *sql.Rows) ([]*cinchv1.Clip, error) {
	clips := make([]*cinchv1.Clip, 0)
	for rows.Next() {
		c := &cinchv1.Clip{}
		var mediaPath sql.NullString
		var pinNote sql.NullString
		var createdAt time.Time
		if err := rows.Scan(&c.ClipId, &c.UserId, &c.Content, &c.ContentType, &c.Source, &c.Label, &c.ByteSize, &mediaPath, &createdAt, &c.Encrypted, &c.IsPinned, &pinNote); err != nil {
			return nil, err
		}
		if mediaPath.Valid && mediaPath.String != "" {
			s := mediaPath.String
			c.MediaPath = &s
		}
		if pinNote.Valid && pinNote.String != "" {
			s := pinNote.String
			c.PinNote = &s
		}
		c.CreatedAt = protocol.FormatRFC3339(createdAt)
		clips = append(clips, c)
	}
	return clips, rows.Err()
}

// ListClips returns recent clips for a user.
func (s *Store) ListClips(userID string, limit int) ([]*cinchv1.Clip, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	rows, err := s.db.Query(
		`SELECT id, user_id, content, content_type, source, label, byte_size, media_path, created_at, encrypted, is_pinned, pin_note
		 FROM clips WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2`,
		userID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanClips(rows)
}

// ListClipsSince returns clips newer than `since` (exclusive), ordered oldest-first.
func (s *Store) ListClipsSince(userID string, since time.Time, limit int) ([]*cinchv1.Clip, error) {
	if since.IsZero() {
		return s.ListClips(userID, limit)
	}

	rows, err := s.db.Query(`
		SELECT id, user_id, content, content_type, source, label, byte_size,
		       media_path, created_at, encrypted, is_pinned, pin_note
		FROM clips
		WHERE user_id = $1 AND created_at > $2
		ORDER BY created_at ASC
		LIMIT $3`,
		userID, since.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanClips(rows)
}

// ListFilter is the query shape for ListClipsFiltered.
type ListFilter struct {
	Limit         int
	SourceFilter  string
	ExcludeSource string
	ExcludeImage  bool
	ExcludeText   bool
	ClipIDs       []string
}

// ListClipsFiltered returns clips matching the filter, newest-first.
// Limit is clamped to [1, 200]; 0 → 50.
func (s *Store) ListClipsFiltered(userID string, f ListFilter) ([]*cinchv1.Clip, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	if f.Limit > 200 {
		f.Limit = 200
	}

	clauses := []string{"user_id = $1"}
	args := []any{userID}
	paramIdx := 2

	if f.SourceFilter != "" {
		clauses = append(clauses, fmt.Sprintf("source = $%d", paramIdx))
		args = append(args, f.SourceFilter)
		paramIdx++
	}
	if f.ExcludeSource != "" {
		clauses = append(clauses, fmt.Sprintf("source != $%d", paramIdx))
		args = append(args, f.ExcludeSource)
		paramIdx++
	}
	if f.ExcludeImage {
		clauses = append(clauses, "content_type != 'image'")
	}
	if f.ExcludeText {
		// content_type can be one of text/url/code/image (see clips.proto). Excluding
		// "text" must keep url/code/image — not collapse to image only.
		clauses = append(clauses, "content_type != 'text'")
	}
	if len(f.ClipIDs) > 0 {
		placeholders := make([]string, len(f.ClipIDs))
		for i, id := range f.ClipIDs {
			placeholders[i] = fmt.Sprintf("$%d", paramIdx)
			args = append(args, id)
			paramIdx++
		}
		clauses = append(clauses, "id IN ("+strings.Join(placeholders, ",")+")")
	}

	query := `SELECT id, user_id, content, content_type, source, label, byte_size,
	                 media_path, created_at, encrypted, is_pinned, pin_note
	          FROM clips
	          WHERE ` + strings.Join(clauses, " AND ") + fmt.Sprintf(`
	          ORDER BY created_at DESC
	          LIMIT $%d`, paramIdx)
	args = append(args, f.Limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanClips(rows)
}

// DeleteClip removes a clip by ID, scoped to the user.
func (s *Store) DeleteClip(userID, clipID string) error {
	res, err := s.db.Exec("DELETE FROM clips WHERE id = $1 AND user_id = $2", clipID, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("clip not found")
	}
	return nil
}

// DeleteClipReturningMedia removes a clip and returns its media_path key (or "").
func (s *Store) DeleteClipReturningMedia(userID, clipID string) (mediaPath string, err error) {
	if err = s.db.QueryRow(
		"SELECT COALESCE(media_path, '') FROM clips WHERE id = $1 AND user_id = $2",
		clipID, userID,
	).Scan(&mediaPath); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}

	res, err := s.db.Exec("DELETE FROM clips WHERE id = $1 AND user_id = $2", clipID, userID)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", fmt.Errorf("clip not found")
	}
	return mediaPath, nil
}

// scanClipRow decodes a single clip row produced by a query that selects
// the same columns as scanClips. Returns sql.ErrNoRows if the row is empty.
func scanClipRow(row *sql.Row) (*cinchv1.Clip, error) {
	c := &cinchv1.Clip{}
	var mediaPath sql.NullString
	var pinNote sql.NullString
	var createdAt time.Time
	if err := row.Scan(&c.ClipId, &c.UserId, &c.Content, &c.ContentType, &c.Source, &c.Label, &c.ByteSize, &mediaPath, &createdAt, &c.Encrypted, &c.IsPinned, &pinNote); err != nil {
		return nil, err
	}
	if mediaPath.Valid && mediaPath.String != "" {
		s := mediaPath.String
		c.MediaPath = &s
	}
	if pinNote.Valid && pinNote.String != "" {
		s := pinNote.String
		c.PinNote = &s
	}
	c.CreatedAt = protocol.FormatRFC3339(createdAt)
	return c, nil
}

// GetLatestClipBySource returns the most recent clip from a specific source.
func (s *Store) GetLatestClipBySource(userID, source string) (*cinchv1.Clip, error) {
	row := s.db.QueryRow(
		`SELECT id, user_id, content, content_type, source, label, byte_size,
		        media_path, created_at, encrypted, is_pinned, pin_note
		 FROM clips WHERE user_id = $1 AND source = $2
		 ORDER BY created_at DESC LIMIT 1`,
		userID, source,
	)
	clip, err := scanClipRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		// Wrap with %w so callers can still match via errors.Is(err, sql.ErrNoRows).
		// The handler relies on this to map the no-row case to CodeNotFound symmetrically
		// with the GetLatestClipExcludingSource path.
		return nil, fmt.Errorf("no clips from source %s: %w", source, err)
	}
	return clip, err
}

// GetLatestClipExcludingSource returns the newest clip for userID whose
// source != excludeSource. Returns sql.ErrNoRows when no clip qualifies.
func (s *Store) GetLatestClipExcludingSource(userID, excludeSource string) (*cinchv1.Clip, error) {
	row := s.db.QueryRow(
		`SELECT id, user_id, content, content_type, source, label, byte_size,
		        media_path, created_at, encrypted, is_pinned, pin_note
		 FROM clips WHERE user_id = $1 AND source != $2
		 ORDER BY created_at DESC LIMIT 1`,
		userID, excludeSource,
	)
	return scanClipRow(row)
}

// GetLatestClipForUser returns the newest clip for userID across every source.
// Returns sql.ErrNoRows when the user has no clips.
func (s *Store) GetLatestClipForUser(userID string) (*cinchv1.Clip, error) {
	row := s.db.QueryRow(
		`SELECT id, user_id, content, content_type, source, label, byte_size,
		        media_path, created_at, encrypted, is_pinned, pin_note
		 FROM clips WHERE user_id = $1
		 ORDER BY created_at DESC LIMIT 1`,
		userID,
	)
	return scanClipRow(row)
}

// SetClipPin sets or clears the pin state for a clip owned by the caller.
func (s *Store) SetClipPin(userID, clipID string, isPinned bool, pinNote *string) error {
	res, err := s.db.Exec(
		`UPDATE clips SET is_pinned = $1, pin_note = $2 WHERE id = $3 AND user_id = $4`,
		isPinned, pinNote, clipID, userID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("clip not found")
	}
	return nil
}

// UpdateDeviceActivity increments clip count and updates last_push_at.
func (s *Store) UpdateDeviceActivity(userID, source string) error {
	_, err := s.db.Exec(
		`UPDATE devices SET clip_count = clip_count + 1, last_push_at = NOW()
		 WHERE user_id = $1 AND source_key = $2`,
		userID, source,
	)
	return err
}

// GetSetting reads a value from the settings table.
func (s *Store) GetSetting(key string) (string, error) {
	var val string
	err := s.db.QueryRow("SELECT value FROM settings WHERE key = $1", key).Scan(&val)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return val, err
}

// SetSetting writes a value to the settings table.
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(
		"INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value",
		key, value,
	)
	return err
}

// GetClipMediaPath returns the media_path for a clip (for cascade delete).
func (s *Store) GetClipMediaPath(userID, clipID string) (string, error) {
	var mp sql.NullString
	err := s.db.QueryRow("SELECT media_path FROM clips WHERE id = $1 AND user_id = $2", clipID, userID).Scan(&mp)
	if err != nil {
		return "", err
	}
	if mp.Valid {
		return mp.String, nil
	}
	return "", nil
}

// ListDevices returns all non-revoked devices for a user.
func (s *Store) ListDevices(userID string) ([]*cinchv1.Device, error) {
	rows, err := s.db.Query(
		`SELECT id, hostname, source_key, clip_count, paired_at, last_push_at, COALESCE(public_key, ''), COALESCE(nickname, ''), machine_id
		 FROM devices WHERE user_id = $1 AND revoked_at IS NULL ORDER BY last_push_at DESC NULLS LAST`,
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
		var machineID sql.NullString
		if err := rows.Scan(&d.Id, &d.Hostname, &d.SourceKey, &clipCount, &pairedAt, &lastPush, &d.PublicKey, &d.Nickname, &machineID); err != nil {
			return nil, err
		}
		d.ClipCount = int32(clipCount)
		d.PairedAt = protocol.FormatRFC3339(pairedAt)
		if lastPush.Valid {
			d.LastPushAt = protocol.FormatRFC3339Ptr(&lastPush.Time)
		}
		if machineID.Valid {
			d.MachineId = &machineID.String
		}
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

// SetDeviceNickname sets or clears the nickname for a device.
func (s *Store) SetDeviceNickname(deviceID, nickname string) error {
	var val interface{}
	if nickname != "" {
		val = nickname
	}
	_, err := s.db.Exec("UPDATE devices SET nickname = $1 WHERE id = $2", val, deviceID)
	return err
}

// ── Demo session methods ────────────────────────────────────────────

// CreateDemoUser creates a temporary demo user with a 10-minute TTL.
func (s *Store) CreateDemoUser(id, token string) error {
	s.CleanupDemoSessions()
	if _, err := s.db.Exec(
		"INSERT INTO users (id, is_demo) VALUES ($1, TRUE)", id,
	); err != nil {
		return err
	}
	deviceID := ulid.Make().String()
	return s.RegisterDeviceWithToken(id, deviceID, "demo", token)
}

// CleanupDemoSessions deletes expired demo users and their clips.
func (s *Store) CleanupDemoSessions() {
	s.db.Exec("DELETE FROM clips WHERE user_id IN (SELECT id FROM users WHERE is_demo = TRUE AND created_at <= NOW() - INTERVAL '10 minutes')")
	s.db.Exec("DELETE FROM devices WHERE user_id IN (SELECT id FROM users WHERE is_demo = TRUE AND created_at <= NOW() - INTERVAL '10 minutes')")
	s.db.Exec("DELETE FROM users WHERE is_demo = TRUE AND created_at <= NOW() - INTERVAL '10 minutes'")
}

// DemoClipCount returns the number of clips for a demo user.
func (s *Store) DemoClipCount(userID string) (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM clips WHERE user_id = $1", userID).Scan(&count)
	return count, err
}

// ── Device-code flow methods ────────────────────────────────────────────────

// generateStoreToken creates a 32-byte hex token.
func generateStoreToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// generateUserCode creates an 8-char uppercase alphanumeric code formatted as XXXX-XXXX.
func generateUserCode() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const n = len(chars)
	const max = 256 - (256 % n) // reject values >= this to eliminate modular bias
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

// CreateDeviceCode generates a device code and user code, inserts into device_codes.
// If userHint is a known user email (verified) or user_id, returns that user_id so
// the caller can broadcast a device_code_pending event. Unknown hints are silently
// ignored (no enumeration leak).
func (s *Store) CreateDeviceCode(hostname, machineID, userHint, requesterIP string) (*cinchv1.DeviceCodeStartResponse, string, error) {
	deviceCode := generateStoreToken()
	userCode := generateUserCode()
	expiresAt := time.Now().UTC().Add(5 * time.Minute)

	var mi interface{}
	if machineID != "" {
		mi = machineID
	}

	var pendingUserID string
	if userHint != "" {
		// Email lookup goes through oauth_identities (verified-only, to avoid
		// spam by an unverified attacker-claimed email). Falls back to a raw
		// users.id lookup when the hint isn't an email.
		var uid sql.NullString
		_ = s.db.QueryRow(
			`SELECT user_id FROM oauth_identities
			 WHERE email = $1 AND email_verified = TRUE
			 ORDER BY last_seen_at DESC LIMIT 1`,
			userHint,
		).Scan(&uid)
		if !uid.Valid {
			_ = s.db.QueryRow(`SELECT id FROM users WHERE id = $1`, userHint).Scan(&uid)
		}
		if uid.Valid {
			pendingUserID = uid.String
		}
	}

	var pendingNullable sql.NullString
	if pendingUserID != "" {
		pendingNullable = sql.NullString{String: pendingUserID, Valid: true}
	}
	var ipNullable sql.NullString
	if requesterIP != "" {
		ipNullable = sql.NullString{String: requesterIP, Valid: true}
	}

	_, err := s.db.Exec(
		`INSERT INTO device_codes (device_code, user_code, hostname, machine_id, expires_at, pending_user_id, requester_ip)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		deviceCode, userCode, hostname, mi, expiresAt, pendingNullable, ipNullable,
	)
	if err != nil {
		return nil, "", fmt.Errorf("creating device code: %w", err)
	}

	intervalMs := int64(1000)
	return &cinchv1.DeviceCodeStartResponse{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ExpiresIn:  300,
		Interval:   3,
		IntervalMs: &intervalMs,
	}, pendingUserID, nil
}

// CreateDeviceForUser provisions a brand-new device row for an existing user.
func (s *Store) CreateDeviceForUser(userID, hostname, machineID string) (deviceID, token string, err error) {
	deviceID = ulid.Make().String()
	token = generateStoreToken()
	if hostname == "" {
		hostname = "unknown"
	}
	sourceKey := "approve:" + deviceID

	var mi interface{}
	if machineID != "" {
		mi = machineID
	}

	_, err = s.db.Exec(
		`INSERT INTO devices (id, user_id, hostname, source_key, token, machine_id)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		deviceID, userID, hostname, sourceKey, token, mi,
	)
	if err != nil {
		return "", "", fmt.Errorf("creating device for approve: %w", err)
	}
	return deviceID, token, nil
}

// CompleteDeviceCode marks a device code as complete with the provided credentials.
func (s *Store) CompleteDeviceCode(userCode, userID, deviceID, token string) error {
	res, err := s.db.Exec(
		`UPDATE device_codes SET status = 'complete', user_id = $1, device_id = $2, token = $3
		 WHERE user_code = $4 AND status = 'pending' AND expires_at > NOW()`,
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

// DenyDeviceCode marks a pending device-code row as 'denied', provided the row's
// pending_user_id matches the supplied userID. Used by an already-signed-in
// device to reject a pending remote-login request before the 5-minute expiry.
// Returns an error if no matching pending row exists (not yours, expired,
// already used, or wrong code).
func (s *Store) DenyDeviceCode(userCode, userID string) error {
	res, err := s.db.Exec(
		`UPDATE device_codes SET status='denied'
		 WHERE user_code = $1 AND status='pending'
		   AND expires_at > NOW() AND pending_user_id = $2`,
		userCode, userID,
	)
	if err != nil {
		return fmt.Errorf("denying device code: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("device code not found, already used, expired, or not yours")
	}
	return nil
}

// PollDeviceCode checks the status of a device code.
func (s *Store) PollDeviceCode(deviceCode string) (*cinchv1.DeviceCodePollResponse, error) {
	var status, userID, deviceID, token sql.NullString
	var expiresAt time.Time

	err := s.db.QueryRow(
		`SELECT status, user_id, device_id, token, expires_at FROM device_codes WHERE device_code = $1`,
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

	if status.String == "denied" {
		return &cinchv1.DeviceCodePollResponse{Status: "denied"}, nil
	}

	if status.String == "complete" {
		t := token.String
		u := userID.String
		d := deviceID.String
		resp := &cinchv1.DeviceCodePollResponse{
			Status:   "complete",
			Token:    &t,
			UserId:   &u,
			DeviceId: &d,
		}
		var email, provider, displayName sql.NullString
		if u != "" {
			_ = s.db.QueryRow(
				`SELECT
					oi.email,
					oi.provider,
					COALESCE(NULLIF(u.display_name, ''), oi.display_name, '') AS effective_name
				 FROM oauth_identities oi
				 JOIN users u ON u.id = oi.user_id
				 WHERE oi.user_id = $1 AND oi.email IS NOT NULL
				 ORDER BY oi.last_seen_at DESC LIMIT 1`,
				u,
			).Scan(&email, &provider, &displayName)
		}
		if email.Valid && email.String != "" {
			resp.Email = &email.String
		}
		if provider.Valid && provider.String != "" {
			resp.IdentityProvider = &provider.String
		}
		if displayName.Valid && displayName.String != "" {
			name := displayName.String
			resp.DisplayName = &name
		}
		return resp, nil
	}

	return &cinchv1.DeviceCodePollResponse{Status: "pending"}, nil
}

// DeviceCodeHostname returns the hostname stored in a device_codes row by user_code.
func (s *Store) DeviceCodeHostname(userCode string) (string, error) {
	hostname, _, err := s.DeviceCodeContext(userCode)
	return hostname, err
}

// DeviceCodeContext returns the hostname and machine_id stored when the device code was issued.
func (s *Store) DeviceCodeContext(userCode string) (string, string, error) {
	var hostname string
	var machineID sql.NullString
	err := s.db.QueryRow(
		"SELECT hostname, machine_id FROM device_codes WHERE user_code = $1", userCode,
	).Scan(&hostname, &machineID)
	if err != nil {
		return "", "", err
	}
	return hostname, machineID.String, nil
}

// CleanupExpiredDeviceCodes removes device codes that expired more than 1 hour ago.
func (s *Store) CleanupExpiredDeviceCodes() error {
	_, err := s.db.Exec("DELETE FROM device_codes WHERE expires_at < NOW() - INTERVAL '1 hour'")
	return err
}

// SweepExpiredClips deletes clips older than retentionDays for a given user.
func (s *Store) SweepExpiredClips(userID string, retentionDays int) (int, error) {
	result, err := s.db.Exec(
		`DELETE FROM clips WHERE user_id = $1 AND created_at < NOW() - $2 * INTERVAL '1 day'`,
		userID, retentionDays,
	)
	if err != nil {
		return 0, err
	}
	n, _ := result.RowsAffected()
	return int(n), nil
}

// SweepAllUsersRetention iterates all users with remote_retention_days set and sweeps their expired clips.
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
			slog.Info("retention sweep deleted clips", "count", count, "user", ur.userID, "retention_days", ur.days)
		}
	}
	return nil
}

// sweepBatchSize bounds how many clip IDs go into a single DELETE / tombstone
// INSERT statement. Postgres caps a query at 65535 parameters; 1000 leaves a
// comfortable margin and keeps individual round-trips short so a long sweep
// can be interrupted between chunks.
const sweepBatchSize = 1000

// SweepExpiredClipsReturningMedia deletes clips older than retentionDays and returns media keys.
func (s *Store) SweepExpiredClipsReturningMedia(userID string, retentionDays int) (count int, mediaPaths []string, err error) {
	rows, err := s.db.Query(
		`SELECT id, COALESCE(media_path, '') FROM clips
		  WHERE user_id = $1 AND created_at < NOW() - $2 * INTERVAL '1 day'`,
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
		if scanErr := rows.Scan(&r.id, &r.key); scanErr != nil {
			slog.Error("sweep scan expired clip row failed", "user", userID, "err", scanErr)
			continue
		}
		toDelete = append(toDelete, r)
	}
	rows.Close()

	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	if len(toDelete) == 0 {
		return 0, nil, nil
	}

	for i := 0; i < len(toDelete); i += sweepBatchSize {
		end := i + sweepBatchSize
		if end > len(toDelete) {
			end = len(toDelete)
		}
		chunk := toDelete[i:end]
		ids := make([]string, len(chunk))
		for j, r := range chunk {
			ids[j] = r.id
		}
		if delErr := s.deleteClipsBatch(userID, ids); delErr != nil {
			// Don't bail on the whole sweep — the next hourly tick retries.
			// We log the chunk size rather than every ID to keep log volume sane.
			slog.Error("sweep batch delete failed", "count", len(ids), "user", userID, "err", delErr)
			continue
		}
		// Only collect media keys after a successful delete so the caller
		// doesn't orphan-delete media for clips still in the DB.
		for _, r := range chunk {
			if r.key != "" {
				mediaPaths = append(mediaPaths, r.key)
			}
		}
		count += len(ids)
		if tErr := s.insertTombstonesBatch(userID, ids); tErr != nil {
			slog.Error("sweep batch tombstones failed", "count", len(ids), "user", userID, "err", tErr)
		}
	}
	return count, mediaPaths, nil
}

// deleteClipsBatch removes up to len(ids) clips for a single user in one
// statement. Callers must keep len(ids) under sweepBatchSize.
func (s *Store) deleteClipsBatch(userID string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	placeholders := make([]string, len(ids))
	args := make([]any, 0, len(ids)+1)
	args = append(args, userID)
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args = append(args, id)
	}
	query := fmt.Sprintf(
		"DELETE FROM clips WHERE user_id = $1 AND id IN (%s)",
		strings.Join(placeholders, ","),
	)
	_, err := s.db.Exec(query, args...)
	return err
}

// insertTombstonesBatch records deletion events for many clip IDs in one
// statement. Idempotent per-clip via the ON CONFLICT clause.
func (s *Store) insertTombstonesBatch(userID string, clipIDs []string) error {
	if len(clipIDs) == 0 {
		return nil
	}
	placeholders := make([]string, len(clipIDs))
	args := make([]any, 0, len(clipIDs)*2)
	for i, id := range clipIDs {
		placeholders[i] = fmt.Sprintf("($%d, $%d)", i*2+1, i*2+2)
		args = append(args, id, userID)
	}
	query := fmt.Sprintf(
		"INSERT INTO clip_tombstones (clip_id, user_id) VALUES %s ON CONFLICT (clip_id) DO NOTHING",
		strings.Join(placeholders, ","),
	)
	_, err := s.db.Exec(query, args...)
	return err
}

// SweepAllUsersRetentionReturningMedia sweeps all users' expired clips and collects media keys.
//
// The capability lookup is folded into the device query via LEFT JOIN so we
// don't pay one round-trip per user. Behavior is preserved: a positive
// user_capabilities.retention_days overrides the device-level value, which is
// itself the per-device knob users set via the desktop's settings.
func (s *Store) SweepAllUsersRetentionReturningMedia() (mediaPaths []string, err error) {
	rows, err := s.db.Query(
		`SELECT DISTINCT d.user_id,
		                 d.remote_retention_days,
		                 COALESCE(uc.retention_days, 0) AS cap_retention
		  FROM devices d
		  LEFT JOIN user_capabilities uc ON uc.user_id = d.user_id
		  WHERE d.remote_retention_days IS NOT NULL AND d.revoked_at IS NULL`,
	)
	if err != nil {
		return nil, err
	}

	type ur struct {
		userID       string
		deviceDays   int
		capRetention int
	}
	var users []ur
	for rows.Next() {
		var u ur
		if scanErr := rows.Scan(&u.userID, &u.deviceDays, &u.capRetention); scanErr != nil {
			slog.Error("retention sweep scan device row failed", "err", scanErr)
			continue
		}
		users = append(users, u)
	}
	rows.Close()

	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, u := range users {
		retentionDays := u.deviceDays
		if u.capRetention > 0 {
			retentionDays = u.capRetention
		}
		count, paths, sweepErr := s.SweepExpiredClipsReturningMedia(u.userID, retentionDays)
		if sweepErr != nil {
			slog.Error("retention sweep failed", "user", u.userID, "err", sweepErr)
		} else if count > 0 {
			slog.Info("retention sweep deleted clips", "count", count, "user", u.userID, "retention_days", retentionDays)
		}
		mediaPaths = append(mediaPaths, paths...)
	}
	return mediaPaths, nil
}

// UpdateDeviceRetention sets the remote_retention_days for a specific device.
func (s *Store) UpdateDeviceRetention(deviceID string, days int) error {
	if days < 1 || days > 365 {
		return fmt.Errorf("retention days must be between 1 and 365, got %d", days)
	}
	result, err := s.db.Exec(
		"UPDATE devices SET remote_retention_days = $1 WHERE id = $2 AND revoked_at IS NULL",
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
	err := s.db.QueryRow("SELECT push_count FROM demo_stats WHERE date = $1", today).Scan(&count)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return count, err
}

// IncrementDemoCounter increments today's demo push counter.
func (s *Store) IncrementDemoCounter() error {
	today := time.Now().UTC().Format("2006-01-02")
	_, err := s.db.Exec(
		`INSERT INTO demo_stats (date, push_count) VALUES ($1, 1)
		 ON CONFLICT(date) DO UPDATE SET push_count = demo_stats.push_count + 1`,
		today,
	)
	return err
}

// ── E2EE key exchange store methods ─────────────────────────────────────────

// SetDevicePublicKey stores the X25519 public key and its fingerprint for a
// device. Any previously stored encrypted_key_bundle / ephemeral_public_key is
// cleared atomically: those values were ECDH-encrypted under the prior
// pubkey, so a freshly-rotated keypair could not decrypt them. Clearing the
// bundle puts the device back into ListPendingKeyExchanges so a bearer can
// share a freshly-encrypted bundle under the new pubkey.
func (s *Store) SetDevicePublicKey(deviceID, pubKeyB64, fingerprint string) error {
	res, err := s.db.Exec(
		"UPDATE devices SET public_key = $1, public_key_fingerprint = $2, encrypted_key_bundle = NULL, ephemeral_public_key = NULL WHERE id = $3",
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
func (s *Store) GetDevicePublicKey(deviceID string) (string, error) {
	var key sql.NullString
	err := s.db.QueryRow("SELECT public_key FROM devices WHERE id = $1", deviceID).Scan(&key)
	if err != nil {
		return "", err
	}
	if !key.Valid || key.String == "" {
		return "", fmt.Errorf("no public key for device %s", deviceID)
	}
	return key.String, nil
}

// SaveKeyBundle persists the ECDH key bundle for a device.
func (s *Store) SaveKeyBundle(deviceID, ephPubKeyB64, encryptedBundleB64 string) error {
	_, err := s.db.Exec(
		"UPDATE devices SET ephemeral_public_key = $1, encrypted_key_bundle = $2 WHERE id = $3",
		ephPubKeyB64, encryptedBundleB64, deviceID,
	)
	return err
}

// GetKeyBundle retrieves the stored ECDH key bundle for a device.
func (s *Store) GetKeyBundle(deviceID string) (ephPubKeyB64, encryptedBundleB64 string, err error) {
	var eph, bundle sql.NullString
	err = s.db.QueryRow(
		"SELECT ephemeral_public_key, encrypted_key_bundle FROM devices WHERE id = $1", deviceID,
	).Scan(&eph, &bundle)
	if err != nil {
		return "", "", err
	}
	if eph.Valid && bundle.Valid {
		return eph.String, bundle.String, nil
	}
	return "", "", nil
}

// GetDeviceHostnameAndPubKey returns the hostname and X25519 public key for a device.
func (s *Store) GetDeviceHostnameAndPubKey(deviceID string) (hostname, pubKey string, err error) {
	var nullKey sql.NullString
	err = s.db.QueryRow(
		`SELECT hostname, public_key FROM devices WHERE id = $1`,
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

// GetKeyBundlePendingSince returns when the device first registered a public key without a bundle.
func (s *Store) GetKeyBundlePendingSince(deviceID string) (time.Time, error) {
	var t time.Time
	err := s.db.QueryRow(
		`SELECT paired_at FROM devices
		 WHERE id = $1 AND public_key IS NOT NULL AND encrypted_key_bundle IS NULL`,
		deviceID,
	).Scan(&t)
	if err == sql.ErrNoRows {
		return time.Time{}, nil
	}
	return t, err
}

// ListPendingKeyExchanges returns devices that have a public_key but no encrypted_key_bundle yet.
func (s *Store) ListPendingKeyExchanges(userID string) ([]*cinchv1.Device, error) {
	rows, err := s.db.Query(
		`SELECT id, hostname, COALESCE(public_key,''), COALESCE(public_key_fingerprint,'') FROM devices
		 WHERE user_id = $1 AND public_key IS NOT NULL AND encrypted_key_bundle IS NULL
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

// PendingDeviceCodeRow is a single unexpired pending device-code row, used
// for the WS-connect sweep that replays device_code_pending broadcasts to
// desktops that were offline at DeviceCodeStart time.
type PendingDeviceCodeRow struct {
	UserCode    string
	Hostname    string
	RequesterIP string
	RequestedAt time.Time
}

// ListPendingDeviceCodes returns unexpired 'pending' device_codes whose
// pending_user_id matches userID. Used to replay device_code_pending
// broadcasts when a desktop reconnects after the initial DeviceCodeStart
// fan-out, so an offline desktop still sees the approval prompt.
func (s *Store) ListPendingDeviceCodes(userID string) ([]PendingDeviceCodeRow, error) {
	rows, err := s.db.Query(
		`SELECT user_code, COALESCE(hostname, ''), COALESCE(requester_ip, ''), created_at
		 FROM device_codes
		 WHERE pending_user_id = $1 AND status = 'pending' AND expires_at > NOW()`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing pending device codes: %w", err)
	}
	defer rows.Close()
	var out []PendingDeviceCodeRow
	for rows.Next() {
		var p PendingDeviceCodeRow
		if err := rows.Scan(&p.UserCode, &p.Hostname, &p.RequesterIP, &p.RequestedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ── Tombstone methods ────────────────────────────────────────────────────────

// InsertTombstone records that a clip was deleted. Idempotent.
func (s *Store) InsertTombstone(userID, clipID string) error {
	_, err := s.db.Exec(
		`INSERT INTO clip_tombstones (clip_id, user_id) VALUES ($1, $2) ON CONFLICT(clip_id) DO NOTHING`,
		clipID, userID,
	)
	return err
}

// ListTombstones returns tombstones for userID with deleted_at > since, oldest first.
func (s *Store) ListTombstones(userID string, since time.Time, limit int) ([]Tombstone, error) {
	rows, err := s.db.Query(
		`SELECT clip_id, deleted_at FROM clip_tombstones
		 WHERE user_id = $1 AND deleted_at > $2
		 ORDER BY deleted_at ASC
		 LIMIT $3`,
		userID, since.UTC(), limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Tombstone
	for rows.Next() {
		var clipID string
		var deletedAt time.Time
		if err := rows.Scan(&clipID, &deletedAt); err != nil {
			return nil, err
		}
		out = append(out, Tombstone{
			ClipID:    clipID,
			DeletedAt: deletedAt.UTC().Format(time.RFC3339),
		})
	}
	return out, rows.Err()
}

// SweepTombstones deletes tombstones older than retentionDays.
func (s *Store) SweepTombstones(retentionDays int) (int, error) {
	res, err := s.db.Exec(
		`DELETE FROM clip_tombstones WHERE deleted_at < NOW() - $1 * INTERVAL '1 day'`,
		retentionDays,
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// SweepStaleIdempotencyKeys NULLs the idempotency_key column on clip rows
// older than maxAge so the partial unique index does not grow without bound.
// The dedup window for real backlog retries is seconds-to-minutes; clearing
// keys after ~24h reclaims index space with zero risk of late collisions.
// Returns the number of rows updated.
func (s *Store) SweepStaleIdempotencyKeys(maxAge time.Duration) (int, error) {
	cutoff := time.Now().UTC().Add(-maxAge)
	res, err := s.db.Exec(
		`UPDATE clips
		 SET idempotency_key = NULL
		 WHERE idempotency_key IS NOT NULL
		   AND created_at < $1`,
		cutoff,
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// GetUserCapabilities loads quota limits for a user.
func (s *Store) GetUserCapabilities(userID string) (UserCapabilities, error) {
	var cap UserCapabilities
	var graceAt sql.NullTime
	err := s.db.QueryRow(
		`SELECT user_id, device_limit, retention_days, rate_limit, grace_expires_at
		 FROM user_capabilities WHERE user_id = $1`,
		userID,
	).Scan(&cap.UserID, &cap.DeviceLimit, &cap.RetentionDays, &cap.RateLimit, &graceAt)
	if err == sql.ErrNoRows {
		return UserCapabilities{}, nil
	}
	if err != nil {
		return UserCapabilities{}, err
	}
	if graceAt.Valid {
		cap.GraceExpiresAt = graceAt.Time
	}
	return cap, nil
}

// UpsertUserCapabilities writes (or replaces) quota limits for a user.
func (s *Store) UpsertUserCapabilities(cap UserCapabilities) error {
	var graceAt interface{}
	if !cap.GraceExpiresAt.IsZero() {
		graceAt = cap.GraceExpiresAt.UTC()
	}
	_, err := s.db.Exec(
		`INSERT INTO user_capabilities (user_id, device_limit, retention_days, rate_limit, grace_expires_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, NOW())
		 ON CONFLICT(user_id) DO UPDATE SET
		   device_limit     = EXCLUDED.device_limit,
		   retention_days   = EXCLUDED.retention_days,
		   rate_limit       = EXCLUDED.rate_limit,
		   grace_expires_at = EXCLUDED.grace_expires_at,
		   updated_at       = EXCLUDED.updated_at`,
		cap.UserID, cap.DeviceLimit, cap.RetentionDays, cap.RateLimit, graceAt,
	)
	return err
}

// CountActiveDevices returns the number of non-revoked devices for a user.
func (s *Store) CountActiveDevices(userID string) (int, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM devices WHERE user_id = $1 AND revoked_at IS NULL`,
		userID,
	).Scan(&count)
	return count, err
}

// IncrementDailyRequestCount atomically increments today's request count and returns the new total.
func (s *Store) IncrementDailyRequestCount(userID string) (int, error) {
	today := time.Now().UTC().Format("2006-01-02")
	var count int
	err := s.db.QueryRow(
		`INSERT INTO api_request_counts (user_id, date, count)
		 VALUES ($1, $2, 1)
		 ON CONFLICT(user_id, date) DO UPDATE SET count = api_request_counts.count + 1
		 RETURNING count`,
		userID, today,
	).Scan(&count)
	return count, err
}

// Invite is the row shape returned by ListInvites.
type Invite struct {
	// CodeHash is the SHA-256 hex of the plaintext invite code.
	// It is NOT the redeemable code; the plaintext cannot be recovered from it.
	CodeHash  string
	CreatedBy *string
	Label     string
	MaxUses   int
	UsedCount int
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// CreateInvite inserts a fresh invite row. createdBy may be nil (bootstrap).
func (s *Store) CreateInvite(codeHash string, createdBy *string, label string, maxUses int, expiresAt time.Time) error {
	_, err := s.db.Exec(`
		INSERT INTO invites (code_hash, created_by, label, max_uses, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`, codeHash, createdBy, label, maxUses, expiresAt)
	return err
}

// RedeemInvite atomically increments used_count when the invite is valid.
// Returns nil on success; an error if the code is unknown, expired, revoked,
// or fully used.
func (s *Store) RedeemInvite(codeHash string) error {
	res, err := s.db.Exec(`
		UPDATE invites
		SET    used_count = used_count + 1
		WHERE  code_hash    = $1
		  AND  revoked_at   IS NULL
		  AND  expires_at   > NOW()
		  AND  used_count   < max_uses
	`, codeHash)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("invite is unknown, expired, revoked, or used up")
	}
	return nil
}

// ListInvites returns every invite row, newest first.
func (s *Store) ListInvites() ([]Invite, error) {
	rows, err := s.db.Query(`
		SELECT code_hash, created_by, COALESCE(label,''), max_uses, used_count,
		       created_at, expires_at, revoked_at
		FROM   invites
		ORDER  BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invite
	for rows.Next() {
		var inv Invite
		if err := rows.Scan(&inv.CodeHash, &inv.CreatedBy, &inv.Label, &inv.MaxUses,
			&inv.UsedCount, &inv.CreatedAt, &inv.ExpiresAt, &inv.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

// RevokeInvite marks an invite revoked. Idempotent.
func (s *Store) RevokeInvite(codeHash string) error {
	res, err := s.db.Exec(
		`UPDATE invites SET revoked_at = NOW() WHERE code_hash = $1 AND revoked_at IS NULL`,
		codeHash,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var dummy string
		err2 := s.db.QueryRow(`SELECT code_hash FROM invites WHERE code_hash = $1`, codeHash).Scan(&dummy)
		if errors.Is(err2, sql.ErrNoRows) {
			return fmt.Errorf("invite not found: %s", codeHash)
		}
		// Row exists but was already revoked — idempotent success.
	}
	return nil
}

// SweepOldRequestCounts deletes daily request count rows older than retentionDays.
func (s *Store) SweepOldRequestCounts(retentionDays int) (int, error) {
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays).Format("2006-01-02")
	res, err := s.db.Exec(
		`DELETE FROM api_request_counts WHERE date < $1`,
		cutoff,
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// UserRow is the shape returned by ListUsers.
type UserRow struct {
	ID          string
	DisplayName string
	IsAdmin     bool
	CreatedAt   time.Time
}

// CountUsers returns the total number of user rows.
func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// SetUserAdmin sets or clears the is_admin flag for a user.
func (s *Store) SetUserAdmin(userID string, admin bool) error {
	res, err := s.db.Exec(`UPDATE users SET is_admin = $1 WHERE id = $2`, admin, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}
	return nil
}

// SetUserDisplayName updates display_name. A blank name is a no-op.
func (s *Store) SetUserDisplayName(userID, name string) error {
	if name == "" {
		return nil
	}
	res, err := s.db.Exec(`UPDATE users SET display_name = $1 WHERE id = $2`, name, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("user not found: %s", userID)
	}
	return nil
}

// IsUserAdmin reports whether the given user has is_admin = TRUE.
func (s *Store) IsUserAdmin(userID string) (bool, error) {
	var v bool
	err := s.db.QueryRow(`SELECT is_admin FROM users WHERE id = $1`, userID).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("user not found: %s", userID)
	}
	if err != nil {
		return false, err
	}
	return v, nil
}

// ListUsers returns all user rows ordered by creation time ascending.
func (s *Store) ListUsers() ([]UserRow, error) {
	rows, err := s.db.Query(`
		SELECT id, COALESCE(display_name,''), is_admin, created_at
		FROM   users ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserRow
	for rows.Next() {
		var u UserRow
		if err := rows.Scan(&u.ID, &u.DisplayName, &u.IsAdmin, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// DeleteUser removes a user and all dependent rows in the correct FK order.
// Wraps the deletions in a transaction so a failure leaves the DB consistent.
// invites.created_by is left intact (SET NULL by Postgres FK).
// For self-host operator use only.
func (s *Store) DeleteUser(userID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM clip_tombstones    WHERE user_id = $1`,
		`DELETE FROM clips              WHERE user_id = $1`,
		`DELETE FROM devices            WHERE user_id = $1`,
		`DELETE FROM user_capabilities  WHERE user_id = $1`,
		`DELETE FROM api_request_counts WHERE user_id = $1`,
		`DELETE FROM oauth_identities   WHERE user_id = $1`,
		`DELETE FROM users              WHERE id      = $1`,
	} {
		if _, err := tx.Exec(q, userID); err != nil {
			return fmt.Errorf("%s: %w", q, err)
		}
	}
	return tx.Commit()
}

// InternalUsersFilter is the input to ListInternalUserAggregates.
// Cursor carries the keyset (created_at, user_id) atomically; nil means
// the first page. Grouping the two fields into one pointer prevents
// callers from passing a half-set cursor (e.g. UserID without CreatedAt),
// which would otherwise collapse the SQL keyset disjunct to a tautology
// and silently return all rows instead of paginating.
type InternalUsersFilter struct {
	Limit        int
	Cursor       *InternalCursorPayload
	UpdatedSince *time.Time
	IncludeDemo  bool
}

// InternalUserAggregate is one row returned by ListInternalUserAggregates.
// Capabilities is nil when the user has no user_capabilities row.
type InternalUserAggregate struct {
	UserID            string
	CreatedAt         time.Time
	IsDemo            bool
	DeviceCount       int
	ActiveDeviceCount int
	LastActiveAt      *time.Time
	Capabilities      *InternalUserCapabilities
}

// InternalUserCapabilities mirrors user_capabilities columns plus updated_at.
type InternalUserCapabilities struct {
	DeviceLimit    int
	RetentionDays  int
	RateLimit      int
	GraceExpiresAt *time.Time
	UpdatedAt      time.Time
}

// InternalUsersPage wraps a result set with an opaque cursor for the next page.
type InternalUsersPage struct {
	Rows       []InternalUserAggregate
	NextCursor string
}

// ListInternalUserAggregates returns user rows with device aggregates and
// capability echoes, paginated by (created_at, id). Demo users are excluded
// unless f.IncludeDemo is true. UpdatedSince filters to users whose user row,
// capabilities row, or any device timestamp is newer than the given instant.
func (s *Store) ListInternalUserAggregates(f InternalUsersFilter) (InternalUsersPage, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	const q = `
SELECT
    u.id,
    u.created_at,
    u.is_demo,
    COUNT(d.id)                                                   AS device_count,
    COUNT(d.id) FILTER (WHERE d.revoked_at IS NULL)               AS active_device_count,
    MAX(d.last_push_at)                                           AS last_active_at,
    c.device_limit,
    c.retention_days,
    c.rate_limit,
    c.grace_expires_at,
    c.updated_at                                                  AS capabilities_updated_at
FROM users u
LEFT JOIN devices           d ON d.user_id = u.id
LEFT JOIN user_capabilities c ON c.user_id = u.id
WHERE
    ($1::boolean OR NOT u.is_demo)
    AND ($2::timestamptz IS NULL
         OR u.created_at > $2
         OR (u.created_at = $2 AND u.id > $3))
GROUP BY u.id, u.created_at, u.is_demo,
         c.device_limit, c.retention_days, c.rate_limit, c.grace_expires_at, c.updated_at
HAVING $4::timestamptz IS NULL
    OR u.created_at > $4
    OR c.updated_at > $4
    OR MAX(d.last_push_at) > $4
    OR MAX(d.paired_at)    > $4
    OR MAX(d.revoked_at)   > $4
ORDER BY u.created_at ASC, u.id ASC
LIMIT $5
`

	var cursorCreatedAt *time.Time
	var cursorUserID string
	if f.Cursor != nil {
		t := f.Cursor.CreatedAt
		cursorCreatedAt = &t
		cursorUserID = f.Cursor.UserID
	}

	rows, err := s.db.Query(q,
		f.IncludeDemo,
		cursorCreatedAt,
		cursorUserID,
		f.UpdatedSince,
		limit+1, // n+1 trick to know if there's another page
	)
	if err != nil {
		return InternalUsersPage{}, fmt.Errorf("query internal users: %w", err)
	}
	defer rows.Close()

	var out []InternalUserAggregate
	for rows.Next() {
		var a InternalUserAggregate
		var lastActive, capUpdated, capGrace sql.NullTime
		var capDeviceLimit, capRetention, capRateLimit sql.NullInt64
		if err := rows.Scan(
			&a.UserID, &a.CreatedAt, &a.IsDemo,
			&a.DeviceCount, &a.ActiveDeviceCount, &lastActive,
			&capDeviceLimit, &capRetention, &capRateLimit, &capGrace, &capUpdated,
		); err != nil {
			return InternalUsersPage{}, fmt.Errorf("scan internal user row: %w", err)
		}
		if lastActive.Valid {
			t := lastActive.Time
			a.LastActiveAt = &t
		}
		if capUpdated.Valid {
			caps := &InternalUserCapabilities{
				DeviceLimit:   int(capDeviceLimit.Int64),
				RetentionDays: int(capRetention.Int64),
				RateLimit:     int(capRateLimit.Int64),
				UpdatedAt:     capUpdated.Time,
			}
			if capGrace.Valid {
				t := capGrace.Time
				caps.GraceExpiresAt = &t
			}
			a.Capabilities = caps
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return InternalUsersPage{}, fmt.Errorf("iterate internal users: %w", err)
	}

	page := InternalUsersPage{Rows: out}
	if len(out) > limit {
		// We fetched limit+1 rows. Drop the extra and emit a cursor pointing at
		// the last in-page row so the next call resumes immediately after it.
		last := out[limit-1]
		page.Rows = out[:limit]
		page.NextCursor = EncodeInternalCursor(InternalCursorPayload{
			CreatedAt: last.CreatedAt,
			UserID:    last.UserID,
		})
	}
	return page, nil
}
