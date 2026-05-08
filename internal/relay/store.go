package relay

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	cinchv1 "github.com/cinchcli/relay/internal/gen/cinch/v1"
	"github.com/cinchcli/relay/internal/protocol"
	_ "github.com/lib/pq"
	"github.com/oklog/ulid/v2"
)

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
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}
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
			device_code TEXT PRIMARY KEY,
			user_code   TEXT UNIQUE NOT NULL,
			hostname    TEXT DEFAULT '',
			machine_id  TEXT,
			user_id     TEXT,
			device_id   TEXT,
			token       TEXT,
			status      TEXT DEFAULT 'pending',
			created_at  TIMESTAMPTZ DEFAULT NOW(),
			expires_at  TIMESTAMPTZ NOT NULL
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
func (s *Store) UpsertOAuthUser(provider, subject, email string, emailVerified bool, hostname, machineID string) (string, string, string, error) {
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
				if _, err := s.db.Exec(
					`INSERT INTO oauth_identities(id, user_id, provider, subject, email, email_verified)
					 VALUES ($1, $2, $3, $4, $5, TRUE) ON CONFLICT(provider, subject) DO NOTHING`,
					identityRowID, userID, provider, subject, email,
				); err != nil {
					return "", "", "", fmt.Errorf("linking cross-provider identity: %w", err)
				}
			} else {
				userID = ulid.Make().String()
				if _, err := s.db.Exec(`INSERT INTO users (id) VALUES ($1)`, userID); err != nil {
					return "", "", "", fmt.Errorf("creating oauth user: %w", err)
				}
				identityRowID = ulid.Make().String()
				if _, err := s.db.Exec(
					`INSERT INTO oauth_identities(id, user_id, provider, subject, email, email_verified)
					 VALUES ($1, $2, $3, $4, $5, TRUE) ON CONFLICT(provider, subject) DO NOTHING`,
					identityRowID, userID, provider, subject, email,
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
			if _, err := s.db.Exec(
				`INSERT INTO oauth_identities(id, user_id, provider, subject, email, email_verified)
				 VALUES ($1, $2, $3, $4, $5, FALSE) ON CONFLICT(provider, subject) DO NOTHING`,
				identityRowID, userID, provider, subject, emailArg,
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

	if existingID != "" {
		var args []interface{}
		query := `UPDATE devices SET token = $1, hostname = $2`
		args = append(args, deviceToken, hostname)
		paramIdx := 3
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

// SaveClip persists a clip and returns it.
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

	_, err := s.db.Exec(
		`INSERT INTO clips (id, user_id, content, content_type, source, label, byte_size, media_path, created_at, encrypted)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		clip.ClipId, clip.UserId, clip.Content, clip.ContentType,
		clip.Source, clip.Label, clip.ByteSize, sql.NullString{String: mediaPath, Valid: mediaPath != ""},
		now, clip.Encrypted,
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
		 FROM clips WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2`,
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

// ListClipsSince returns clips newer than `since` (exclusive), ordered oldest-first.
func (s *Store) ListClipsSince(userID string, since time.Time, limit int) ([]*cinchv1.Clip, error) {
	if since.IsZero() {
		return s.ListClips(userID, limit)
	}

	rows, err := s.db.Query(`
		SELECT id, user_id, content, content_type, source, label, byte_size,
		       media_path, created_at, encrypted
		FROM clips
		WHERE user_id = $1 AND created_at > $2
		ORDER BY created_at ASC
		LIMIT $3`,
		userID, since.UTC(), limit)
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

// GetLatestClipBySource returns the most recent clip from a specific source.
func (s *Store) GetLatestClipBySource(userID, source string) (*cinchv1.Clip, error) {
	c := &cinchv1.Clip{}
	var mediaPath sql.NullString
	var createdAt time.Time
	err := s.db.QueryRow(
		`SELECT id, user_id, content, content_type, source, label, byte_size, media_path, created_at, encrypted
		 FROM clips WHERE user_id = $1 AND source = $2
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
		`SELECT id, hostname, source_key, clip_count, paired_at, last_push_at, COALESCE(public_key, ''), COALESCE(nickname, '')
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
		 VALUES ($1, $2, $3, $4, $5)`,
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
		var email, provider sql.NullString
		if u != "" {
			_ = s.db.QueryRow(
				`SELECT email, provider FROM oauth_identities WHERE user_id = $1 AND email IS NOT NULL
				 ORDER BY last_seen_at DESC LIMIT 1`,
				u,
			).Scan(&email, &provider)
		}
		if email.Valid && email.String != "" {
			resp.Email = &email.String
		}
		if provider.Valid && provider.String != "" {
			resp.IdentityProvider = &provider.String
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
			log.Printf("retention sweep: deleted %d clips for user %s (>%d days)", count, ur.userID, ur.days)
		}
	}
	return nil
}

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
		if err := rows.Scan(&r.id, &r.key); err != nil {
			continue
		}
		toDelete = append(toDelete, r)
	}
	rows.Close()

	if err := rows.Err(); err != nil {
		return 0, nil, err
	}

	for _, r := range toDelete {
		if _, err := s.db.Exec("DELETE FROM clips WHERE id = $1 AND user_id = $2", r.id, userID); err != nil {
			log.Printf("sweep: delete clip %q: %v", r.id, err)
			continue
		}
		count++
		if r.key != "" {
			mediaPaths = append(mediaPaths, r.key)
		}
		if err := s.InsertTombstone(userID, r.id); err != nil {
			log.Printf("sweep: insert tombstone %q: %v", r.id, err)
		}
	}
	return count, mediaPaths, nil
}

// SweepAllUsersRetentionReturningMedia sweeps all users' expired clips and collects media keys.
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

	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, u := range users {
		retentionDays := u.days
		if cap, capErr := s.GetUserCapabilities(u.userID); capErr == nil && cap.RetentionDays > 0 {
			retentionDays = cap.RetentionDays
		}
		count, paths, sweepErr := s.SweepExpiredClipsReturningMedia(u.userID, retentionDays)
		if sweepErr != nil {
			log.Printf("retention sweep: user %s: %v", u.userID, sweepErr)
		} else if count > 0 {
			log.Printf("retention sweep: deleted %d clips for user %s (>%d days)", count, u.userID, retentionDays)
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

// SetDevicePublicKey stores the X25519 public key and its fingerprint for a device.
func (s *Store) SetDevicePublicKey(deviceID, pubKeyB64, fingerprint string) error {
	res, err := s.db.Exec(
		"UPDATE devices SET public_key = $1, public_key_fingerprint = $2 WHERE id = $3",
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
