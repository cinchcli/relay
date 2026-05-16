# Invite-Token Self-Host Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let self-hosted relays gate account registration with single-use invite tokens, support a single admin (the first user), and expose admin operations through both a local-only `relay` binary subcommand and an HTTP `/admin/*` API consumed by `cinch admin ...`.

**Architecture:** Three phases. (1) cinch-core wire schema adds two optional fields to `LoginRequest`. (2) Relay adds an `invites` table + `users.is_admin`/`users.display_name` columns, gates `AuthLogin`/Connect-RPC `Login` on a valid invite when no OAuth providers are configured, bootstraps the first invite from `RELAY_BOOTSTRAP_INVITE_CODE`, ships HTTP `/admin/*` endpoints, and adds `relay invite|user ...` subcommands on the binary. (3) Cinch CLI grows a thin `cinch admin ...` client over the new HTTP API.

**Tech Stack:** Go (relay), Rust (cinch-core, cinch CLI), Protobuf 3 + buf, Postgres, Connect-RPC, clap.

**Out of scope:** Generic OIDC provider (option B from design discussion — separate future plan). Per-user invite permissions (only admin issues invites). Web admin UI (CLI only). Desktop app changes.

---

## Cross-Cutting Design Decisions

**Settled in design discussion:**
- OAuth-and-invite are **mutex**: when any OAuth provider env is configured, the invite gate stays off and `/auth/login` remains unregistered (existing behavior preserved).
- **First user = admin**: whoever creates the first user row gets `is_admin = TRUE` automatically. No separate `relay admin promote` for bootstrap.
- **Label is operator-side convenience only.** Optional at create time, never required. Identity is captured from the user's `display_name` input at redemption.
- **Defaults**: invite expires in 7 days, max 1 use. Override with `--expires` / `--uses` on create.
- **Both admin surfaces**: `relay` binary subcommand (local, no auth, talks straight to Postgres) for bootstrap / emergency, and HTTP `/admin/*` + `cinch admin ...` for daily ops.

**Invite code format** (locked here):
- 24 random bytes → base32 (no padding, lowercase) → 39-char body → prefix `cinch_inv_` → total ~49 chars.
- Stored as SHA-256 hex digest (`code_hash` is PRIMARY KEY). Plaintext code is returned **only at creation** and never re-shown.
- Comparison and revoke lookups use the hash.

**Bootstrap rule** (locked here):
- On startup, if `RELAY_BOOTSTRAP_INVITE_CODE` env var is set AND `SELECT COUNT(*) FROM users = 0`, the relay inserts one invite row with `code_hash = sha256(env_value)`, `max_uses = 1`, `expires_at = NOW() + 7d`, `label = 'bootstrap'`. Logs `bootstrap invite installed; expires <ts>`.
- If users already exist, the env var is logged once as "ignored — bootstrap already complete" and otherwise ignored.

**Admin-only routes:** standard `RequireAuth` middleware → resolve device token → load `users.is_admin` → 403 if false. New helper `RequireAdmin` wraps `RequireAuth`.

---

## File Structure

### Phase 1 — cinch-core wire schema
- **Modify:** `cinch-core/crates/client-core/proto/cinch/v1/auth.proto` — add fields 2, 3 to `LoginRequest`
- **Regenerated:** `cinch-core/go/cinch/v1/auth.pb.go`, Rust `OUT_DIR/cinch.v1.rs`
- **Modify:** `cinch-core/crates/client-core/Cargo.toml` — bump minor version (`0.1.4` → `0.1.5`)
- **Modify:** `cinch-core/testdata/wire-vectors.json` + mirror in `relay/internal/wire_test/testdata/wire-vectors.json`
- **Verify:** existing `cinch-core/crates/client-core/tests/wire_vectors.rs` round-trips with the new fields populated

### Phase 2 — relay
- **Modify:** `relay/internal/relay/store.go` — migration (new `invites` table + 2 columns on `users`) and new Store methods
- **Create:** `relay/internal/relay/invites.go` — pure-domain helpers (code generation, hashing, validation)
- **Create:** `relay/internal/relay/invites_test.go`
- **Modify:** `relay/internal/relay/handler.go` — gate `AuthLogin` on invite + display_name handling, new `RequireAdmin` middleware, register admin routes
- **Modify:** `relay/internal/relay/connect_auth.go` — mirror gating in Connect-RPC `Login`
- **Create:** `relay/internal/relay/admin.go` — HTTP `/admin/*` handlers
- **Create:** `relay/internal/relay/admin_test.go`
- **Modify:** `relay/cmd/relay/main.go` — bootstrap-env import + subcommand dispatch
- **Create:** `relay/cmd/relay/admin_cli.go` — `relay invite|user ...` subcommands
- **Modify:** `relay/go.mod` — bump `cinch-core` to the new tag

### Phase 3 — cinch CLI
- **Create:** `cinch/crates/cli/src/commands/admin.rs` — clap subcommand tree + HTTP calls
- **Modify:** `cinch/crates/cli/src/commands/mod.rs` — `pub mod admin;`
- **Modify:** `cinch/crates/cli/src/main.rs` — wire `Admin` subcommand into the top-level enum
- **Modify:** `cinch/crates/cli/Cargo.toml` — bump `client-core` to the new minor

---

## Phase 1 — cinch-core: add `invite_code` and `display_name` to `LoginRequest`

### Task 1.1: Add proto fields and regenerate

**Files:** Modify `cinch-core/crates/client-core/proto/cinch/v1/auth.proto`

- [ ] **Step 1: Edit `LoginRequest`**

Replace the existing message:

```proto
message LoginRequest {
  optional string hostname = 1;
  // Single-use invite token required when the relay has no OAuth provider
  // configured. Ignored on OAuth-enabled relays (they reject /auth/login
  // entirely). Format: "cinch_inv_<base32>".
  optional string invite_code = 2;
  // Friendly display name the user types at the browser sign-in page.
  // Stored on `users.display_name`; shown in `relay user list`.
  optional string display_name = 3;
}
```

- [ ] **Step 2: Regenerate bindings**

Run:
```bash
cd cinch-core && make generate
```
Expected: `go/cinch/v1/auth.pb.go` and the Rust `OUT_DIR/cinch.v1.rs` regenerate without manual edits.

- [ ] **Step 3: Verify Rust build**

Run:
```bash
cd cinch-core && cargo build --workspace
```
Expected: clean build.

- [ ] **Step 4: Verify Go build + tests**

Run:
```bash
cd cinch-core && go test ./go/...
```
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
cd cinch-core
git add crates/client-core/proto/cinch/v1/auth.proto go/cinch/v1/auth.pb.go
git commit -m "feat(proto): add invite_code and display_name to LoginRequest"
```

### Task 1.2: Extend wire-vector golden file (round-trip coverage)

**Files:** Modify `cinch-core/testdata/wire-vectors.json`; the existing `tests/wire_vectors.rs` already asserts byte-equal round-trip.

- [ ] **Step 1: Add a `LoginRequest` vector with the new fields**

Add (next to any existing `LoginRequest` entry — if none exists, add a new top-level entry keyed `"LoginRequest_invite"`):

```json
{
  "LoginRequest_invite": {
    "hostname": "my-macbook",
    "invite_code": "cinch_inv_aaaabbbbccccddddeeeeffffgggghhhhiiii",
    "display_name": "han"
  }
}
```

- [ ] **Step 2: Run the wire-vector test**

Run:
```bash
cd cinch-core && cargo test -p cinchcli-core --test wire_vectors
```
Expected: PASS. (Test parses JSON → proto → JSON, asserts byte-equal modulo key order.)

- [ ] **Step 3: Mirror the file into relay**

```bash
cp cinch-core/testdata/wire-vectors.json \
   relay/internal/wire_test/testdata/wire-vectors.json
```

- [ ] **Step 4: Run the relay-side round-trip**

Run:
```bash
cd relay && go test ./internal/wire_test/...
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd cinch-core
git add testdata/wire-vectors.json
git commit -m "test(proto): wire-vector for LoginRequest with invite + display_name"
```

(The relay-side copy commits as part of Task 2.13 when bumping `cinch-core`.)

### Task 1.3: Bump `cinchcli-core` to `0.1.5` and publish

- [ ] **Step 1: Bump version**

In `cinch-core/crates/client-core/Cargo.toml`:
```toml
[package]
name = "cinchcli-core"
version = "0.1.5"
```

- [ ] **Step 2: Re-run full test suite**

Run:
```bash
cd cinch-core && cargo test --workspace && go test ./go/...
```
Expected: all pass.

- [ ] **Step 3: Commit**

```bash
cd cinch-core
git add crates/client-core/Cargo.toml
git commit -m "chore(cinch-core): bump cinchcli-core to 0.1.5"
```

- [ ] **Step 4: Publish + tag** (manual step, requires crates.io token)

```bash
cd cinch-core
cargo publish -p cinchcli-core
git tag v0.1.5 && git push --tags
```
Expected: crate appears at https://crates.io/crates/cinchcli-core/0.1.5.

---

## Phase 2 — relay: invite system + admin

### Task 2.1: Schema migration — `invites` table + `users.is_admin` + `users.display_name`

**Files:** Modify `relay/internal/relay/store.go` (extend `migrate()`); create `relay/internal/relay/store_invite_test.go`.

- [ ] **Step 1: Write the failing test**

Create `relay/internal/relay/store_invite_test.go`:

```go
package relay

import "testing"

func TestMigrate_CreatesInvitesTable(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	var exists bool
	if err := s.db.QueryRow(`SELECT EXISTS (
		SELECT 1 FROM information_schema.tables WHERE table_name = 'invites'
	)`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("invites table missing after migrate()")
	}
}

func TestMigrate_AddsUserAdminAndDisplayName(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	for _, c := range []struct{ col, want string }{
		{"is_admin", "boolean"},
		{"display_name", "text"},
	} {
		var dt string
		err := s.db.QueryRow(`SELECT data_type FROM information_schema.columns
			WHERE table_name = 'users' AND column_name = $1`, c.col).Scan(&dt)
		if err != nil {
			t.Fatalf("users.%s missing: %v", c.col, err)
		}
		if dt != c.want {
			t.Fatalf("users.%s type = %q, want %q", c.col, dt, c.want)
		}
	}
}
```

(Use whatever existing test-store helper is in the package — look for the pattern in `store_test.go` and reuse the name; if it is exported as `testStore`, swap `newTestStore` for `testStore`. Do not introduce a new helper.)

- [ ] **Step 2: Run the test (expect FAIL)**

Run:
```bash
cd relay && go test ./internal/relay -run 'TestMigrate_Creates|TestMigrate_AddsUser' -v
```
Expected: FAIL — table missing, columns missing.

- [ ] **Step 3: Extend the migration**

In `relay/internal/relay/store.go`, inside `migrate()`, after the existing `_, err = db.Exec(...)` block that creates the legacy tables (around line 60–170) add **before** the bool-column type conversions:

```go
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
`)
if err != nil {
	return fmt.Errorf("invites + user columns migration: %w", err)
}
```

- [ ] **Step 4: Run the test (expect PASS)**

Run:
```bash
cd relay && go test ./internal/relay -run 'TestMigrate_Creates|TestMigrate_AddsUser' -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd relay
git add internal/relay/store.go internal/relay/store_invite_test.go
git commit -m "feat(relay): add invites table and is_admin/display_name on users"
```

### Task 2.2: Pure invite helpers — code generation + hashing

**Files:** Create `relay/internal/relay/invites.go` and `relay/internal/relay/invites_test.go`.

- [ ] **Step 1: Write the failing tests**

`relay/internal/relay/invites_test.go`:

```go
package relay

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateInviteCode_PrefixAndLength(t *testing.T) {
	c, err := GenerateInviteCode()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c, "cinch_inv_") {
		t.Fatalf("missing prefix: %q", c)
	}
	body := strings.TrimPrefix(c, "cinch_inv_")
	if got := len(body); got != 39 {
		t.Fatalf("body length = %d, want 39", got)
	}
	for _, r := range body {
		if !(('a' <= r && r <= 'z') || ('2' <= r && r <= '7')) {
			t.Fatalf("non-base32 char in body: %q", r)
		}
	}
}

func TestGenerateInviteCode_Unique(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 100; i++ {
		c, err := GenerateInviteCode()
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[c]; dup {
			t.Fatal("duplicate invite code generated")
		}
		seen[c] = struct{}{}
	}
}

func TestHashInviteCode_DeterministicHex64(t *testing.T) {
	h := HashInviteCode("cinch_inv_abcdef")
	if len(h) != 64 {
		t.Fatalf("hash length = %d, want 64", len(h))
	}
	if _, err := hex.DecodeString(h); err != nil {
		t.Fatalf("hash is not hex: %v", err)
	}
	if HashInviteCode("cinch_inv_abcdef") != h {
		t.Fatal("hash is not deterministic")
	}
	if HashInviteCode("cinch_inv_xyz") == h {
		t.Fatal("different inputs produced same hash")
	}
}
```

- [ ] **Step 2: Run the tests (expect FAIL)**

Run:
```bash
cd relay && go test ./internal/relay -run 'TestGenerateInviteCode|TestHashInviteCode' -v
```
Expected: FAIL — undefined identifiers.

- [ ] **Step 3: Implement helpers**

`relay/internal/relay/invites.go`:

```go
package relay

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
)

const InvitePrefix = "cinch_inv_"

// GenerateInviteCode returns a fresh single-use invite code in the form
// "cinch_inv_<base32-of-24-random-bytes>". The unprefixed body is 39 chars.
func GenerateInviteCode() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	body := enc.EncodeToString(b[:])
	// StdEncoding is uppercase; switch to lowercase for friendlier URLs.
	body = toLowerASCII(body)
	return InvitePrefix + body, nil
}

// HashInviteCode returns the lowercase hex SHA-256 of the full code.
// This is what gets stored in invites.code_hash.
func HashInviteCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

func toLowerASCII(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}
```

- [ ] **Step 4: Run the tests (expect PASS)**

Run:
```bash
cd relay && go test ./internal/relay -run 'TestGenerateInviteCode|TestHashInviteCode' -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd relay
git add internal/relay/invites.go internal/relay/invites_test.go
git commit -m "feat(relay): invite code generation + sha256 hashing"
```

### Task 2.3: Store methods — `CreateInvite`, `RedeemInvite`, `ListInvites`, `RevokeInvite`

**Files:** Modify `relay/internal/relay/store.go`; extend `relay/internal/relay/store_invite_test.go`.

- [ ] **Step 1: Write the failing tests**

Append to `store_invite_test.go`:

```go
import "time"

func TestCreateAndListInvite(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	hash := HashInviteCode("cinch_inv_test123")
	exp := time.Now().Add(7 * 24 * time.Hour)
	if err := s.CreateInvite(hash, nil, "friend-han", 1, exp); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListInvites()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 invite, got %d", len(list))
	}
	if list[0].Label != "friend-han" || list[0].MaxUses != 1 {
		t.Fatalf("bad invite: %+v", list[0])
	}
}

func TestRedeemInvite_HappyPath(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	hash := HashInviteCode("cinch_inv_red")
	if err := s.CreateInvite(hash, nil, "", 1, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemInvite(hash); err != nil {
		t.Fatalf("first redeem failed: %v", err)
	}
	if err := s.RedeemInvite(hash); err == nil {
		t.Fatal("second redeem should fail (used up)")
	}
}

func TestRedeemInvite_RejectsExpired(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	hash := HashInviteCode("cinch_inv_old")
	_ = s.CreateInvite(hash, nil, "", 1, time.Now().Add(-time.Hour))
	if err := s.RedeemInvite(hash); err == nil {
		t.Fatal("expired invite should be rejected")
	}
}

func TestRevokeInvite_StopsRedemption(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	hash := HashInviteCode("cinch_inv_revoked")
	_ = s.CreateInvite(hash, nil, "", 5, time.Now().Add(time.Hour))
	if err := s.RevokeInvite(hash); err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemInvite(hash); err == nil {
		t.Fatal("revoked invite should be rejected")
	}
}
```

- [ ] **Step 2: Run tests (expect FAIL — methods missing)**

```bash
cd relay && go test ./internal/relay -run 'TestCreateAndListInvite|TestRedeemInvite|TestRevokeInvite' -v
```
Expected: FAIL with undefined `s.CreateInvite` etc.

- [ ] **Step 3: Implement Store methods**

Append to `relay/internal/relay/store.go`:

```go
// Invite is the row shape returned by ListInvites.
type Invite struct {
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
	_, err := s.db.Exec(
		`UPDATE invites SET revoked_at = NOW() WHERE code_hash = $1 AND revoked_at IS NULL`,
		codeHash,
	)
	return err
}
```

(Add `"time"` to the import block if not present.)

- [ ] **Step 4: Run tests (expect PASS)**

```bash
cd relay && go test ./internal/relay -run 'TestCreateAndListInvite|TestRedeemInvite|TestRevokeInvite' -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd relay
git add internal/relay/store.go internal/relay/store_invite_test.go
git commit -m "feat(relay): Store CRUD for invites"
```

### Task 2.4: User helpers — `CountUsers`, `SetUserAdmin`, `SetUserDisplayName`, `IsUserAdmin`, `ListUsers`, `DeleteUser`

**Files:** Modify `relay/internal/relay/store.go`; extend `relay/internal/relay/store_invite_test.go`.

- [ ] **Step 1: Write the failing tests**

Append to `store_invite_test.go`:

```go
func TestUserAdminAndDisplayName(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	uid := "u1"
	if err := s.CreateUser(uid); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserDisplayName(uid, "han"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserAdmin(uid, true); err != nil {
		t.Fatal(err)
	}
	ok, err := s.IsUserAdmin(uid)
	if err != nil || !ok {
		t.Fatalf("IsUserAdmin=%v err=%v want true", ok, err)
	}
	count, err := s.CountUsers()
	if err != nil || count != 1 {
		t.Fatalf("CountUsers=%d err=%v want 1", count, err)
	}
	list, err := s.ListUsers()
	if err != nil || len(list) != 1 || list[0].DisplayName != "han" || !list[0].IsAdmin {
		t.Fatalf("ListUsers bad: %+v err=%v", list, err)
	}
	if err := s.DeleteUser(uid); err != nil {
		t.Fatal(err)
	}
	count2, _ := s.CountUsers()
	if count2 != 0 {
		t.Fatalf("DeleteUser failed: count=%d", count2)
	}
}
```

- [ ] **Step 2: Run test (expect FAIL)**

```bash
cd relay && go test ./internal/relay -run TestUserAdminAndDisplayName -v
```

- [ ] **Step 3: Implement helpers**

Append to `relay/internal/relay/store.go`:

```go
type UserRow struct {
	ID          string
	DisplayName string
	IsAdmin     bool
	CreatedAt   time.Time
}

func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) SetUserAdmin(userID string, admin bool) error {
	_, err := s.db.Exec(`UPDATE users SET is_admin = $1 WHERE id = $2`, admin, userID)
	return err
}

func (s *Store) SetUserDisplayName(userID, name string) error {
	if name == "" {
		return nil
	}
	_, err := s.db.Exec(`UPDATE users SET display_name = $1 WHERE id = $2`, name, userID)
	return err
}

func (s *Store) IsUserAdmin(userID string) (bool, error) {
	var v bool
	err := s.db.QueryRow(`SELECT is_admin FROM users WHERE id = $1`, userID).Scan(&v)
	return v, err
}

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

// DeleteUser removes a user and its dependent rows. Relies on CASCADE on
// oauth_identities; clips/devices/etc. use plain FK so caller must accept
// failure if those still reference the user. For self-host operator use.
func (s *Store) DeleteUser(userID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM clip_tombstones WHERE user_id = $1`,
		`DELETE FROM clips           WHERE user_id = $1`,
		`DELETE FROM devices         WHERE user_id = $1`,
		`DELETE FROM user_capabilities WHERE user_id = $1`,
		`DELETE FROM api_request_counts WHERE user_id = $1`,
		`DELETE FROM oauth_identities WHERE user_id = $1`,
		`DELETE FROM users           WHERE id      = $1`,
	} {
		if _, err := tx.Exec(q, userID); err != nil {
			return fmt.Errorf("%s: %w", q, err)
		}
	}
	return tx.Commit()
}
```

- [ ] **Step 4: Run test (expect PASS)**

```bash
cd relay && go test ./internal/relay -run TestUserAdminAndDisplayName -v
```

- [ ] **Step 5: Commit**

```bash
cd relay
git add internal/relay/store.go internal/relay/store_invite_test.go
git commit -m "feat(relay): user helpers (admin flag, display name, count, list, delete)"
```

### Task 2.5: Gate `AuthLogin` on invite + capture `display_name` + first-user-is-admin

**Files:** Modify `relay/internal/relay/handler.go:226-292` (the `AuthLogin` function); extend handler tests.

- [ ] **Step 1: Write the failing tests**

Create `relay/internal/relay/auth_login_invite_test.go`:

```go
package relay

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	cinchv1 "github.com/cinchcli/cinch-core/go/cinch/v1"
)

func TestAuthLogin_RejectsWithoutInvite(t *testing.T) {
	h := newTestHandler(t) // no OAuth providers configured
	defer h.Close()

	body, _ := json.Marshal(cinchv1.LoginRequest{})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	h.AuthLogin(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestAuthLogin_AcceptsValidInvite_FirstUserBecomesAdmin(t *testing.T) {
	h := newTestHandler(t)
	defer h.Close()

	code := "cinch_inv_first1"
	hash := HashInviteCode(code)
	if err := h.store.CreateInvite(hash, nil, "bootstrap", 1, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	hostname := "macbook"
	display := "han"
	body, _ := json.Marshal(cinchv1.LoginRequest{
		Hostname: &hostname, InviteCode: &code, DisplayName: &display,
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	h.AuthLogin(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s want 200", w.Code, w.Body.String())
	}
	var resp cinchv1.LoginResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.UserId == "" {
		t.Fatal("empty user_id")
	}
	admin, _ := h.store.IsUserAdmin(resp.UserId)
	if !admin {
		t.Fatal("first user should be admin")
	}
	users, _ := h.store.ListUsers()
	if len(users) != 1 || users[0].DisplayName != "han" {
		t.Fatalf("user row wrong: %+v", users)
	}
}

func TestAuthLogin_RejectsExhaustedInvite(t *testing.T) {
	h := newTestHandler(t)
	defer h.Close()
	code := "cinch_inv_exhaust"
	hash := HashInviteCode(code)
	_ = h.store.CreateInvite(hash, nil, "", 1, time.Now().Add(time.Hour))
	_ = h.store.RedeemInvite(hash) // pre-consume

	body, _ := json.Marshal(cinchv1.LoginRequest{InviteCode: &code})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	h.AuthLogin(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}
```

(Reuse whichever `newTestHandler` / handler-test helper exists in the package — check `handler_test.go` and `oauth_test.go` for the established pattern. If the existing helper enables OAuth, add a variant that leaves `h.OAuth = nil`.)

- [ ] **Step 2: Run tests (expect FAIL)**

```bash
cd relay && go test ./internal/relay -run TestAuthLogin -v
```

- [ ] **Step 3: Modify `AuthLogin`**

In `relay/internal/relay/handler.go`, replace the body of `AuthLogin` (currently at ~line 233) with this version. **Key changes**: invite-gate added, `display_name` captured, first user promoted to admin in a single transaction with redemption.

```go
func (h *Handler) AuthLogin(w http.ResponseWriter, r *http.Request) {
	// OAuth-enabled relays reject /auth/login outright (preserves security
	// finding 3 — audit trail).
	if h.OAuth != nil && (h.OAuth.GitHub != nil || h.OAuth.Google != nil) {
		writeError(w, http.StatusForbidden, "oauth_required",
			"Direct login is disabled. Use OAuth to authenticate.", "")
		return
	}

	// IP-based rate limiting (unchanged).
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip, _, _ = strings.Cut(r.RemoteAddr, ":")
	} else {
		ip = strings.TrimSpace(strings.SplitN(ip, ",", 2)[0])
	}
	if ip != "127.0.0.1" && ip != "::1" {
		h.loginRateMu.Lock()
		if last, ok := h.loginRateMap[ip]; ok && time.Since(last) < loginRateWindow {
			h.loginRateMu.Unlock()
			writeError(w, http.StatusTooManyRequests, "rate_limited",
				"Too many login attempts. Try again in a minute.", "")
			return
		}
		h.loginRateMap[ip] = time.Now()
		h.loginRateMu.Unlock()
	}

	var req cinchv1.LoginRequest
	if r.Body != nil && r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	// Invite gate: required when OAuth is off.
	if req.InviteCode == nil || *req.InviteCode == "" {
		writeError(w, http.StatusForbidden, "invite_required",
			"An invite code is required to create an account on this relay.",
			"Ask the operator for an invite code.")
		return
	}
	hash := HashInviteCode(*req.InviteCode)
	if err := h.store.RedeemInvite(hash); err != nil {
		writeError(w, http.StatusForbidden, "invite_invalid",
			"Invite code is invalid, expired, revoked, or used up.", "")
		return
	}

	hostname := "unknown"
	if req.Hostname != nil && *req.Hostname != "" {
		hostname = *req.Hostname
	}

	userID := ulid.Make().String()
	if err := h.store.CreateUser(userID); err != nil {
		writeInternalError(w, "account creation failed", "create account", err)
		return
	}
	if req.DisplayName != nil && *req.DisplayName != "" {
		_ = h.store.SetUserDisplayName(userID, *req.DisplayName)
	}

	// First user on the relay becomes admin automatically. CountUsers is
	// called after the insert, so the freshly-created user is included.
	if n, err := h.store.CountUsers(); err == nil && n == 1 {
		_ = h.store.SetUserAdmin(userID, true)
	}

	deviceID := ulid.Make().String()
	deviceToken := generateToken()
	if err := h.store.RegisterDeviceWithToken(userID, deviceID, hostname, deviceToken); err != nil {
		writeError(w, http.StatusInternalServerError, "device creation failed", err.Error(), "")
		return
	}

	writeJSON(w, http.StatusOK, cinchv1.LoginResponse{
		Token: deviceToken, UserId: userID, DeviceId: deviceID,
	})
}
```

- [ ] **Step 4: Run tests (expect PASS)**

```bash
cd relay && go test ./internal/relay -run TestAuthLogin -v
```

- [ ] **Step 5: Re-register the route unconditionally when OAuth is off**

The existing `RegisterRoutes` already guards `/auth/login` registration on OAuth absence — no change required. Verify by reading `handler.go:1773-1776`.

- [ ] **Step 6: Commit**

```bash
cd relay
git add internal/relay/handler.go internal/relay/auth_login_invite_test.go
git commit -m "feat(relay): gate AuthLogin on invite code; capture display name; first user is admin"
```

### Task 2.6: Mirror gating in Connect-RPC `Login`

**Files:** Modify `relay/internal/relay/connect_auth.go`.

- [ ] **Step 1: Locate the existing Connect `Login` handler**

```bash
grep -n 'func .* Login' relay/internal/relay/connect_auth.go
```

- [ ] **Step 2: Write the failing test**

Add `TestConnectLogin_RejectsWithoutInvite` to whatever existing Connect-RPC test file covers auth (look for `connect_auth_test.go` or extend `auth_login_invite_test.go`). The test pattern mirrors Task 2.5 Step 1, but calls the Connect-RPC `Login` method (over `httptest.NewServer` + Connect client) instead of the REST handler.

- [ ] **Step 3: Implement gating**

In the Connect-RPC `Login` body, add the same two checks used in Task 2.5:
1. Return `connect.NewError(connect.CodePermissionDenied, errors.New("invite_required"))` when `req.Msg.InviteCode` is empty/nil.
2. Call `h.store.RedeemInvite(HashInviteCode(*req.Msg.InviteCode))` and return `PermissionDenied` on error.
3. Capture `req.Msg.DisplayName` on the created user via `SetUserDisplayName`.
4. After successful creation, call `CountUsers` and promote to admin if `== 1`.

- [ ] **Step 4: Run test (expect PASS)**

```bash
cd relay && go test ./internal/relay -run TestConnectLogin -v
```

- [ ] **Step 5: Commit**

```bash
cd relay
git add internal/relay/connect_auth.go internal/relay/auth_login_invite_test.go
git commit -m "feat(relay): mirror invite gate in Connect-RPC Login"
```

### Task 2.7: `RELAY_BOOTSTRAP_INVITE_CODE` bootstrap on startup

**Files:** Modify `relay/cmd/relay/main.go`; add `relay/internal/relay/bootstrap.go`.

- [ ] **Step 1: Write the failing test**

Create `relay/internal/relay/bootstrap_test.go`:

```go
package relay

import (
	"strings"
	"testing"
	"time"
)

func TestApplyBootstrapInvite_NoUsers_InstallsInvite(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	logBuf := &strings.Builder{}
	if err := ApplyBootstrapInvite(s, "cinch_inv_boot", logBuf); err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemInvite(HashInviteCode("cinch_inv_boot")); err != nil {
		t.Fatalf("bootstrap invite should be redeemable: %v", err)
	}
	if !strings.Contains(logBuf.String(), "bootstrap invite installed") {
		t.Fatalf("expected log message, got %q", logBuf.String())
	}
}

func TestApplyBootstrapInvite_UsersExist_NoOp(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	_ = s.CreateUser("u")
	logBuf := &strings.Builder{}
	if err := ApplyBootstrapInvite(s, "cinch_inv_late", logBuf); err != nil {
		t.Fatal(err)
	}
	if err := s.RedeemInvite(HashInviteCode("cinch_inv_late")); err == nil {
		t.Fatal("bootstrap invite should NOT have been installed after users exist")
	}
	if !strings.Contains(logBuf.String(), "ignored") {
		t.Fatalf("expected ignore log, got %q", logBuf.String())
	}
	_ = time.Now() // keep time import if linter complains
}
```

- [ ] **Step 2: Run test (expect FAIL — undefined)**

```bash
cd relay && go test ./internal/relay -run TestApplyBootstrapInvite -v
```

- [ ] **Step 3: Implement**

Create `relay/internal/relay/bootstrap.go`:

```go
package relay

import (
	"fmt"
	"io"
	"time"
)

// ApplyBootstrapInvite installs the env-provided invite code as a single-use
// 7-day invite IFF the relay has zero users. Safe to call on every startup.
// Writes a status line to log.
func ApplyBootstrapInvite(s *Store, code string, log io.Writer) error {
	if code == "" {
		return nil
	}
	n, err := s.CountUsers()
	if err != nil {
		return fmt.Errorf("counting users: %w", err)
	}
	if n > 0 {
		fmt.Fprintln(log, "RELAY_BOOTSTRAP_INVITE_CODE ignored — users already exist; bootstrap already complete")
		return nil
	}
	hash := HashInviteCode(code)
	exp := time.Now().Add(7 * 24 * time.Hour)
	if err := s.CreateInvite(hash, nil, "bootstrap", 1, exp); err != nil {
		// Idempotency: if relay restarts before redemption, the same hash is
		// already in the table; ignore duplicate-key errors silently.
		fmt.Fprintf(log, "bootstrap invite already present in DB (restart before redemption): %v\n", err)
		return nil
	}
	fmt.Fprintf(log, "bootstrap invite installed; expires %s\n", exp.UTC().Format(time.RFC3339))
	return nil
}
```

- [ ] **Step 4: Wire into `cmd/relay/main.go`**

Add after `store, err := relay.NewStore(dsn)` but before the server starts:

```go
if code := os.Getenv("RELAY_BOOTSTRAP_INVITE_CODE"); code != "" {
	if err := relay.ApplyBootstrapInvite(store, code, os.Stderr); err != nil {
		log.Fatalf("bootstrap invite: %v", err)
	}
}
```

- [ ] **Step 5: Run tests (expect PASS)**

```bash
cd relay && go test ./internal/relay -run TestApplyBootstrapInvite -v
cd relay && go build ./...
```

- [ ] **Step 6: Commit**

```bash
cd relay
git add internal/relay/bootstrap.go internal/relay/bootstrap_test.go cmd/relay/main.go
git commit -m "feat(relay): RELAY_BOOTSTRAP_INVITE_CODE installs first-user invite"
```

### Task 2.8: Browser HTML — invite + "Your name" inputs

**Files:** Modify `relay/internal/relay/handler.go:1357+` (`authBrowserHTML` constant).

- [ ] **Step 1: Decide visibility logic**

The page is rendered for both OAuth-enabled and OAuth-disabled relays (OAuth-enabled relays redirect from this page). The invite + display-name fields should appear only when the page is in "self-host invite mode." Since `AuthBrowser` handler already has visibility into `h.OAuth`, render the fields conditionally by templating.

Convert `authBrowserHTML` from a `const` to a `text/template.Template` parsed once at handler init (similar to the `authOAuthData` flow already in place at line 1490+). The template receives `{SelfHost bool, DeviceCode string}`. When `SelfHost` is true, show invite + name fields.

- [ ] **Step 2: Update the template body**

Inside the `<form>`, before the existing `Device Name` field, add (template snippet):

```html
{{if .SelfHost}}
<div class="field">
  <label for="invite">Invite code</label>
  <input type="text" id="invite" name="invite" placeholder="cinch_inv_…" required autocomplete="off">
</div>
<div class="field">
  <label for="display">Your name (optional)</label>
  <input type="text" id="display" name="display" placeholder="han" autocomplete="off">
</div>
{{end}}
```

In the inline `<script>` `fetch(relayURL + '/auth/login', { … body: JSON.stringify(…) })`, change the body to:

```js
body: JSON.stringify({
  hostname: hostname,
  invite_code: document.getElementById('invite') ? document.getElementById('invite').value.trim() : undefined,
  display_name: document.getElementById('display') ? document.getElementById('display').value.trim() : undefined
})
```

- [ ] **Step 3: Render with the new data**

In `AuthBrowser` (the GET `/auth/browser` handler), pass `SelfHost: h.OAuth == nil || (h.OAuth.GitHub == nil && h.OAuth.Google == nil)` to the template.

- [ ] **Step 4: Verify**

Run the relay locally with no OAuth env vars, hit `http://localhost:8080/auth/browser?device_code=AAAA-BBBB`, confirm the invite + display-name fields render. Submit with a fresh invite from `RELAY_BOOTSTRAP_INVITE_CODE`. Confirm `users.display_name` is populated.

- [ ] **Step 5: Commit**

```bash
cd relay
git add internal/relay/handler.go
git commit -m "feat(relay): browser sign-in page shows invite + display name fields in self-host mode"
```

### Task 2.9: `RequireAdmin` middleware

**Files:** Modify `relay/internal/relay/handler.go` (add new helper next to `RequireAuth`).

- [ ] **Step 1: Write the failing test**

In a new `relay/internal/relay/admin_test.go`:

```go
package relay

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireAdmin_RejectsNonAdmin(t *testing.T) {
	h := newTestHandler(t)
	defer h.Close()
	// Non-admin user + device token
	uid := "u-nonadmin"
	_ = h.store.CreateUser(uid)
	tok := "tok-nonadmin"
	_ = h.store.RegisterDeviceWithToken(uid, "d", "host", tok)

	called := false
	wrapped := h.RequireAdmin(func(w http.ResponseWriter, r *http.Request) { called = true })
	req := httptest.NewRequest(http.MethodGet, "/admin/invites", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	wrapped(w, req)
	if w.Code != http.StatusForbidden || called {
		t.Fatalf("status=%d called=%v want 403/false", w.Code, called)
	}
}

func TestRequireAdmin_AllowsAdmin(t *testing.T) {
	h := newTestHandler(t)
	defer h.Close()
	uid := "u-admin"
	_ = h.store.CreateUser(uid)
	_ = h.store.SetUserAdmin(uid, true)
	tok := "tok-admin"
	_ = h.store.RegisterDeviceWithToken(uid, "d", "host", tok)

	called := false
	wrapped := h.RequireAdmin(func(w http.ResponseWriter, r *http.Request) { called = true })
	req := httptest.NewRequest(http.MethodGet, "/admin/invites", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	wrapped(w, req)
	if w.Code != http.StatusOK || !called {
		t.Fatalf("status=%d called=%v want 200/true", w.Code, called)
	}
}
```

- [ ] **Step 2: Run test (expect FAIL)**

```bash
cd relay && go test ./internal/relay -run TestRequireAdmin -v
```

- [ ] **Step 3: Implement**

Add next to `RequireAuth` in `handler.go`:

```go
// RequireAdmin wraps RequireAuth and additionally checks that the
// authenticated user has is_admin = TRUE. Returns 403 otherwise.
func (h *Handler) RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return h.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		uid := r.Header.Get("X-User-ID") // set by RequireAuth
		admin, err := h.store.IsUserAdmin(uid)
		if err != nil || !admin {
			writeError(w, http.StatusForbidden, "admin_required",
				"This endpoint requires an admin account.", "")
			return
		}
		next(w, r)
	})
}
```

- [ ] **Step 4: Run test (expect PASS)**

```bash
cd relay && go test ./internal/relay -run TestRequireAdmin -v
```

- [ ] **Step 5: Commit**

```bash
cd relay
git add internal/relay/handler.go internal/relay/admin_test.go
git commit -m "feat(relay): RequireAdmin middleware checks users.is_admin"
```

### Task 2.10: HTTP `/admin/*` handlers (invites + users)

**Files:** Create `relay/internal/relay/admin.go`; extend `relay/internal/relay/admin_test.go`; modify `handler.go` route registration.

- [ ] **Step 1: Write failing tests**

Extend `admin_test.go` with one happy-path test per endpoint (creation returns plaintext code; list redacts; revoke marks revoked; users list returns at least one row; user delete cascades). Use the admin-authed pattern from Task 2.9 to drive requests.

- [ ] **Step 2: Implement handlers**

`relay/internal/relay/admin.go`:

```go
package relay

import (
	"encoding/json"
	"net/http"
	"time"
)

type createInviteReq struct {
	Label          string `json:"label,omitempty"`
	MaxUses        int    `json:"max_uses,omitempty"`
	ExpiresInDays  int    `json:"expires_in_days,omitempty"`
}
type createInviteResp struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

// POST /admin/invites
func (h *Handler) AdminCreateInvite(w http.ResponseWriter, r *http.Request) {
	var req createInviteReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.MaxUses <= 0 {
		req.MaxUses = 1
	}
	if req.ExpiresInDays <= 0 {
		req.ExpiresInDays = 7
	}
	code, err := GenerateInviteCode()
	if err != nil {
		writeInternalError(w, "generate", "invite code generation", err)
		return
	}
	exp := time.Now().Add(time.Duration(req.ExpiresInDays) * 24 * time.Hour)
	creator := r.Header.Get("X-User-ID")
	if err := h.store.CreateInvite(HashInviteCode(code), &creator, req.Label, req.MaxUses, exp); err != nil {
		writeInternalError(w, "store", "insert invite", err)
		return
	}
	writeJSON(w, http.StatusOK, createInviteResp{Code: code, ExpiresAt: exp})
}

type listInviteRow struct {
	CodeHash  string     `json:"code_hash"`
	Label     string     `json:"label"`
	MaxUses   int        `json:"max_uses"`
	UsedCount int        `json:"used_count"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// GET /admin/invites
func (h *Handler) AdminListInvites(w http.ResponseWriter, r *http.Request) {
	list, err := h.store.ListInvites()
	if err != nil {
		writeInternalError(w, "list", "list invites", err)
		return
	}
	out := make([]listInviteRow, 0, len(list))
	for _, inv := range list {
		out = append(out, listInviteRow{
			CodeHash: inv.CodeHash, Label: inv.Label,
			MaxUses: inv.MaxUses, UsedCount: inv.UsedCount,
			CreatedAt: inv.CreatedAt, ExpiresAt: inv.ExpiresAt,
			RevokedAt: inv.RevokedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": out})
}

// DELETE /admin/invites/{hash}
func (h *Handler) AdminRevokeInvite(w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("hash")
	if err := h.store.RevokeInvite(hash); err != nil {
		writeInternalError(w, "revoke", "revoke invite", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type adminUserRow struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"display_name"`
	IsAdmin     bool      `json:"is_admin"`
	CreatedAt   time.Time `json:"created_at"`
}

// GET /admin/users
func (h *Handler) AdminListUsers(w http.ResponseWriter, r *http.Request) {
	list, err := h.store.ListUsers()
	if err != nil {
		writeInternalError(w, "list", "list users", err)
		return
	}
	out := make([]adminUserRow, 0, len(list))
	for _, u := range list {
		out = append(out, adminUserRow{
			ID: u.ID, DisplayName: u.DisplayName,
			IsAdmin: u.IsAdmin, CreatedAt: u.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

// DELETE /admin/users/{id}
func (h *Handler) AdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("id")
	if uid == r.Header.Get("X-User-ID") {
		writeError(w, http.StatusBadRequest, "self_delete",
			"Refusing to delete your own admin account.", "Promote another user first.")
		return
	}
	if err := h.store.DeleteUser(uid); err != nil {
		writeInternalError(w, "delete", "delete user", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
```

- [ ] **Step 3: Register routes**

In `RegisterRoutes` (handler.go ~line 1769+) add (use `h.RequireAdmin` wrapping):

```go
mux.HandleFunc("POST /admin/invites",          h.RequireAdmin(h.AdminCreateInvite))
mux.HandleFunc("GET /admin/invites",           h.RequireAdmin(h.AdminListInvites))
mux.HandleFunc("DELETE /admin/invites/{hash}", h.RequireAdmin(h.AdminRevokeInvite))
mux.HandleFunc("GET /admin/users",             h.RequireAdmin(h.AdminListUsers))
mux.HandleFunc("DELETE /admin/users/{id}",     h.RequireAdmin(h.AdminDeleteUser))
```

- [ ] **Step 4: Run tests (expect PASS)**

```bash
cd relay && go test ./internal/relay -run 'TestAdmin' -v
```

- [ ] **Step 5: Commit**

```bash
cd relay
git add internal/relay/admin.go internal/relay/admin_test.go internal/relay/handler.go
git commit -m "feat(relay): HTTP /admin/* endpoints for invites and users"
```

### Task 2.11: `relay` binary subcommands — `invite create|list|revoke`, `user list|remove`

**Files:** Modify `relay/cmd/relay/main.go`; create `relay/cmd/relay/admin_cli.go`.

- [ ] **Step 1: Refactor `main()` to detect subcommand**

Wrap existing `main()` body in a `runServer()` function. New `main()`:

```go
func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "invite":
			runInviteCLI(os.Args[2:])
			return
		case "user":
			runUserCLI(os.Args[2:])
			return
		}
	}
	runServer()
}
```

Existing flag parsing moves into `runServer()`. (`--port` / `-p` still work because `runServer` parses its own args via `flag.NewFlagSet`.)

- [ ] **Step 2: Implement subcommand wrappers**

`relay/cmd/relay/admin_cli.go`:

```go
package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	relay "github.com/cinchcli/relay/internal/relay"
)

func mustStore() *relay.Store {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "DATABASE_URL is required")
		os.Exit(1)
	}
	s, err := relay.NewStore(dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open db: %v\n", err)
		os.Exit(1)
	}
	return s
}

func runInviteCLI(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: relay invite create|list|revoke")
		os.Exit(2)
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("invite create", flag.ExitOnError)
		label := fs.String("label", "", "optional admin-side label")
		uses := fs.Int("uses", 1, "max uses")
		days := fs.Int("expires-days", 7, "expiry in days")
		_ = fs.Parse(args[1:])
		s := mustStore()
		defer s.Close()
		code, err := relay.GenerateInviteCode()
		if err != nil {
			fatal(err)
		}
		exp := time.Now().Add(time.Duration(*days) * 24 * time.Hour)
		if err := s.CreateInvite(relay.HashInviteCode(code), nil, *label, *uses, exp); err != nil {
			fatal(err)
		}
		fmt.Println(code)
		fmt.Fprintf(os.Stderr, "expires %s · %d use(s)\n", exp.Format(time.RFC3339), *uses)
	case "list":
		s := mustStore()
		defer s.Close()
		list, err := s.ListInvites()
		if err != nil {
			fatal(err)
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "HASH\tLABEL\tUSES\tEXPIRES\tREVOKED")
		for _, inv := range list {
			revoked := ""
			if inv.RevokedAt != nil {
				revoked = inv.RevokedAt.Format(time.RFC3339)
			}
			fmt.Fprintf(tw, "%s\t%s\t%d/%d\t%s\t%s\n",
				inv.CodeHash[:12], inv.Label, inv.UsedCount, inv.MaxUses,
				inv.ExpiresAt.Format(time.RFC3339), revoked)
		}
		tw.Flush()
	case "revoke":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: relay invite revoke <hash>")
			os.Exit(2)
		}
		s := mustStore()
		defer s.Close()
		if err := s.RevokeInvite(args[1]); err != nil {
			fatal(err)
		}
		fmt.Println("ok")
	default:
		fmt.Fprintf(os.Stderr, "unknown invite subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

func runUserCLI(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: relay user list|remove")
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		s := mustStore()
		defer s.Close()
		list, err := s.ListUsers()
		if err != nil {
			fatal(err)
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tADMIN\tCREATED")
		for _, u := range list {
			fmt.Fprintf(tw, "%s\t%s\t%v\t%s\n",
				u.ID, u.DisplayName, u.IsAdmin, u.CreatedAt.Format(time.RFC3339))
		}
		tw.Flush()
	case "remove":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: relay user remove <id>")
			os.Exit(2)
		}
		s := mustStore()
		defer s.Close()
		if err := s.DeleteUser(args[1]); err != nil {
			fatal(err)
		}
		fmt.Println("ok")
	default:
		fmt.Fprintf(os.Stderr, "unknown user subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
```

- [ ] **Step 3: Build + smoke test**

```bash
cd relay && make build
DATABASE_URL=$LOCAL_DSN ./dist/relay invite create --label test
DATABASE_URL=$LOCAL_DSN ./dist/relay invite list
DATABASE_URL=$LOCAL_DSN ./dist/relay user list
```
Expected: each command prints expected output; `invite create` outputs a fresh `cinch_inv_…` code.

- [ ] **Step 4: Commit**

```bash
cd relay
git add cmd/relay/main.go cmd/relay/admin_cli.go
git commit -m "feat(relay): relay invite|user subcommands on the binary"
```

### Task 2.12: Wire-vector sync from cinch-core into relay testdata

**Files:** Copy `cinch-core/testdata/wire-vectors.json` → `relay/internal/wire_test/testdata/wire-vectors.json` (already done as part of Task 1.2 Step 3 if executed locally; this task ensures it's committed in the relay repo).

- [ ] **Step 1: Confirm file copy**

```bash
diff cinch-core/testdata/wire-vectors.json relay/internal/wire_test/testdata/wire-vectors.json
```
Expected: no diff.

- [ ] **Step 2: Run round-trip**

```bash
cd relay && go test ./internal/wire_test/...
```
Expected: PASS.

- [ ] **Step 3: Commit (in relay repo)**

```bash
cd relay
git add internal/wire_test/testdata/wire-vectors.json
git commit -m "test(relay): wire-vector for LoginRequest with invite + display_name"
```

### Task 2.13: Bump `cinch-core` dependency in relay

**Files:** Modify `relay/go.mod` (and `go.sum` regenerated).

- [ ] **Step 1: Run update**

```bash
cd relay && make update-cinch-core REV=v0.1.5
```

- [ ] **Step 2: Verify build + tests**

```bash
cd relay && make build && make test
```
Expected: all pass.

- [ ] **Step 3: Commit**

```bash
cd relay
git add go.mod go.sum
git commit -m "chore(relay): bump cinch-core to v0.1.5"
```

---

## Phase 3 — cinch CLI: `cinch admin ...` subcommands

### Task 3.1: Add `Admin` to top-level clap enum

**Files:** Modify `cinch/crates/cli/src/main.rs`; create `cinch/crates/cli/src/commands/admin.rs`; modify `cinch/crates/cli/src/commands/mod.rs`.

- [ ] **Step 1: Module wiring**

In `cinch/crates/cli/src/commands/mod.rs`, add:
```rust
pub mod admin;
```

In `cinch/crates/cli/src/main.rs`, locate the top-level `Commands` enum (likely `enum Cli { … }` or a `Subcommand`-derived enum). Add:
```rust
/// Self-host admin operations (requires admin account on the relay).
Admin(commands::admin::AdminCmd),
```
and a dispatch arm:
```rust
Commands::Admin(cmd) => commands::admin::run(cmd).await?,
```

- [ ] **Step 2: Define `AdminCmd` and subcommands**

`cinch/crates/cli/src/commands/admin.rs`:

```rust
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use client_core::{config, credstore, http};

#[derive(Args, Debug)]
pub struct AdminCmd {
    #[command(subcommand)]
    pub sub: AdminSub,
}

#[derive(Subcommand, Debug)]
pub enum AdminSub {
    /// Manage invite codes.
    #[command(subcommand)]
    Invite(InviteSub),
    /// Manage user accounts.
    #[command(subcommand)]
    User(UserSub),
}

#[derive(Subcommand, Debug)]
pub enum InviteSub {
    Create {
        #[arg(long)]
        label: Option<String>,
        #[arg(long, default_value_t = 1)]
        uses: u32,
        #[arg(long = "expires-days", default_value_t = 7)]
        expires_days: u32,
    },
    List,
    Revoke { hash: String },
}

#[derive(Subcommand, Debug)]
pub enum UserSub {
    List,
    Remove { id: String },
}

pub async fn run(cmd: AdminCmd) -> Result<()> {
    let creds = credstore::load().context("no credentials — run `cinch auth login` first")?;
    let base = config::resolve_relay_url(&creds)?;
    let client = http::client_with_bearer(&creds.token)?;

    match cmd.sub {
        AdminSub::Invite(InviteSub::Create { label, uses, expires_days }) => {
            #[derive(Serialize)] struct Req<'a> {
                label: Option<&'a str>, max_uses: u32, expires_in_days: u32,
            }
            #[derive(Deserialize)] struct Resp { code: String, expires_at: String }
            let resp: Resp = client.post(format!("{base}/admin/invites"))
                .json(&Req { label: label.as_deref(), max_uses: uses, expires_in_days: expires_days })
                .send().await?.error_for_status()?.json().await?;
            println!("{}", resp.code);
            eprintln!("expires {} · {} use(s)", resp.expires_at, uses);
        }
        AdminSub::Invite(InviteSub::List) => {
            #[derive(Deserialize)] struct Wrap { invites: Vec<Inv> }
            #[derive(Deserialize)] struct Inv {
                code_hash: String, label: String,
                max_uses: u32, used_count: u32,
                expires_at: String, revoked_at: Option<String>,
            }
            let r: Wrap = client.get(format!("{base}/admin/invites"))
                .send().await?.error_for_status()?.json().await?;
            for i in r.invites {
                let revoked = i.revoked_at.unwrap_or_default();
                println!("{:12}  {:20}  {}/{}  {}  {}",
                    &i.code_hash[..12], i.label, i.used_count, i.max_uses, i.expires_at, revoked);
            }
        }
        AdminSub::Invite(InviteSub::Revoke { hash }) => {
            client.delete(format!("{base}/admin/invites/{hash}"))
                .send().await?.error_for_status()?;
            println!("ok");
        }
        AdminSub::User(UserSub::List) => {
            #[derive(Deserialize)] struct Wrap { users: Vec<U> }
            #[derive(Deserialize)] struct U {
                id: String, display_name: String, is_admin: bool, created_at: String,
            }
            let r: Wrap = client.get(format!("{base}/admin/users"))
                .send().await?.error_for_status()?.json().await?;
            for u in r.users {
                println!("{:26}  {:20}  {}  {}", u.id, u.display_name, u.is_admin, u.created_at);
            }
        }
        AdminSub::User(UserSub::Remove { id }) => {
            client.delete(format!("{base}/admin/users/{id}"))
                .send().await?.error_for_status()?;
            println!("ok");
        }
    }
    Ok(())
}
```

(Adjust import names to match the actual `client_core` re-exports — `http::client_with_bearer` / `credstore::load` may be named differently. Match the pattern used in `cinch/crates/cli/src/commands/devices.rs`, which already loads credentials and calls authenticated HTTP endpoints.)

- [ ] **Step 3: Build**

```bash
cd cinch && cargo build -p cinch-cli
```
Expected: clean build.

- [ ] **Step 4: Manual smoke**

```bash
# Pre-req: relay running locally with admin user already signed in via `cinch auth login`.
cd cinch && cargo run -p cinch-cli -- admin invite create --label demo
cd cinch && cargo run -p cinch-cli -- admin invite list
cd cinch && cargo run -p cinch-cli -- admin user list
```
Expected: invite code printed; list shows it; user list shows your own account with `is_admin = true`.

- [ ] **Step 5: Commit**

```bash
cd cinch
git add crates/cli/src/main.rs crates/cli/src/commands/mod.rs crates/cli/src/commands/admin.rs
git commit -m "feat(cli): cinch admin invite|user subcommands"
```

### Task 3.2: Bump `client-core` dep in cinch CLI

**Files:** Modify `cinch/crates/cli/Cargo.toml`.

- [ ] **Step 1: Bump**

```toml
client-core = { package = "cinchcli-core", version = "0.1.5" }
```

- [ ] **Step 2: Build + run existing tests**

```bash
cd cinch && cargo build -p cinch-cli && cargo test --workspace
```

- [ ] **Step 3: Commit**

```bash
cd cinch
git add crates/cli/Cargo.toml Cargo.lock
git commit -m "chore(cli): bump cinchcli-core to 0.1.5"
```

---

## Open Decisions To Surface During Implementation

These are minor enough that they can be resolved in the PR review of each phase, but flagging now:

1. **`AuthLogin` rate limit and invite — order of operations.** Currently rate limit runs before invite check, so a valid-invite request hits the limiter. Should valid invites bypass the limiter? Default: **no** (rate limit is per-IP; invites are per-code; keep them composed).
2. **Should `/admin/users` show device count / last activity?** Useful for "is this account active" decisions. Default: **omit in v1**; add when an operator asks.
3. **Demoting yourself.** `AdminDeleteUser` blocks self-delete. Promote/demote endpoints aren't in this plan; add only if needed.
4. **Connect-RPC admin parity.** This plan adds HTTP `/admin/*` only. If desktop later wants admin features, mirror via Connect-RPC. Skipped here intentionally — `cinch admin` CLI is the only client.
5. **Bootstrap env var visibility.** Documented in `relay/DEPLOY.md` (add a short section as part of Task 2.7 if time permits; otherwise follow-up doc PR).

---

## Self-Review

**Spec coverage:**
- Invite-token gating → Tasks 2.1, 2.2, 2.3, 2.5, 2.6
- First user = admin → Task 2.5 Step 3 (CountUsers → SetUserAdmin)
- Label optional at create, display_name at redeem → Tasks 2.5, 2.8, 2.10, 2.11
- OAuth/invite mutex → Task 2.5 Step 3 (existing 403 preserved); route registration unchanged (handler.go:1773-1776)
- 7d / 1 use defaults → Tasks 2.10 (HTTP), 2.11 (CLI)
- Bootstrap via env var → Task 2.7
- Relay binary subcommands → Task 2.11
- HTTP `/admin/*` + `cinch admin` CLI → Tasks 2.9, 2.10, 3.1
- Browser HTML changes → Task 2.8
- Proto changes → Phase 1

**Placeholder scan:** Tasks 2.6 and 2.10 Step 1 use prose-only test specs ("write a test using pattern X") rather than full test code because the exact helper names depend on what's already in the repo (`connect_auth_test.go` / handler test helpers). This is intentional — the implementer needs to match existing conventions — but flag if you want me to verify those helpers and inline real test code.

**Type consistency:** `Invite` struct fields (`CodeHash`, `Label`, `MaxUses`, `UsedCount`, `ExpiresAt`, `RevokedAt`) used consistently across Store, HTTP handler (`listInviteRow`), and CLI deserialization (`Inv` struct in `admin.rs`). `UserRow` ↔ `adminUserRow` ↔ `U` likewise.
