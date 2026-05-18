# Internal Users Endpoint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `GET /internal/users` to relay so the biz Cloudflare Worker can pull a paginated, filterable view of users + device aggregates to render the SaaS admin dashboard — without putting any SaaS concepts into relay itself.

**Architecture:** Mirror the existing `POST /internal/quota` pattern in reverse: bearer-auth via `INTERNAL_SERVICE_SECRET` (disabled on self-hosters by default), `LEFT JOIN devices LEFT JOIN user_capabilities` with `GROUP BY user`, keyset pagination on `(created_at, user_id)`, optional `updated_since` and `include_demo` filters. The endpoint exposes only aggregates and capability echoes — never device tokens, hostnames, nicknames, machine ids, clip content, key material, or OAuth identity strings.

**Tech Stack:** Go, `net/http`, Postgres via `database/sql` (existing `*Store`), `encoding/json`, `encoding/base64`, `crypto/subtle`. No new dependencies.

---

## File Structure

- **CREATE** `relay/internal/relay/internal_users.go` — handler `ListInternalUsers`, request/response DTOs, cursor encode/decode helpers. Package `relay`.
- **CREATE** `relay/internal/relay/internal_users_test.go` — integration tests via `httptest` (external `package relay_test`, follows `relay_test.go` convention).
- **MODIFY** `relay/internal/relay/store.go` — append `ListInternalUserAggregates` method plus its input/output types. Internal to the `relay` package.
- **MODIFY** `relay/internal/relay/handler.go` — single line: register `GET /internal/users` next to the existing `/internal/quota` registration (around line 1889).

The handler file is kept separate from `handler.go` (which is already ~1900 lines) so future `/internal/*` endpoints have an obvious home, matching the existing `admin.go` / `oauth.go` / `invites.go` pattern.

---

## Wire Shape Reference (locked from spec)

Response body:

```json
{
  "users": [
    {
      "user_id": "01HXY...",
      "created_at": "2026-04-10T08:12:33Z",
      "is_demo": false,
      "device_count": 4,
      "active_device_count": 3,
      "last_active_at": "2026-05-17T22:01:09Z",
      "capabilities": {
        "device_limit": 10,
        "retention_days": 90,
        "rate_limit": 0,
        "grace_expires_at": null,
        "updated_at": "2026-05-01T00:00:00Z"
      }
    }
  ],
  "next_cursor": "eyJjcmVhdGVkX2F0IjoiMjAyNi0wNS0wMVQwMDowMDowMFoiLCJpZCI6IjAxSFhZIn0"
}
```

- `last_active_at`: nullable; omitted when the user has no `devices.last_push_at` populated.
- `capabilities`: nullable; `null` when no `user_capabilities` row exists.
- `grace_expires_at`: nullable inside `capabilities`.
- `next_cursor`: omitted when there are no more rows.

Cursor payload (base64-RawURL-encoded JSON):

```json
{"created_at": "2026-05-01T00:00:00Z", "id": "01HXY..."}
```

Query params:

| Param | Type | Default | Validation |
|---|---|---|---|
| `limit` | int | 100 | 1 ≤ n ≤ 1000, else 400 `invalid_limit` |
| `cursor` | string | — | decodable base64 + JSON with non-empty `id`, else 400 `invalid_cursor` |
| `updated_since` | RFC3339 | — | else 400 `invalid_updated_since` |
| `include_demo` | bool | `false` | `"true"` enables; any other value is treated as false |

---

### Task 1: Store types + basic aggregate query

**Files:**
- Modify: `relay/internal/relay/store.go` (append at end)
- Test: `relay/internal/relay/store_test.go` (append)

- [ ] **Step 1: Write the failing test**

Append to `relay/internal/relay/store_test.go`:

```go
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
	// Pair 3 devices, then revoke 1.
	if _, err := store.db.Exec(`
		INSERT INTO devices (id, user_id, hostname, source_key, last_push_at)
		VALUES ('d1','user-a','h1','sk1', NOW() - interval '1 hour'),
		       ('d2','user-a','h2','sk2', NOW() - interval '5 minutes'),
		       ('d3','user-a','h3','sk3', NULL)
	`); err != nil {
		t.Fatalf("seed devices: %v", err)
	}
	if _, err := store.db.Exec(`UPDATE devices SET revoked_at = NOW() WHERE id = 'd3'`); err != nil {
		t.Fatalf("revoke device: %v", err)
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
	if c == nil {
		t.Fatal("expected non-nil capabilities")
	}
	if c.DeviceLimit != 10 || c.RetentionDays != 90 {
		t.Fatalf("unexpected capabilities: %+v", c)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd relay && go test ./internal/relay/ -run TestListInternalUserAggregates -v`
Expected: FAIL with "undefined: InternalUsersFilter" / "store.ListInternalUserAggregates undefined".

- [ ] **Step 3: Implement types and method**

Append to `relay/internal/relay/store.go`:

```go
// InternalUsersFilter is the input to ListInternalUserAggregates.
// CursorCreatedAt/CursorUserID together form a keyset for pagination.
type InternalUsersFilter struct {
	Limit           int
	CursorCreatedAt *time.Time
	CursorUserID    string
	UpdatedSince    *time.Time
	IncludeDemo     bool
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

	rows, err := s.db.Query(q,
		f.IncludeDemo,
		f.CursorCreatedAt,
		f.CursorUserID,
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
```

Note: `EncodeInternalCursor` and `InternalCursorPayload` are defined in Task 2. Until then the build will fail on that reference — that is expected; Task 2 lands the helpers in the same package and the commit is deferred to the end of Task 2 so the tree never breaks.

- [ ] **Step 4: Run tests to verify they pass (after Task 2 lands)**

The query compiles on its own but `encodeInternalCursor` is undefined until Task 2. Park here and move to Task 2; do not commit until Task 2 also compiles. After Task 2:

Run: `cd relay && go test ./internal/relay/ -run TestListInternalUserAggregates -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit (deferred — bundled with Task 2)**

Commit happens at the end of Task 2 so the tree never breaks.

---

### Task 2: Cursor encode/decode helpers

**Files:**
- Create: `relay/internal/relay/internal_users.go`
- Test: `relay/internal/relay/internal_users_test.go`

- [ ] **Step 1: Write the failing test**

Create `relay/internal/relay/internal_users_test.go`:

```go
package relay_test

import (
	"strings"
	"testing"
	"time"

	relay "github.com/cinchcli/relay/internal/relay"
)

func TestInternalCursor_RoundTrip(t *testing.T) {
	in := relay.InternalCursorPayload{
		CreatedAt: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
		UserID:    "01HXYZ123",
	}
	s := relay.EncodeInternalCursor(in)
	if s == "" {
		t.Fatal("EncodeInternalCursor returned empty string")
	}
	if strings.ContainsAny(s, "+/=") {
		t.Fatalf("cursor should be base64-RawURL (no +/=), got %q", s)
	}
	out, err := relay.DecodeInternalCursor(s)
	if err != nil {
		t.Fatalf("DecodeInternalCursor: %v", err)
	}
	if !out.CreatedAt.Equal(in.CreatedAt) || out.UserID != in.UserID {
		t.Fatalf("round-trip mismatch: in=%+v out=%+v", in, out)
	}
}

func TestInternalCursor_RejectsGarbage(t *testing.T) {
	cases := []string{
		"!!!not-base64!!!",
		"e30",                  // valid base64 → "{}"; missing id field
		"eyJpZCI6IiJ9",         // valid base64 → '{"id":""}'; empty id
	}
	for _, s := range cases {
		if _, err := relay.DecodeInternalCursor(s); err == nil {
			t.Fatalf("expected error for cursor %q", s)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd relay && go test ./internal/relay/ -run TestInternalCursor -v`
Expected: FAIL with undefined `InternalCursorPayload`, `EncodeInternalCursor`, `DecodeInternalCursor`.

- [ ] **Step 3: Implement the helpers**

Create `relay/internal/relay/internal_users.go`:

```go
package relay

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// InternalCursorPayload is the decoded form of the opaque cursor used by
// GET /internal/users. Pagination is keyset on (created_at, user_id).
type InternalCursorPayload struct {
	CreatedAt time.Time `json:"created_at"`
	UserID    string    `json:"id"`
}

// EncodeInternalCursor serialises a cursor payload as base64-RawURL JSON.
// The result is opaque to callers; only the relay decodes it.
func EncodeInternalCursor(c InternalCursorPayload) string {
	b, err := json.Marshal(c)
	if err != nil {
		// json.Marshal of a fixed struct with time.Time + string cannot fail
		// in practice; encode a safe empty token on the off chance.
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeInternalCursor parses a cursor produced by EncodeInternalCursor.
// Returns an error if the string is not base64-RawURL, not valid JSON, or
// is missing the required id field.
func DecodeInternalCursor(s string) (InternalCursorPayload, error) {
	var out InternalCursorPayload
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("cursor base64: %w", err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return out, fmt.Errorf("cursor json: %w", err)
	}
	if out.UserID == "" {
		return out, fmt.Errorf("cursor missing id")
	}
	return out, nil
}
```

Update the import block in `internal_users.go` to add `"time"`:

```go
import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)
```

- [ ] **Step 4: Run all tests up to this point**

Run: `cd relay && go test ./internal/relay/ -run "TestInternalCursor|TestListInternalUserAggregates" -v`
Expected: PASS (5 tests — 3 from Task 1 + 2 from Task 2).

- [ ] **Step 5: Commit Task 1 + Task 2 together**

```bash
cd relay
git add internal/relay/store.go internal/relay/store_test.go internal/relay/internal_users.go internal/relay/internal_users_test.go
git commit -m "feat(relay): add ListInternalUserAggregates store method + cursor helpers"
```

---

### Task 3: Store filter — updated_since

**Files:**
- Modify: `relay/internal/relay/store_test.go` (append)

The query already implements the filter (Task 1); this task adds a regression test so the behaviour is locked in before the HTTP layer depends on it.

- [ ] **Step 1: Write the failing test**

Append to `relay/internal/relay/store_test.go`:

```go
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
```

- [ ] **Step 2: Run to verify they pass**

Run: `cd relay && go test ./internal/relay/ -run TestListInternalUserAggregates_UpdatedSince -v`
Expected: PASS (2 tests). The store implementation already supports this; the tests lock it down.

- [ ] **Step 3: If a test fails, fix the SQL HAVING clause**

If `TestListInternalUserAggregates_UpdatedSinceCatchesDeviceActivity` fails, re-check that `HAVING ... OR MAX(d.paired_at) > $4 OR MAX(d.revoked_at) > $4 OR MAX(d.last_push_at) > $4` is present in `store.go`. The 30-day-old user must surface because a device pushed recently.

- [ ] **Step 4: Commit**

```bash
cd relay
git add internal/relay/store_test.go
git commit -m "test(relay): lock down updated_since filter on internal users query"
```

---

### Task 4: Store filter — include_demo + pagination

**Files:**
- Modify: `relay/internal/relay/store_test.go` (append)

- [ ] **Step 1: Write the failing tests**

Append to `relay/internal/relay/store_test.go`:

```go
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
		Limit:           2,
		CursorCreatedAt: &cur.CreatedAt,
		CursorUserID:    cur.UserID,
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
		Limit:           2,
		CursorCreatedAt: &cur2.CreatedAt,
		CursorUserID:    cur2.UserID,
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
```

Note the new `fmt` import in `store_test.go` if not already present.

- [ ] **Step 2: Run tests**

Run: `cd relay && go test ./internal/relay/ -run "TestListInternalUserAggregates_ExcludesDemo|TestListInternalUserAggregates_Paginates" -v`
Expected: PASS (2 tests). Implementation supports both already.

- [ ] **Step 3: Commit**

```bash
cd relay
git add internal/relay/store_test.go
git commit -m "test(relay): lock down include_demo + cursor pagination on internal users query"
```

---

### Task 5: HTTP handler — auth gating + skeleton

**Files:**
- Modify: `relay/internal/relay/internal_users.go` (append handler)
- Modify: `relay/internal/relay/handler.go` (register route, line ~1889)
- Modify: `relay/internal/relay/internal_users_test.go` (append)

- [ ] **Step 1: Write the failing tests**

Append to `relay/internal/relay/internal_users_test.go`:

```go
import (
	"encoding/json"
	"io"
	"net/http"
)

func TestInternalUsers_UnavailableWhenNoSecret(t *testing.T) {
	ts, _ := setupTestServer(t) // no secret configured

	req, _ := http.NewRequest("GET", ts.URL+"/internal/users", nil)
	req.Header.Set("Authorization", "Bearer anything")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
}

func TestInternalUsers_RejectsWrongSecret(t *testing.T) {
	ts, _ := setupTestServerWithSecret(t, "correct-secret")

	req, _ := http.NewRequest("GET", ts.URL+"/internal/users", nil)
	req.Header.Set("Authorization", "Bearer wrong-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestInternalUsers_HappyPathEmpty(t *testing.T) {
	ts, _ := setupTestServerWithSecret(t, "test-secret")

	req, _ := http.NewRequest("GET", ts.URL+"/internal/users", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var got struct {
		Users      []map[string]any `json:"users"`
		NextCursor string           `json:"next_cursor"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Users) != 0 {
		t.Fatalf("expected empty users on fresh store, got %d", len(got.Users))
	}
	if got.NextCursor != "" {
		t.Fatalf("expected empty cursor, got %q", got.NextCursor)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd relay && go test ./internal/relay/ -run TestInternalUsers -v`
Expected: FAIL with 404 (route not registered).

- [ ] **Step 3: Implement the handler**

Append to `relay/internal/relay/internal_users.go`:

```go
// Add to imports:
//   "crypto/subtle"
//   "net/http"
//   "strconv"
//   "strings"

type internalUsersListResponseUser struct {
	UserID            string                              `json:"user_id"`
	CreatedAt         time.Time                           `json:"created_at"`
	IsDemo            bool                                `json:"is_demo"`
	DeviceCount       int                                 `json:"device_count"`
	ActiveDeviceCount int                                 `json:"active_device_count"`
	LastActiveAt      *time.Time                          `json:"last_active_at,omitempty"`
	Capabilities      *internalUsersListResponseCapsBlock `json:"capabilities"`
}

type internalUsersListResponseCapsBlock struct {
	DeviceLimit    int        `json:"device_limit"`
	RetentionDays  int        `json:"retention_days"`
	RateLimit      int        `json:"rate_limit"`
	GraceExpiresAt *time.Time `json:"grace_expires_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type internalUsersListResponse struct {
	Users      []internalUsersListResponseUser `json:"users"`
	NextCursor string                          `json:"next_cursor,omitempty"`
}

// ListInternalUsers handles GET /internal/users.
// Returns paginated user rows with device aggregates and capability echoes
// so the biz Cloudflare Worker can render the SaaS admin dashboard.
// Protected by INTERNAL_SERVICE_SECRET bearer (same secret as POST /internal/quota).
// Returns 503 when the secret is unset so self-hosters get the endpoint disabled
// by default.
func (h *Handler) ListInternalUsers(w http.ResponseWriter, r *http.Request) {
	if h.internalServiceSecret == "" {
		writeError(w, http.StatusServiceUnavailable, "not_configured",
			"Internal users endpoint is not configured on this relay", "")
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(token), []byte(h.internalServiceSecret)) != 1 {
		writeError(w, http.StatusForbidden, "forbidden", "Invalid service secret", "")
		return
	}

	f := InternalUsersFilter{Limit: 100}
	q := r.URL.Query()

	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			writeError(w, http.StatusBadRequest, "invalid_limit", "limit must be an integer between 1 and 1000", "")
			return
		}
		f.Limit = n
	}
	if v := q.Get("cursor"); v != "" {
		c, err := DecodeInternalCursor(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_cursor", "Cursor could not be decoded", "")
			return
		}
		f.CursorCreatedAt = &c.CreatedAt
		f.CursorUserID = c.UserID
	}
	if v := q.Get("updated_since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_updated_since", "updated_since must be RFC 3339", "")
			return
		}
		f.UpdatedSince = &t
	}
	f.IncludeDemo = q.Get("include_demo") == "true"

	page, err := h.store.ListInternalUserAggregates(f)
	if err != nil {
		writeInternalError(w, "query", "list internal users", err)
		return
	}

	resp := internalUsersListResponse{
		Users:      make([]internalUsersListResponseUser, 0, len(page.Rows)),
		NextCursor: page.NextCursor,
	}
	for _, row := range page.Rows {
		u := internalUsersListResponseUser{
			UserID:            row.UserID,
			CreatedAt:         row.CreatedAt,
			IsDemo:            row.IsDemo,
			DeviceCount:       row.DeviceCount,
			ActiveDeviceCount: row.ActiveDeviceCount,
			LastActiveAt:      row.LastActiveAt,
		}
		if row.Capabilities != nil {
			u.Capabilities = &internalUsersListResponseCapsBlock{
				DeviceLimit:    row.Capabilities.DeviceLimit,
				RetentionDays:  row.Capabilities.RetentionDays,
				RateLimit:      row.Capabilities.RateLimit,
				GraceExpiresAt: row.Capabilities.GraceExpiresAt,
				UpdatedAt:      row.Capabilities.UpdatedAt,
			}
		}
		resp.Users = append(resp.Users, u)
	}
	writeJSON(w, http.StatusOK, resp)
}
```

Update the import block in `internal_users.go`:

```go
import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)
```

- [ ] **Step 4: Register the route**

Modify `relay/internal/relay/handler.go`. Find:

```go
mux.HandleFunc("POST /internal/quota", h.UpdateUserQuota)
```

Add immediately below:

```go
mux.HandleFunc("GET /internal/users", h.ListInternalUsers)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd relay && go test ./internal/relay/ -run TestInternalUsers -v`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
cd relay
git add internal/relay/internal_users.go internal/relay/internal_users_test.go internal/relay/handler.go
git commit -m "feat(relay): add GET /internal/users handler with auth gating"
```

---

### Task 6: HTTP handler — end-to-end with users, filters, and pagination

**Files:**
- Modify: `relay/internal/relay/internal_users_test.go` (append)

- [ ] **Step 1: Write the failing tests**

Append to `relay/internal/relay/internal_users_test.go`:

```go
func TestInternalUsers_ReturnsAggregates(t *testing.T) {
	ts, store := setupTestServerWithSecret(t, "test-secret")

	if err := store.CreateUser("alice"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := store.UpsertUserCapabilities(relay.UserCapabilities{
		UserID: "alice", DeviceLimit: 10, RetentionDays: 90, RateLimit: 0,
	}); err != nil {
		t.Fatalf("UpsertUserCapabilities: %v", err)
	}

	req, _ := http.NewRequest("GET", ts.URL+"/internal/users", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	var got struct {
		Users []struct {
			UserID       string `json:"user_id"`
			DeviceCount  int    `json:"device_count"`
			Capabilities *struct {
				DeviceLimit int `json:"device_limit"`
			} `json:"capabilities"`
		} `json:"users"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Users) != 1 || got.Users[0].UserID != "alice" {
		t.Fatalf("expected alice, got %+v", got.Users)
	}
	if got.Users[0].Capabilities == nil || got.Users[0].Capabilities.DeviceLimit != 10 {
		t.Fatalf("expected device_limit=10, got %+v", got.Users[0].Capabilities)
	}
}

func TestInternalUsers_RejectsBadLimit(t *testing.T) {
	ts, _ := setupTestServerWithSecret(t, "test-secret")

	cases := []string{"0", "-1", "1001", "notanumber"}
	for _, v := range cases {
		req, _ := http.NewRequest("GET", ts.URL+"/internal/users?limit="+v, nil)
		req.Header.Set("Authorization", "Bearer test-secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("limit=%s: %v", v, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("limit=%s: expected 400, got %d", v, resp.StatusCode)
		}
	}
}

func TestInternalUsers_RejectsBadCursor(t *testing.T) {
	ts, _ := setupTestServerWithSecret(t, "test-secret")

	req, _ := http.NewRequest("GET", ts.URL+"/internal/users?cursor=!!!garbage!!!", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad cursor, got %d", resp.StatusCode)
	}
}

func TestInternalUsers_RejectsBadUpdatedSince(t *testing.T) {
	ts, _ := setupTestServerWithSecret(t, "test-secret")

	req, _ := http.NewRequest("GET", ts.URL+"/internal/users?updated_since=not-a-date", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad updated_since, got %d", resp.StatusCode)
	}
}

func TestInternalUsers_PaginatesEndToEnd(t *testing.T) {
	ts, store := setupTestServerWithSecret(t, "test-secret")

	for i := 0; i < 3; i++ {
		uid := fmt.Sprintf("user-%d", i)
		if err := store.CreateUser(uid); err != nil {
			t.Fatalf("CreateUser %s: %v", uid, err)
		}
	}

	req, _ := http.NewRequest("GET", ts.URL+"/internal/users?limit=2", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("page 1 request: %v", err)
	}
	defer resp.Body.Close()

	var p1 struct {
		Users      []map[string]any `json:"users"`
		NextCursor string           `json:"next_cursor"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&p1); err != nil {
		t.Fatalf("decode page 1: %v", err)
	}
	if len(p1.Users) != 2 {
		t.Fatalf("page 1 expected 2 users, got %d", len(p1.Users))
	}
	if p1.NextCursor == "" {
		t.Fatal("page 1 should have a next_cursor")
	}

	req2, _ := http.NewRequest("GET", ts.URL+"/internal/users?limit=2&cursor="+p1.NextCursor, nil)
	req2.Header.Set("Authorization", "Bearer test-secret")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("page 2 request: %v", err)
	}
	defer resp2.Body.Close()

	var p2 struct {
		Users      []map[string]any `json:"users"`
		NextCursor string           `json:"next_cursor"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&p2); err != nil {
		t.Fatalf("decode page 2: %v", err)
	}
	if len(p2.Users) != 1 {
		t.Fatalf("page 2 expected 1 user, got %d", len(p2.Users))
	}
	if p2.NextCursor != "" {
		t.Fatalf("page 2 should not have a next_cursor, got %q", p2.NextCursor)
	}
}
```

Add `"fmt"` to the imports at the top of `internal_users_test.go` if not already present.

- [ ] **Step 2: Run tests**

Run: `cd relay && go test ./internal/relay/ -run TestInternalUsers -v`
Expected: PASS (8 tests total — 3 from Task 5 + 5 from this task).

- [ ] **Step 3: Run the full relay test suite**

Run: `cd relay && make test`
Expected: PASS, no regressions.

- [ ] **Step 4: Verify query plan on a populated DB (optional but recommended)**

Spin up the local Postgres compose file and run:

```bash
cd relay
docker compose up -d db
# … seed a handful of users + devices via test fixtures or by hand …
psql "$DATABASE_URL" -c "EXPLAIN ANALYZE SELECT u.id, u.created_at, u.is_demo, COUNT(d.id), COUNT(d.id) FILTER (WHERE d.revoked_at IS NULL), MAX(d.last_push_at), c.device_limit, c.retention_days, c.rate_limit, c.grace_expires_at, c.updated_at FROM users u LEFT JOIN devices d ON d.user_id = u.id LEFT JOIN user_capabilities c ON c.user_id = u.id WHERE NOT u.is_demo GROUP BY u.id, c.device_limit, c.retention_days, c.rate_limit, c.grace_expires_at, c.updated_at ORDER BY u.created_at, u.id LIMIT 101;"
```

Expected: index scan on `users.created_at`, hash/merge join on `devices.user_id` (existing `idx_devices_user_source` covers it). If a sequential scan on `devices` shows up under realistic data sizes, add an explicit `CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);` migration in `store.go` — but only if measured, not preemptively.

- [ ] **Step 5: Commit**

```bash
cd relay
git add internal/relay/internal_users_test.go
git commit -m "test(relay): end-to-end coverage for GET /internal/users (aggregates, validation, pagination)"
```

---

### Task 7: Documentation

**Files:**
- Modify: `relay/docs/INFRA.md` (or wherever the existing `/internal/quota` is documented — search first)
- Modify: `relay/CLAUDE.md` (one-liner under the route list, if such a list exists)

- [ ] **Step 1: Locate existing `/internal/quota` documentation**

Run: `cd relay && grep -rn "/internal/quota" docs/ CLAUDE.md README.md 2>/dev/null`

Wherever the quota endpoint is described, the users endpoint goes immediately next to it (so future readers see the symmetry).

- [ ] **Step 2: Add a short doc block**

In the same place as the quota docs, add:

```markdown
### `GET /internal/users`

Read-only counterpart to `POST /internal/quota`. Returns paginated user
rows with device aggregates so the SaaS billing layer can render its
admin dashboard. Disabled by default — enable by setting
`INTERNAL_SERVICE_SECRET`. Self-hosters should use `GET /admin/users`
instead.

Query params: `limit` (1–1000, default 100), `cursor` (opaque, from a
prior response), `updated_since` (RFC 3339), `include_demo` (default
false).

Response shape: `{users: [...], next_cursor?: string}`. Each user row
includes only `user_id`, `created_at`, `is_demo`, `device_count`,
`active_device_count`, `last_active_at`, and a nullable `capabilities`
block. Device tokens, hostnames, nicknames, machine IDs, clip metadata,
key material, and OAuth identity strings are **never** returned by this
endpoint. If biz needs per-device drill-down, add a separate scoped
endpoint — don't widen this one.
```

- [ ] **Step 3: Commit**

```bash
cd relay
git add docs/ CLAUDE.md 2>/dev/null
git commit -m "docs(relay): document GET /internal/users next to /internal/quota"
```

---

## Self-Review Checklist (run before handing off)

- [ ] **Spec coverage:** every field in the response sample maps to a struct field and is tested. `last_active_at` nullable + capabilities nullable both have direct assertions. ✓
- [ ] **No PII leakage:** struct fields enumerated explicitly. `hostname`, `nickname`, `machine_id`, `token`, `public_key`, `encrypted_key_bundle`, `display_name`, `identity_provider`, `identity_subject` do not appear in any handler struct. ✓
- [ ] **Self-host disabled by default:** verified by `TestInternalUsers_UnavailableWhenNoSecret`. ✓
- [ ] **Auth mirror:** same `INTERNAL_SERVICE_SECRET`, same `subtle.ConstantTimeCompare`, same 503/403 pattern as `/internal/quota`. ✓
- [ ] **Pagination correctness:** n+1 fetch, cursor encodes (created_at, id), keyset compares with strict `>` then tuple, last page emits no cursor — covered by `TestListInternalUserAggregates_PaginatesByCursor` and `TestInternalUsers_PaginatesEndToEnd`. ✓
- [ ] **Filter semantics:** `updated_since` covers user/capabilities/device-activity surfaces — both store + handler tests pin this. ✓
- [ ] **No placeholders:** every code block is complete and copy-pasteable. ✓
- [ ] **Type consistency:** `InternalUsersFilter`, `InternalUserAggregate`, `InternalUserCapabilities`, `InternalUsersPage`, `InternalCursorPayload` — names match across Task 1, Task 2, and Task 5. ✓
