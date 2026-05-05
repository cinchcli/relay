# Relay Quota Enforcement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add plan-aware quota enforcement to the relay: device limits, daily rate limits, and capabilities-driven retention sweep — all injected by an external Cloud API via `POST /internal/quota`.

**Architecture:** Cloud API writes numeric limits to the relay's `user_capabilities` table via a single authenticated internal endpoint. The relay reads capabilities from its local DB on every hot-path request — no external call, no added latency. Self-hosters have no row in `user_capabilities` and get unlimited access by default.

**Tech Stack:** Go, SQLite (`modernc.org/sqlite`), standard `net/http`, `database/sql`

**Spec:** `relay/docs/superpowers/specs/2026-05-05-relay-quota-enforcement-design.md`

---

## File Map

| File | Change |
|---|---|
| `relay/internal/relay/store.go` | Add tables to `migrate()`, add `UserCapabilities` struct + 4 new Store methods |
| `relay/internal/relay/handler.go` | Add `internalServiceSecret` field + `UpdateUserQuota` handler + device limit check in `AuthLogin` + rate limit check in `PushClip` + register route |
| `relay/internal/relay/connect_clips.go` | Rate limit check in `connectClipsServer.PushClip` |
| `relay/cmd/relay/main.go` | Read `INTERNAL_SERVICE_SECRET` env var, set on handler, add `SweepOldRequestCounts` to retention sweep |
| `relay/internal/relay/relay_test.go` | New test functions for all enforcement scenarios |

---

## Task 1: Schema migration + Store data layer

**Files:**
- Modify: `relay/internal/relay/store.go:47-111` (add tables to `migrate()`)
- Modify: `relay/internal/relay/store.go:19-26` (add `UserCapabilities` struct near `Tombstone`)

- [ ] **Step 1: Write the failing test**

Add to `relay/internal/relay/relay_test.go` (after the existing `TestDeleteClip` function):

```go
func TestUserCapabilities_DefaultUnlimited(t *testing.T) {
	ts, _ := setupTestServer(t)
	token, _, userID := login(t, ts.URL)
	_ = token

	// A brand-new user has no capabilities row — should return zero struct (unlimited).
	store, err := relay.NewStore(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer store.Close()
	if err := store.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	cap, err := store.GetUserCapabilities(userID)
	if err != nil {
		t.Fatalf("GetUserCapabilities: %v", err)
	}
	if cap.DeviceLimit != 0 || cap.RetentionDays != 0 || cap.RateLimit != 0 {
		t.Fatalf("expected all-zero capabilities for user without row, got %+v", cap)
	}
}

func TestUserCapabilities_UpsertAndRead(t *testing.T) {
	store, err := relay.NewStore(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer store.Close()
	userID := "test-user-cap"
	if err := store.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	want := relay.UserCapabilities{
		UserID:        userID,
		DeviceLimit:   3,
		RetentionDays: 7,
		RateLimit:     100,
	}
	if err := store.UpsertUserCapabilities(want); err != nil {
		t.Fatalf("UpsertUserCapabilities: %v", err)
	}

	got, err := store.GetUserCapabilities(userID)
	if err != nil {
		t.Fatalf("GetUserCapabilities: %v", err)
	}
	if got.DeviceLimit != 3 || got.RetentionDays != 7 || got.RateLimit != 100 {
		t.Fatalf("unexpected capabilities: %+v", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/jinmu/Programming/cinchcli/relay
go test ./internal/relay/... -run "TestUserCapabilities" -v
```

Expected: FAIL — `relay.UserCapabilities` undefined, `store.GetUserCapabilities` undefined.

- [ ] **Step 3: Add `UserCapabilities` struct**

In `relay/internal/relay/store.go`, after the `Tombstone` struct (around line 23):

```go
// UserCapabilities stores plan-derived limits for a user.
// All zero values mean unlimited (self-host default).
type UserCapabilities struct {
	UserID          string
	DeviceLimit     int
	RetentionDays   int
	RateLimit       int       // requests per day; 0 = unlimited
	GraceExpiresAt  time.Time // zero = no active grace period
}
```

- [ ] **Step 4: Add tables to `migrate()`**

In `relay/internal/relay/store.go`, inside the `migrate()` function, add the new tables to the opening `db.Exec` block (after the `clip_tombstones` table, before the closing backtick and `)`):

```sql
CREATE TABLE IF NOT EXISTS user_capabilities (
    user_id          TEXT PRIMARY KEY REFERENCES users(id),
    device_limit     INTEGER  NOT NULL DEFAULT 0,
    retention_days   INTEGER  NOT NULL DEFAULT 0,
    rate_limit       INTEGER  NOT NULL DEFAULT 0,
    grace_expires_at DATETIME,
    updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api_request_counts (
    user_id TEXT NOT NULL,
    date    TEXT NOT NULL,
    count   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, date)
);
```

- [ ] **Step 5: Add `GetUserCapabilities` and `UpsertUserCapabilities` methods**

Add to `relay/internal/relay/store.go` after `SweepTombstones` (end of file):

```go
// GetUserCapabilities loads quota limits for a user.
// Returns a zero-value UserCapabilities (all limits = 0 = unlimited) when
// no row exists, which is the correct default for self-hosters.
func (s *Store) GetUserCapabilities(userID string) (UserCapabilities, error) {
	var cap UserCapabilities
	var graceAt sql.NullTime
	err := s.db.QueryRow(
		`SELECT user_id, device_limit, retention_days, rate_limit, grace_expires_at
		 FROM user_capabilities WHERE user_id = ?`,
		userID,
	).Scan(&cap.UserID, &cap.DeviceLimit, &cap.RetentionDays, &cap.RateLimit, &graceAt)
	if err == sql.ErrNoRows {
		return UserCapabilities{}, nil // unlimited
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
// Called only by the internal quota endpoint.
func (s *Store) UpsertUserCapabilities(cap UserCapabilities) error {
	var graceAt interface{}
	if !cap.GraceExpiresAt.IsZero() {
		graceAt = cap.GraceExpiresAt.UTC().Format(time.RFC3339)
	}
	_, err := s.db.Exec(
		`INSERT INTO user_capabilities (user_id, device_limit, retention_days, rate_limit, grace_expires_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, datetime('now'))
		 ON CONFLICT(user_id) DO UPDATE SET
		   device_limit     = excluded.device_limit,
		   retention_days   = excluded.retention_days,
		   rate_limit       = excluded.rate_limit,
		   grace_expires_at = excluded.grace_expires_at,
		   updated_at       = excluded.updated_at`,
		cap.UserID, cap.DeviceLimit, cap.RetentionDays, cap.RateLimit, graceAt,
	)
	return err
}
```

- [ ] **Step 6: Add `CountActiveDevices` and `IncrementDailyRequestCount` methods**

Add to `relay/internal/relay/store.go` after `UpsertUserCapabilities`:

```go
// CountActiveDevices returns the number of non-revoked devices for a user.
func (s *Store) CountActiveDevices(userID string) (int, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM devices WHERE user_id = ? AND revoked_at IS NULL`,
		userID,
	).Scan(&count)
	return count, err
}

// IncrementDailyRequestCount atomically increments today's request count for a user
// and returns the new total.
func (s *Store) IncrementDailyRequestCount(userID string) (int, error) {
	today := time.Now().UTC().Format("2006-01-02")
	var count int
	err := s.db.QueryRow(
		`INSERT INTO api_request_counts (user_id, date, count)
		 VALUES (?, ?, 1)
		 ON CONFLICT(user_id, date) DO UPDATE SET count = count + 1
		 RETURNING count`,
		userID, today,
	).Scan(&count)
	return count, err
}

// SweepOldRequestCounts deletes daily request count rows older than retentionDays.
func (s *Store) SweepOldRequestCounts(retentionDays int) (int, error) {
	res, err := s.db.Exec(
		`DELETE FROM api_request_counts WHERE date < date('now', '-' || ? || ' days')`,
		retentionDays,
	)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
```

- [ ] **Step 7: Run tests to verify they pass**

```bash
cd /Users/jinmu/Programming/cinchcli/relay
go test ./internal/relay/... -run "TestUserCapabilities" -v
```

Expected: PASS both tests.

- [ ] **Step 8: Commit**

```bash
cd /Users/jinmu/Programming/cinchcli/relay
git add internal/relay/store.go internal/relay/relay_test.go
git commit -m "feat: add user_capabilities schema and Store data layer for quota enforcement"
```

---

## Task 2: Device limit enforcement in OAuth device registration

The device limit should block registration of a *new* device (not a re-auth of an existing one) when the user has hit their limit and grace has expired. The enforcement point is `UpsertOAuthUser` in `store.go`, in the path where `existingID == ""` (fresh device row).

**Files:**
- Modify: `relay/internal/relay/store.go:727` (`UpsertOAuthUser`)
- Modify: `relay/internal/relay/relay_test.go` (new tests)

- [ ] **Step 1: Write the failing test**

Add to `relay/internal/relay/relay_test.go`:

```go
func TestDeviceLimit_BlocksNewDevice(t *testing.T) {
	store, err := relay.NewStore(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer store.Close()

	// First OAuth login: creates user + device 1.
	userID, _, _, err := store.UpsertOAuthUser("github", "block-subject", "host1", "machine1")
	if err != nil {
		t.Fatalf("first login: %v", err)
	}

	// Set device_limit = 1 (user is now at the limit).
	if err := store.UpsertUserCapabilities(relay.UserCapabilities{
		UserID:      userID,
		DeviceLimit: 1,
	}); err != nil {
		t.Fatalf("UpsertUserCapabilities: %v", err)
	}

	// Second OAuth login with a NEW machine — same user (same github subject), different machineID.
	_, _, _, err = store.UpsertOAuthUser("github", "block-subject", "host2", "machine2")
	if err == nil {
		t.Fatal("expected device_limit_exceeded error, got nil")
	}
	if !strings.Contains(err.Error(), "device_limit_exceeded") {
		t.Fatalf("expected device_limit_exceeded in error, got: %v", err)
	}
}

func TestDeviceLimit_GracePeriodAllowsDevice(t *testing.T) {
	store, err := relay.NewStore(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer store.Close()

	// First OAuth login: creates user + device 1.
	userID, _, _, err := store.UpsertOAuthUser("github", "grace-subject", "host1", "machine1")
	if err != nil {
		t.Fatalf("first login: %v", err)
	}

	// Set limit = 1 but grace expires in the future.
	if err := store.UpsertUserCapabilities(relay.UserCapabilities{
		UserID:         userID,
		DeviceLimit:    1,
		GraceExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("UpsertUserCapabilities: %v", err)
	}

	// Second device on new machine — should succeed because grace period is active.
	_, _, _, err = store.UpsertOAuthUser("github", "grace-subject", "host2", "machine2")
	if err != nil {
		t.Fatalf("expected success during grace period, got: %v", err)
	}
}

func TestDeviceLimit_ReauthAllowed(t *testing.T) {
	store, err := relay.NewStore(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer store.Close()

	machineID := "same-machine-123"
	// First login on this machine: creates user + device.
	userID, _, _, err := store.UpsertOAuthUser("github", "reauth-subject", "my-mac", machineID)
	if err != nil {
		t.Fatalf("first login: %v", err)
	}

	// Set limit = 1 (exactly at the limit).
	if err := store.UpsertUserCapabilities(relay.UserCapabilities{
		UserID:      userID,
		DeviceLimit: 1,
	}); err != nil {
		t.Fatalf("UpsertUserCapabilities: %v", err)
	}

	// Re-auth from the SAME machine — should succeed (not a new device row).
	_, _, _, err = store.UpsertOAuthUser("github", "reauth-subject", "my-mac", machineID)
	if err != nil {
		t.Fatalf("re-auth from same machine should succeed, got: %v", err)
	}
}
```

Add `"strings"` to the test file's import block if not already present.

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/jinmu/Programming/cinchcli/relay
go test ./internal/relay/... -run "TestDeviceLimit" -v
```

Expected: FAIL — `UpsertOAuthUser` does not yet enforce limits.

- [ ] **Step 3: Add device limit check in `UpsertOAuthUser`**

In `relay/internal/relay/store.go`, locate `UpsertOAuthUser` (around line 727). Find the section after `existingID` is determined and the block `if existingID != "" { ... return ... }`. The check must be inserted **after** the existing-device check and **before** the fresh device INSERT:

```go
// After the existing-device check that returns early, add:

// Device limit check — only for new device rows (re-auth always passes).
cap, capErr := s.GetUserCapabilities(userID)
if capErr == nil && cap.DeviceLimit > 0 {
    count, cntErr := s.CountActiveDevices(userID)
    if cntErr == nil && count >= cap.DeviceLimit {
        // Allow if grace period is still active.
        if cap.GraceExpiresAt.IsZero() || time.Now().After(cap.GraceExpiresAt) {
            return "", "", "", fmt.Errorf("device_limit_exceeded: user has %d/%d active devices", count, cap.DeviceLimit)
        }
    }
}

// Fresh device row.
deviceID := ulid.Make().String()
// ... existing INSERT code continues unchanged ...
```

The exact insertion point in `store.go` is after line ~793 (`return userID, existingID, deviceToken, nil`) ends the existing-device branch, and before the line `// Fresh device row.` (around line 795).

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/jinmu/Programming/cinchcli/relay
go test ./internal/relay/... -run "TestDeviceLimit" -v
```

Expected: PASS all three.

- [ ] **Step 5: Commit**

```bash
cd /Users/jinmu/Programming/cinchcli/relay
git add internal/relay/store.go internal/relay/relay_test.go
git commit -m "feat: enforce device limit in UpsertOAuthUser with grace period support"
```

---

## Task 3: Rate limit enforcement in PushClip

Enforce daily request rate limits in both the REST handler and the Connect-RPC handler.

**Files:**
- Modify: `relay/internal/relay/handler.go:425` (`PushClip`)
- Modify: `relay/internal/relay/connect_clips.go:50` (`connectClipsServer.PushClip`)
- Modify: `relay/internal/relay/relay_test.go` (new tests)

- [ ] **Step 1: Write the failing test**

Add to `relay/internal/relay/relay_test.go`:

```go
func TestRateLimit_BlocksAfterLimit(t *testing.T) {
	store, err := relay.NewStore(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer store.Close()
	uid := "rate-user"
	if err := store.CreateUser(uid); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := store.UpsertUserCapabilities(relay.UserCapabilities{
		UserID:    uid,
		RateLimit: 2,
	}); err != nil {
		t.Fatalf("UpsertUserCapabilities: %v", err)
	}

	// Increment twice — both should be within limit.
	for i := 0; i < 2; i++ {
		count, err := store.IncrementDailyRequestCount(uid)
		if err != nil {
			t.Fatalf("increment %d: %v", i, err)
		}
		cap, _ := store.GetUserCapabilities(uid)
		if cap.RateLimit > 0 && count > cap.RateLimit {
			t.Fatalf("push %d blocked unexpectedly", i+1)
		}
	}

	// Third increment — count=3 exceeds limit=2.
	count, err := store.IncrementDailyRequestCount(uid)
	if err != nil {
		t.Fatalf("increment: %v", err)
	}
	cap, _ := store.GetUserCapabilities(uid)
	if cap.RateLimit == 0 || count <= cap.RateLimit {
		t.Fatalf("expected rate limit exceeded (count=%d limit=%d)", count, cap.RateLimit)
	}
}

func TestRateLimit_ZeroIsUnlimited(t *testing.T) {
	store, err := relay.NewStore(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer store.Close()
	uid := "unlimited-user"
	if err := store.CreateUser(uid); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	// No capabilities row = rate_limit 0 = unlimited.
	cap, err := store.GetUserCapabilities(uid)
	if err != nil {
		t.Fatalf("GetUserCapabilities: %v", err)
	}
	if cap.RateLimit != 0 {
		t.Fatalf("expected rate_limit 0, got %d", cap.RateLimit)
	}
}

func TestPushClip_RateLimitHTTP(t *testing.T) {
	// Verifies that the rate limit check does not block pushes when no
	// capabilities row exists (self-host / no limit configured).
	ts, _ := setupTestServer(t)
	token, _, _ := login(t, ts.URL)

	body, _ := json.Marshal(map[string]interface{}{
		"content":   "hello",
		"encrypted": true,
	})
	req, _ := http.NewRequest("POST", ts.URL+"/clips", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}
```

- [ ] **Step 2: Run test to verify it fails (the rate limit test)**

```bash
cd /Users/jinmu/Programming/cinchcli/relay
go test ./internal/relay/... -run "TestRateLimit|TestPushClip_RateLimit" -v
```

Expected: `TestRateLimit_BlocksAfterLimit` and `TestRateLimit_ZeroIsUnlimited` pass (they test Store only); `TestPushClip_RateLimitHTTP` passes (no rate limit configured yet, so push succeeds).

- [ ] **Step 3: Add rate limit check in `Handler.PushClip`**

In `relay/internal/relay/handler.go`, locate `PushClip` at line 425. After the demo-restriction block (around line 500, just before `clip, err := h.store.SaveClip(userID, &req)` for the non-demo path), add:

```go
// Rate limit check (non-demo users only; demo has its own count gate).
if !isDemoUser {
    cap, capErr := h.store.GetUserCapabilities(userID)
    if capErr == nil && cap.RateLimit > 0 {
        count, cntErr := h.store.IncrementDailyRequestCount(userID)
        if cntErr == nil && count > cap.RateLimit {
            writeError(w, http.StatusTooManyRequests, "rate_limit_exceeded",
                fmt.Sprintf("Daily push limit of %d reached", cap.RateLimit),
                "Upgrade your plan or wait until midnight UTC to reset")
            return
        }
    }
}
```

This goes right before the `clip, err := h.store.SaveClip(userID, &req)` call on line 503 (the non-targeted, non-demo path). The targeted-push path (lines 464-483) also needs the same check — add it before the `SaveClip` call inside the `if targetDeviceID != ""` block too.

For the targeted-push block (around line 462, before `clip, err := h.store.SaveClip`):

```go
// Rate limit check for targeted push.
if !isDemoUser {
    cap, capErr := h.store.GetUserCapabilities(userID)
    if capErr == nil && cap.RateLimit > 0 {
        count, cntErr := h.store.IncrementDailyRequestCount(userID)
        if cntErr == nil && count > cap.RateLimit {
            writeError(w, http.StatusTooManyRequests, "rate_limit_exceeded",
                fmt.Sprintf("Daily push limit of %d reached", cap.RateLimit),
                "Upgrade your plan or wait until midnight UTC to reset")
            return
        }
    }
}
```

- [ ] **Step 4: Add rate limit check in `connectClipsServer.PushClip`**

In `relay/internal/relay/connect_clips.go`, locate `connectClipsServer.PushClip`. After the demo-restriction block (around line 104, before `clip, err := s.h.store.SaveClip(userID, req.Msg)` for the non-targeted path), add:

```go
// Rate limit check (non-demo users only).
if !isDemoUser {
    cap, capErr := s.h.store.GetUserCapabilities(userID)
    if capErr == nil && cap.RateLimit > 0 {
        count, cntErr := s.h.store.IncrementDailyRequestCount(userID)
        if cntErr == nil && count > cap.RateLimit {
            return nil, connect.NewError(connect.CodeResourceExhausted,
                fmt.Errorf("rate_limit_exceeded: daily push limit of %d reached", cap.RateLimit))
        }
    }
}
```

Add the same check before the targeted-push `SaveClip` call (around line 73).

- [ ] **Step 5: Run all relay tests**

```bash
cd /Users/jinmu/Programming/cinchcli/relay
make test
```

Expected: PASS. No existing tests should break.

- [ ] **Step 6: Commit**

```bash
cd /Users/jinmu/Programming/cinchcli/relay
git add internal/relay/handler.go internal/relay/connect_clips.go internal/relay/relay_test.go
git commit -m "feat: enforce daily rate limit in PushClip (REST + Connect-RPC)"
```

---

## Task 4: Retention sweep uses capabilities

When a user has a `retention_days` value in `user_capabilities`, use it as the sweep retention; otherwise fall back to the device's `remote_retention_days`. This allows Cloud API to override the per-device setting for Free-tier users.

**Files:**
- Modify: `relay/internal/relay/store.go:1456` (`SweepAllUsersRetentionReturningMedia`)
- Modify: `relay/internal/relay/relay_test.go` (new test)

- [ ] **Step 1: Write the failing test**

Add to `relay/internal/relay/relay_test.go`:

```go
func TestSweepUsesCapabilitiesRetention(t *testing.T) {
	store, err := relay.NewStore(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer store.Close()

	userID := "sweep-cap-user"
	if err := store.CreateUser(userID); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	// Register a device with remote_retention_days = 30.
	if err := store.RegisterDeviceWithToken(userID, "dev1", "host1", "tok1"); err != nil {
		t.Fatalf("RegisterDeviceWithToken: %v", err)
	}
	if err := store.UpdateDeviceRetention("dev1", 30); err != nil {
		t.Fatalf("UpdateDeviceRetention: %v", err)
	}

	// Push a clip and backdate it to 5 days ago (within 30-day device limit, within 3-day cap limit).
	_, err = store.DB().Exec(
		`INSERT INTO clips (id, user_id, content, content_type, created_at)
		 VALUES ('clip-old', ?, 'hello', 'text', datetime('now', '-5 days'))`, userID)
	if err != nil {
		t.Fatalf("insert clip: %v", err)
	}

	// Set capabilities retention_days = 3 (stricter than device's 30).
	if err := store.UpsertUserCapabilities(relay.UserCapabilities{
		UserID:        userID,
		RetentionDays: 3,
	}); err != nil {
		t.Fatalf("UpsertUserCapabilities: %v", err)
	}

	// Sweep should use retention_days=3 from capabilities, not 30 from device.
	// The 5-day-old clip should be swept.
	_, err = store.SweepAllUsersRetentionReturningMedia()
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}

	var count int
	store.DB().QueryRow("SELECT COUNT(*) FROM clips WHERE id = 'clip-old'").Scan(&count)
	if count != 0 {
		t.Fatal("expected clip to be swept by capabilities retention_days=3, but it still exists")
	}
}
```

The test uses `store.DB()` for direct SQL access. Add this accessor to `store.go` as part of this step (end of file):

```go
// DB returns the underlying *sql.DB. Only use in tests.
func (s *Store) DB() *sql.DB { return s.db }
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/jinmu/Programming/cinchcli/relay
go test ./internal/relay/... -run "TestSweepUsesCapabilitiesRetention" -v
```

Expected: FAIL — clip is not swept because sweep uses device's 30-day retention (the clip is 5 days old, device says 30, so it survives).

- [ ] **Step 3: Modify `SweepAllUsersRetentionReturningMedia`**

In `relay/internal/relay/store.go`, find `SweepAllUsersRetentionReturningMedia` at line 1456. Replace the inner loop body:

```go
// BEFORE:
for _, u := range users {
    count, paths, sweepErr := s.SweepExpiredClipsReturningMedia(u.userID, u.days)
    if sweepErr != nil {
        log.Printf("retention sweep: user %s: %v", u.userID, sweepErr)
    } else if count > 0 {
        log.Printf("retention sweep: deleted %d clips for user %s (>%d days)", count, u.userID, u.days)
    }
    mediaPaths = append(mediaPaths, paths...)
}
```

```go
// AFTER:
for _, u := range users {
    retentionDays := u.days
    // Capabilities override per-device retention when set (non-zero).
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/jinmu/Programming/cinchcli/relay
go test ./internal/relay/... -run "TestSweepUsesCapabilitiesRetention" -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/jinmu/Programming/cinchcli/relay
git add internal/relay/store.go internal/relay/relay_test.go
git commit -m "feat: retention sweep respects capabilities.retention_days when set"
```

---

## Task 5: POST /internal/quota endpoint

Add the authenticated internal endpoint that Cloud API calls to write user capabilities.

**Files:**
- Modify: `relay/internal/relay/handler.go:128` (`Handler` struct)
- Modify: `relay/internal/relay/handler.go:1797` (`RegisterRoutes`)
- Modify: `relay/cmd/relay/main.go:64` (set secret on handler)
- Modify: `relay/internal/relay/relay_test.go` (new tests)

- [ ] **Step 1: Write the failing test**

Add to `relay/internal/relay/relay_test.go`:

```go
func setupTestServerWithSecret(t *testing.T, secret string) *httptest.Server {
	t.Helper()
	store, err := relay.NewStore(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	hub := relay.NewHub()
	go hub.Run()
	handler := relay.NewHandler(store, hub)
	handler.SetInternalServiceSecret(secret)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func TestInternalQuota_WritesCapabilities(t *testing.T) {
	ts := setupTestServerWithSecret(t, "test-secret")

	// Create a user first (quota endpoint requires user to exist).
	loginResp, _ := http.Post(ts.URL+"/auth/login", "application/json", nil)
	var lr struct{ UserId string `json:"user_id"` }
	json.NewDecoder(loginResp.Body).Decode(&lr)
	loginResp.Body.Close()
	userID := lr.UserId

	body, _ := json.Marshal(map[string]interface{}{
		"user_id":        userID,
		"device_limit":   3,
		"retention_days": 7,
		"rate_limit":     100,
	})
	req, _ := http.NewRequest("POST", ts.URL+"/internal/quota", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("quota request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 204, got %d: %s", resp.StatusCode, body)
	}
}

func TestInternalQuota_RejectsWrongSecret(t *testing.T) {
	ts := setupTestServerWithSecret(t, "correct-secret")

	body, _ := json.Marshal(map[string]interface{}{
		"user_id":      "some-user",
		"device_limit": 3,
	})
	req, _ := http.NewRequest("POST", ts.URL+"/internal/quota", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer wrong-secret")
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestInternalQuota_UnavailableWhenNoSecret(t *testing.T) {
	ts, _ := setupTestServer(t) // no secret set

	body, _ := json.Marshal(map[string]interface{}{"user_id": "x"})
	req, _ := http.NewRequest("POST", ts.URL+"/internal/quota", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer anything")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when no secret configured, got %d", resp.StatusCode)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/jinmu/Programming/cinchcli/relay
go test ./internal/relay/... -run "TestInternalQuota" -v
```

Expected: FAIL — `handler.SetInternalServiceSecret` undefined, `/internal/quota` returns 404.

- [ ] **Step 3: Add `internalServiceSecret` field and `SetInternalServiceSecret` to `Handler`**

In `relay/internal/relay/handler.go`, add field to the `Handler` struct (around line 128):

```go
type Handler struct {
    store       *Store
    hub         *Hub
    media       media.Store
    BaseURL     string
    OAuth       *OAuthProviders
    CORSOrigins []string

    TelemetryURL    string
    TelemetryAPIKey string

    telemetryLimiter *rateLimiter

    loginRateMu  sync.Mutex
    loginRateMap map[string]time.Time

    internalServiceSecret string // protects POST /internal/quota; empty = endpoint disabled
}

// SetInternalServiceSecret configures the bearer secret for POST /internal/quota.
func (h *Handler) SetInternalServiceSecret(s string) { h.internalServiceSecret = s }
```

- [ ] **Step 4: Add `UpdateUserQuota` handler**

Add to `relay/internal/relay/handler.go` (before `RegisterRoutes`):

```go
// UpdateUserQuota handles POST /internal/quota.
// Called by Cloud API to write numeric plan limits for a user.
// Protected by INTERNAL_SERVICE_SECRET bearer token (not RequireAuth).
func (h *Handler) UpdateUserQuota(w http.ResponseWriter, r *http.Request) {
    if h.internalServiceSecret == "" {
        writeError(w, http.StatusServiceUnavailable, "not_configured",
            "Internal quota endpoint is not configured on this relay", "")
        return
    }
    token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
    if token != h.internalServiceSecret {
        writeError(w, http.StatusForbidden, "forbidden", "Invalid service secret", "")
        return
    }

    var req struct {
        UserID         string  `json:"user_id"`
        DeviceLimit    int     `json:"device_limit"`
        RetentionDays  int     `json:"retention_days"`
        RateLimit      int     `json:"rate_limit"`
        GraceExpiresAt *string `json:"grace_expires_at"` // RFC 3339, optional
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid_request", "Could not parse request body", "")
        return
    }
    if req.UserID == "" {
        writeError(w, http.StatusBadRequest, "missing_user_id", "user_id is required", "")
        return
    }
    if req.DeviceLimit < 0 || req.RetentionDays < 0 || req.RateLimit < 0 {
        writeError(w, http.StatusBadRequest, "invalid_limits", "Limits must be non-negative", "")
        return
    }

    cap := UserCapabilities{
        UserID:        req.UserID,
        DeviceLimit:   req.DeviceLimit,
        RetentionDays: req.RetentionDays,
        RateLimit:     req.RateLimit,
    }
    if req.GraceExpiresAt != nil && *req.GraceExpiresAt != "" {
        t, err := time.Parse(time.RFC3339, *req.GraceExpiresAt)
        if err != nil {
            writeError(w, http.StatusBadRequest, "invalid_grace", "grace_expires_at must be RFC 3339", "")
            return
        }
        cap.GraceExpiresAt = t
    }

    if err := h.store.UpsertUserCapabilities(cap); err != nil {
        writeError(w, http.StatusInternalServerError, "upsert_failed", err.Error(), "")
        return
    }
    w.WriteHeader(http.StatusNoContent)
}
```

- [ ] **Step 5: Register the route in `RegisterRoutes`**

In `relay/internal/relay/handler.go`, inside `RegisterRoutes` (around line 1827, after the `GET /health` line), add:

```go
mux.HandleFunc("POST /internal/quota", h.UpdateUserQuota)
```

- [ ] **Step 6: Read env var in `main.go`**

In `relay/cmd/relay/main.go`, after `handler.TelemetryAPIKey = ...` (around line 91), add:

```go
handler.SetInternalServiceSecret(os.Getenv("INTERNAL_SERVICE_SECRET"))
```

- [ ] **Step 7: Run tests to verify they pass**

```bash
cd /Users/jinmu/Programming/cinchcli/relay
go test ./internal/relay/... -run "TestInternalQuota" -v
```

Expected: PASS all three.

- [ ] **Step 8: Run full test suite**

```bash
cd /Users/jinmu/Programming/cinchcli/relay
make test
```

Expected: PASS all tests.

- [ ] **Step 9: Commit**

```bash
cd /Users/jinmu/Programming/cinchcli/relay
git add internal/relay/handler.go internal/relay/relay_test.go cmd/relay/main.go
git commit -m "feat: add POST /internal/quota endpoint for Cloud API to write user capabilities"
```

---

## Task 6: Sweep old api_request_counts rows

Old daily count rows accumulate indefinitely. Add them to the hourly retention sweep.

**Files:**
- Modify: `relay/cmd/relay/main.go:110` (`runRetentionSweep`)
- Modify: `relay/internal/relay/relay_test.go` (new test)

- [ ] **Step 1: Write the failing test**

Add to `relay/internal/relay/relay_test.go`:

```go
func TestSweepOldRequestCounts(t *testing.T) {
	store, err := relay.NewStore(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer store.Close()
	uid := "sweep-count-user"
	if err := store.CreateUser(uid); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Insert a count row for 10 days ago.
	_, err = store.DB().Exec(
		`INSERT INTO api_request_counts (user_id, date, count) VALUES (?, date('now', '-10 days'), 5)`,
		uid,
	)
	if err != nil {
		t.Fatalf("insert old count: %v", err)
	}
	// Insert today's count.
	_, err = store.DB().Exec(
		`INSERT INTO api_request_counts (user_id, date, count) VALUES (?, date('now'), 3)`,
		uid,
	)
	if err != nil {
		t.Fatalf("insert today count: %v", err)
	}

	// Sweep rows older than 7 days.
	n, err := store.SweepOldRequestCounts(7)
	if err != nil {
		t.Fatalf("SweepOldRequestCounts: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 row swept, got %d", n)
	}

	// Today's row should remain.
	var remaining int
	store.DB().QueryRow(
		`SELECT COUNT(*) FROM api_request_counts WHERE user_id = ?`, uid,
	).Scan(&remaining)
	if remaining != 1 {
		t.Fatalf("expected 1 row remaining, got %d", remaining)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/jinmu/Programming/cinchcli/relay
go test ./internal/relay/... -run "TestSweepOldRequestCounts" -v
```

Expected: FAIL — `SweepOldRequestCounts` is defined in Task 1 but `runRetentionSweep` doesn't call it. The store test should PASS (method exists from Task 1). If it fails, verify Task 1 code is committed.

- [ ] **Step 3: Call `SweepOldRequestCounts` in `runRetentionSweep`**

In `relay/cmd/relay/main.go`, inside `runRetentionSweep` (after the tombstone sweep block), add:

```go
if n, err := store.SweepOldRequestCounts(7); err != nil {
    log.Printf("request count sweep: %v", err)
} else if n > 0 {
    log.Printf("request count sweep: removed %d old rows", n)
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/jinmu/Programming/cinchcli/relay
go test ./internal/relay/... -run "TestSweepOldRequestCounts" -v
```

Expected: PASS.

- [ ] **Step 5: Run full test suite**

```bash
cd /Users/jinmu/Programming/cinchcli/relay
make test
```

Expected: PASS all tests.

- [ ] **Step 6: Commit**

```bash
cd /Users/jinmu/Programming/cinchcli/relay
git add cmd/relay/main.go internal/relay/relay_test.go
git commit -m "feat: sweep old api_request_counts rows in hourly retention sweep"
```

---

## Verification

### Manual smoke test

```bash
# 1. Start relay with a service secret
INTERNAL_SERVICE_SECRET=dev-secret go run ./cmd/relay

# 2. Create a user via direct login
TOKEN=$(curl -s -X POST localhost:8080/auth/login | jq -r .token)
USER_ID=$(curl -s -X POST localhost:8080/auth/login | jq -r .user_id)

# 3. Set rate_limit = 2 via internal quota
curl -s -X POST localhost:8080/internal/quota \
  -H "Authorization: Bearer dev-secret" \
  -H "Content-Type: application/json" \
  -d "{\"user_id\": \"$USER_ID\", \"device_limit\": 3, \"retention_days\": 7, \"rate_limit\": 2}"
# Expected: HTTP 204

# 4. Push 2 clips (should succeed)
for i in 1 2; do
  curl -s -X POST localhost:8080/clips \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"content": "clip", "encrypted": true}'
done

# 5. Push 3rd clip (should return 429)
curl -s -X POST localhost:8080/clips \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"content": "clip", "encrypted": true}'
# Expected: {"error": {"code": "rate_limit_exceeded", ...}}

# 6. Verify wrong secret returns 403
curl -s -X POST localhost:8080/internal/quota \
  -H "Authorization: Bearer wrong" \
  -d '{}' | jq .error.code
# Expected: "forbidden"

# 7. Verify no secret returns 503
INTERNAL_SERVICE_SECRET="" go run ./cmd/relay &
curl -s -X POST localhost:8081/internal/quota \
  -H "Authorization: Bearer anything" \
  -d '{}' | jq .error.code
# Expected: "not_configured"
```

### Test run

```bash
cd /Users/jinmu/Programming/cinchcli/relay
make test
```

---

## Out of Scope

- Multi-relay routing (requires SQLite → Postgres)
- Token invalidation on downgrade (enforce immediately vs. on next auth)
- PushBinaryClip rate limiting (same pattern as PushClip — trivial follow-up)
- Cloud API service (sub-project 2)
