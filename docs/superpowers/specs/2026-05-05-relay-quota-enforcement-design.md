# Relay Quota Enforcement — Design Spec

**Date:** 2026-05-05
**Sub-project:** 1 of 2 (Relay-side only; Cloud API is sub-project 2)

---

## Goal

Add plan-aware quota enforcement to the relay without encoding business logic in the relay itself. The relay stays AGPL-clean and plan-agnostic — it enforces numeric limits injected by an external Cloud API service.

---

## Architecture

Pattern: **ngrok model** (documented in `docs/architecture-decisions.md`).

Cloud API translates plan names into numeric limits and writes them to the relay's `user_capabilities` table via a single internal endpoint. The relay reads capabilities from its local DB on every hot-path request — no external call, no added latency.

```
Stripe webhook
      ↓
Cloud API (proprietary)
  plan → numeric limits
      ↓ POST /internal/quota
Relay writes user_capabilities
      ↓
Clip push / device register → relay reads from local DB
```

---

## 1. Data Model

```sql
-- Written by Cloud API, read by relay on hot path
CREATE TABLE user_capabilities (
  user_id          TEXT     PRIMARY KEY REFERENCES users(id),
  device_limit     INTEGER  NOT NULL DEFAULT 0,   -- 0 = unlimited
  retention_days   INTEGER  NOT NULL DEFAULT 0,   -- 0 = unlimited
  rate_limit       INTEGER  NOT NULL DEFAULT 0,   -- 0 = unlimited (requests/day)
  grace_expires_at DATETIME,                      -- NULL = no active grace period
  updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Per-user daily request counter for rate limiting
CREATE TABLE api_request_counts (
  user_id TEXT NOT NULL,
  date    TEXT NOT NULL,  -- YYYY-MM-DD UTC
  count   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, date)
);
```

**Semantics:**
- `0` means unlimited for every numeric field — this is the default for self-hosters who never call `/internal/quota`.
- If no `user_capabilities` row exists for a user, all limits are treated as 0 (unlimited).
- `grace_expires_at` is only set on a downgrade; it is NULL in steady state.

**Plan mappings (Cloud API owns translation; relay only sees numbers):**

| Plan | device_limit | retention_days | rate_limit |
|---|---|---|---|
| Free | 3 | 7 | 100 req/day |
| Pro | 10 | 90 | 0 (unlimited) |
| Team | 0 (unlimited) | 365 | 0 (unlimited) |

---

## 2. Enforcement Points

### ① Device registration (hard limit)

Handler: `POST /devices` (REST) and `RegisterDevice` (Connect-RPC).

```
Load user_capabilities for user_id
if device_limit == 0:
    pass  // unlimited
count = SELECT COUNT(*) FROM devices WHERE user_id = ? AND revoked_at IS NULL
if count < device_limit:
    pass
if grace_expires_at IS NOT NULL AND grace_expires_at > now:
    pass  // grace period active
return 403 device_limit_exceeded
```

### ② Rate limiting on clip push

Handler: `POST /clips` (REST) and `PushClip` (Connect-RPC).

```
Load user_capabilities for user_id
if rate_limit == 0:
    pass  // unlimited
today = UTC date string (YYYY-MM-DD)
INSERT INTO api_request_counts (user_id, date, count)
  VALUES (?, today, 1)
  ON CONFLICT (user_id, date) DO UPDATE SET count = count + 1
RETURNING count
if count > rate_limit:
    return 429 rate_limit_exceeded
```

Old `api_request_counts` rows (past dates) are swept by the existing hourly retention sweep.

### ③ Retention sweep

`SweepExpiredClipsReturningMedia` already uses `devices.remote_retention_days` per device. With capabilities:

```
For each device being swept:
  Load user_capabilities for device.user_id
  if retention_days != 0:
      effective_retention = retention_days     // capabilities override
  else:
      effective_retention = device.remote_retention_days  // fallback (self-host)
```

This means Free users get 7-day relay sweep regardless of what `remote_retention_days` says; self-hosters keep their per-device setting.

---

## 3. Internal Quota Endpoint

Protected by a shared secret (`INTERNAL_SERVICE_SECRET` env var). Not exposed publicly.

```
POST /internal/quota
Authorization: Bearer <INTERNAL_SERVICE_SECRET>
Content-Type: application/json

{
  "user_id":          "01J...",
  "device_limit":     3,
  "retention_days":   7,
  "rate_limit":       100,
  "grace_expires_at": "2026-05-12T00:00:00Z"  // omit or null if no grace period
}
```

**Behavior:**
- `INSERT OR REPLACE` into `user_capabilities` (upsert on `user_id`).
- Returns `204 No Content` on success.
- Returns `400` if `user_id` is missing or limits are negative.
- Returns `403` if `Authorization` header doesn't match `INTERNAL_SERVICE_SECRET`.
- `grace_expires_at` is optional; omitting it leaves the field NULL (no grace period).

---

## 4. Grace Period (Device Limit Downgrade)

When Cloud API downgrades a user (e.g., Pro → Free, device_limit 10 → 3):

1. Cloud API sets `grace_expires_at = now + 7 days` in the `/internal/quota` call.
2. Relay device registration check: if `device_count > device_limit` AND `grace_expires_at > now` → allow.
3. After 7 days: new device registrations are blocked with `403 device_limit_exceeded`.
4. **Existing device sessions are never terminated.** The limit only blocks new registrations.

---

## 5. Error Responses

All errors use the relay's existing `{"error": {"code": "...", "message": "..."}}` envelope.

| Condition | HTTP | error_code |
|---|---|---|
| Device count ≥ limit (grace expired or no grace) | 403 | `device_limit_exceeded` |
| Daily push count > rate_limit | 429 | `rate_limit_exceeded` |

---

## 6. Self-Host Compatibility

- No `user_capabilities` row → all limits are 0 = unlimited. Zero rows = zero enforcement.
- Self-hosters never need to call `/internal/quota`.
- `INTERNAL_SERVICE_SECRET` env var absent → endpoint returns 503 (not silently open).

---

## 7. Out of Scope

- **Cloud API service** (plan management, Stripe webhooks, user portal) — sub-project 2.
- **Authentication between Cloud API and relay** beyond `INTERNAL_SERVICE_SECRET` (service secret is sufficient for v1; mTLS is a future upgrade path).
- **Token refresh on downgrade** (immediate enforcement vs. on next auth) — deferred.
- **Multi-relay routing** — requires SQLite → Postgres migration first.
- **storage_bytes limit** — relay is a 24h pipe; cumulative relay storage is inherently bounded by TTL. Per-clip size limits are a separate, later concern.
