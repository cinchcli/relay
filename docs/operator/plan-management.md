# Plan Management

This relay enforces per-user plan caps via the `user_capabilities` table.
**Defaults (no row exists) are *unlimited*** — `GetUserCapabilities`
returns a zero-value `UserCapabilities{}` for missing rows, and the
enforcement sites both gate on `cap.DeviceLimit > 0`, so a user with no
row pays nothing and consumes unlimited resources. Hosted cinchcli.com
provisions a free-plan row at OAuth sign-up; self-hosters typically
leave the table empty.

## Plan tiers

The relay encodes plan identity in a single column — `device_limit` —
and infers a plan name from it via `planNameFromCaps` in
`internal/relay/connect_me.go`. The recognised values:

| Plan   | `device_limit` | Suggested `retention_days` | `rate_limit` |
|--------|----------------|----------------------------|--------------|
| free   | 3              | 7                          | 0            |
| pro    | 10             | 30                         | 0            |
| team   | 25             | 90                         | 0            |

Only the `device_limit` column drives the plan-name mapping (constants
`freeDeviceLimit`, `proDeviceLimit`, `teamDeviceLimit`). The
`retention_days` values above are the recommended pairings for hosted
cinchcli.com — operators must set them explicitly when writing a row;
nothing in the relay enforces a tier-specific default.

Any other `device_limit` (e.g. `15`) reports as `plan_name = "custom"`
to clients via `MeService.GetMe`. A row with all-zero caps reports as
`"free"`; a row with `device_limit = 0` but non-zero `retention_days`
or `rate_limit` reports as `"custom"`.

`rate_limit = 0` means "unset"; today the relay does not enforce
per-request quotas — the column is reserved for future use.

## Setting caps

### Via `POST /internal/quota` (preferred)

Protected by the `INTERNAL_SERVICE_SECRET` bearer (set on the relay
process; unset means the endpoint returns `503 not_configured`).
On success returns `204 No Content`.

```bash
curl -fsS -X POST https://api.cinchcli.com/internal/quota \
  -H "Authorization: Bearer $INTERNAL_SERVICE_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id":        "01H...",
    "device_limit":   10,
    "retention_days": 30,
    "rate_limit":     0
  }'
```

Body shape (handler: `Handler.UpdateUserQuota` in
`internal/relay/handler.go`):

| Field              | Type     | Notes                                          |
|--------------------|----------|------------------------------------------------|
| `user_id`          | string   | Required. The relay user ULID.                 |
| `device_limit`     | int >= 0 | `0` = no cap.                                  |
| `retention_days`   | int >= 0 | `0` = no plan-level cap (per-device value applies). |
| `rate_limit`       | int >= 0 | Reserved; `0` today.                           |
| `grace_expires_at` | RFC 3339 | Optional. Omit or `""` to clear.               |

Errors:

- `400 invalid_request` — body did not parse.
- `400 missing_user_id` — `user_id` empty.
- `400 invalid_limits` — any of the three numeric fields is negative.
- `400 invalid_grace` — `grace_expires_at` not RFC 3339.
- `403 forbidden` — bearer token mismatch.
- `503 not_configured` — relay started without `INTERNAL_SERVICE_SECRET`.

The endpoint is an upsert — calling it again with the same `user_id`
replaces the row.

### Via SQL (fallback)

When the relay was started without `INTERNAL_SERVICE_SECRET`, or you
need to bulk-promote users, write directly:

```sql
INSERT INTO user_capabilities (user_id, device_limit, retention_days, rate_limit)
VALUES ('01H...', 10, 30, 0)
ON CONFLICT (user_id) DO UPDATE SET
  device_limit   = EXCLUDED.device_limit,
  retention_days = EXCLUDED.retention_days,
  rate_limit     = EXCLUDED.rate_limit,
  updated_at     = NOW();
```

## Grace periods

Set `grace_expires_at` to a future timestamp to let a user temporarily
exceed `device_limit`. The common case: a paying user downgrades — give
them N days to revoke devices before the cap snaps shut.

Both enforcement sites honour the grace window: when the user is over
the cap **and** `now() <= grace_expires_at`, the device is provisioned
anyway.

```sql
UPDATE user_capabilities
SET grace_expires_at = NOW() + INTERVAL '14 days'
WHERE user_id = '01H...';
```

Or via the HTTP endpoint:

```bash
curl -fsS -X POST https://api.cinchcli.com/internal/quota \
  -H "Authorization: Bearer $INTERNAL_SERVICE_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id":          "01H...",
    "device_limit":     3,
    "retention_days":   7,
    "rate_limit":       0,
    "grace_expires_at": "2026-06-04T00:00:00Z"
  }'
```

### Cap-check asymmetry

The two enforcement sites use deliberately different comparisons —
this is correct, not a bug:

- **`UpsertOAuthUser`** (OAuth sign-up path,
  `internal/relay/store.go`): rejects when `count >= cap.DeviceLimit`.
  The new device has not been inserted yet, so we reject *before*
  adding it.
- **`CompleteDeviceCode`** (device-code flow, `internal/relay/store.go`):
  rejects when `count > cap.DeviceLimit`. The pending device row was
  already inserted by `CreateDeviceForUser` and is counted in `count`,
  so equality is the allowed boundary; a rejection here also rolls back
  the phantom device row.

The grace check is identical at both sites:
`cap.GraceExpiresAt.IsZero() || time.Now().After(cap.GraceExpiresAt)`.

## Self-host carve-out

Operators of standalone relays who don't want enforcement at all can set:

```
CINCH_PLAN_ENFORCEMENT_DISABLED=1
```

`"1"` or `"true"` (case-insensitive) both enable the carve-out. This
flips `Store.EnforcementDisabled = true`, which:

- Skips the `device_limit` check in `CompleteDeviceCode`.
- Skips the plan-derived retention clamp in `UpdateDeviceRetention`
  (per-device `remote_retention_days` still applies).
- Degrades the hourly retention sweep to "no plan cap" — only the
  per-device value drives clip deletion.

`UpsertOAuthUser` does not currently consult `EnforcementDisabled` —
it gates on `cap.DeviceLimit > 0` instead, so self-hosters with an
empty `user_capabilities` table are unaffected. Don't write rows into
that table on a self-host install unless you want them enforced.

Logged at startup with `level=WARN`:

```
plan enforcement disabled via CINCH_PLAN_ENFORCEMENT_DISABLED — self-host mode
```

## Verifying

After applying caps, on the affected user's paired machine:

```bash
cinch plan
```

This calls `MeService.GetMe` and prints the resolved plan name, the
numeric caps, and the current active-device count. The plan name is
derived server-side from the `device_limit` value, so a `device_limit`
that doesn't match one of `freeDeviceLimit` (3), `proDeviceLimit` (10),
or `teamDeviceLimit` (25) renders as `custom`.
