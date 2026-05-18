# Cinch Architecture Decisions

> Living document. Add a new section each time a significant decision is made.

---

## 2026-05-05 — Local-First Architecture Flip

### Decision

Flip source of truth from relay to desktop local SQLite.

**Before:** Relay stores all clips (30-day default TTL). Desktop backtracks from relay on startup.

**After:** Desktop local SQLite is source of truth. Relay is a 24h delivery buffer and catch-up pipe only.

### Why

- Competitor free tiers (Raycast: 3-month history) made our relay-gated retention look weak.
- Relay storage costs scaled linearly with users and clips, eating into hosted-tier margins.
- Offline reconnect had no catch-up — missed clips were permanently lost.
- `clip_deleted` events were defined but never emitted, so multi-device delete was broken.
- `INSERT OR REPLACE` silently destroyed `is_pinned`/`pin_note` on every backfill.

### What changed

| Area | Change |
|---|---|
| Relay TTL default | 30 days → 1 day (new devices only; existing rows unchanged) |
| Relay sweep predicate | Removed `source LIKE 'remote:%'` — all relay clips are transient |
| `ListClips` | Added `?since=<RFC3339>` filter for delta sync |
| `clip_deleted` broadcast | Now emitted on explicit user delete (REST + Connect-RPC) |
| Desktop `insert_clip` | `INSERT OR REPLACE` → UPSERT preserving `is_pinned`, `pin_note`, `synced` |
| Desktop schema | Added `received_at` column; `max_created_at()` watermark for delta sync |
| Desktop `backfill_from_relay` | Replaced by `delta_sync` — fetches only clips since watermark |
| Reconnect flow | `delta_sync` runs after `flush_offline_queue` on every WS reconnect |
| Delete propagation | `delete_clip` command calls relay best-effort before local delete |

### Known trade-offs

- **Sweep does not broadcast `clip_deleted`** — by design. Relay TTL expiry does not force deletion of local desktop copies. Clips the relay swept remain in desktop until the local retention sweep fires.
- **Delete sync gap for offline devices** — if a device is offline when `clip_deleted` is broadcast and stays offline >24h (past relay TTL), it will never receive the delete. The local copy survives. Tombstones table is a future fix.
- **delta_sync cap is 50** — if >50 clips were pushed while the device was offline within the 1-day TTL window, a single reconnect only recovers 50. Subsequent reconnects catch up the rest. Acceptable at current scale.

---

## 2026-05-05 — Cloud API / Billing Separation Architecture

### Decision

Business logic (billing, quotas, plan management) lives in a separate proprietary **Cloud API** service. The relay stays AGPL-clean.

### Why not these alternatives

| Alternative | Why rejected |
|---|---|
| `BILLING_SERVICE_URL` in relay | Relay calls billing on every hot-path request — adds latency + availability dependency |
| `users.plan` column in relay | Relay would encode business rules ("Pro = 90 days"). Policy changes require relay deploy |
| Quota enforcement in gateway/proxy | Extra network hop on every request; relay becomes unreachable without the proxy |

### Pattern chosen: ngrok model (Pattern A)

Based on research into ngrok, Tailscale, Plausible, Mattermost, and Outline — the closest match for a relay/pipe tool is ngrok's approach: the OSS relay is plan-agnostic and trusts capabilities injected by the control plane.

Concretely:

```
Stripe webhook
      ↓
Cloud API (proprietary)
  translates plan → numeric limits
      ↓ POST /internal/quota  (service secret, not public)
Relay writes to user_capabilities table
      ↓
Clip push / device register → relay reads capabilities from local DB
No external call on hot path
```

### user_capabilities table (relay-side)

```sql
CREATE TABLE user_capabilities (
  user_id        TEXT PRIMARY KEY REFERENCES users(id),
  device_limit   INTEGER NOT NULL DEFAULT 0,   -- 0 = unlimited (self-host)
  retention_days INTEGER NOT NULL DEFAULT 0,   -- 0 = unlimited
  storage_bytes  BIGINT  NOT NULL DEFAULT 0,   -- 0 = unlimited
  updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

- **Self-hosters:** table is empty → all limits default to 0 (unlimited).
- **Cloud users:** Cloud API writes a row on subscription create/update/cancel.
- **Relay code** never stores plan names — only enforces numbers.
- **Plan policy changes** (e.g., Pro retention 90→180 days) require only a Cloud API deploy, not a relay deploy.

### What Cloud API owns

- Stripe webhook handler
- plan → numeric limits translation
- `POST /internal/quota` call to relay (or direct DB write if co-located)
- User management UI (upgrade, cancel, org management)
- SSO/SAML (Enterprise tier)
- Audit log

### `GET /internal/users`

Read-only counterpart to `POST /internal/quota`. Returns paginated user
rows with device aggregates so the SaaS billing layer can render its
admin dashboard. Disabled by default — enable by setting
`INTERNAL_SERVICE_SECRET`. Self-hosters should use `GET /admin/users`
instead.

Query params: `limit` (1–1000, default 100), `cursor` (opaque, from a
prior response), `updated_since` (RFC 3339), `include_demo` (boolean,
default false; accepts `true/false/1/0` per `strconv.ParseBool`).

Response shape: `{users: [...], next_cursor?: string}`. Each user row
includes only `user_id`, `created_at`, `is_demo`, `device_count`,
`active_device_count`, `last_active_at`, and a nullable `capabilities`
block. Device tokens, hostnames, nicknames, machine IDs, clip metadata,
key material, and OAuth identity strings are **never** returned by this
endpoint. If biz needs per-device drill-down, add a separate scoped
endpoint — don't widen this one.

### Not yet designed

- Cloud API repo structure and tech stack
- Authentication between Cloud API and relay's `/internal/quota` endpoint
- Token refresh on plan downgrade (enforce immediately vs. on next auth)
- Multi-relay routing (when relay is horizontally scaled — SQLite → Postgres migration needed first)

---
