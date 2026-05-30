# Cinch Relay

Self-hostable relay server for [Cinch](https://cinchcli.com) — Your clipboard. Across every machine.

The relay receives clipboard clips pushed by the CLI (`cinch push`) and delivers them in real time to connected devices via WebSocket. It is the only component you need to self-host; the CLI and desktop app work with any relay URL.

## Quick Start (Docker)

The relay requires a PostgreSQL database (set `DATABASE_URL`).

If you already have Postgres, you can run the relay directly:

```bash
docker run -p 8080:8080 \
  -e DATABASE_URL='postgres://user:pass@host:5432/relay?sslmode=disable' \
  ghcr.io/cinchcli/relay:latest
```

Then point the CLI at your relay:

```bash
cinch auth login --relay http://your-server:8080
```

## Quick Start (Docker Compose)

This brings up Postgres + relay locally, with media stored on local disk:

```yaml
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: relay
      POSTGRES_PASSWORD: relay
      POSTGRES_DB: relay
    volumes:
      - relay-pg:/var/lib/postgresql/data

  relay:
    image: ghcr.io/cinchcli/relay:latest
    ports:
      - "8080:8080"
    environment:
      PORT: 8080
      DATABASE_URL: postgres://relay:relay@postgres:5432/relay?sslmode=disable
      MEDIA_BACKEND: local
      MEDIA_LOCAL_DIR: /data/media
      BASE_URL: https://relay.example.com
    volumes:
      - relay-media:/data/media
    depends_on:
      - postgres
    restart: unless-stopped

volumes:
  relay-pg:
  relay-media:
```

Save as `docker-compose.yml` and run:

```bash
docker compose up -d
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | TCP port the server listens on |
| `DATABASE_URL` | _(required)_ | PostgreSQL DSN (used with `pgx`), e.g. `postgres://user:pass@host:5432/relay?sslmode=disable` |
| `BASE_URL` | _(unset)_ | Public HTTPS root of the relay, e.g. `https://relay.example.com`. Required for OAuth sign-in. |
| `RELAY_REGION` | _(unset)_ | Optional region label returned in health responses |
| `CORS_ORIGINS` | _(unset)_ | Comma-separated extra allowed CORS origins |
| `MEDIA_BACKEND` | `local` | Media storage backend: `local` or `s3` |
| `MEDIA_LOCAL_DIR` | `media` | Local directory for media objects when `MEDIA_BACKEND=local` |
| `MEDIA_ENDPOINT` | _(unset)_ | S3 endpoint host when `MEDIA_BACKEND=s3` (e.g. `s3.amazonaws.com` or MinIO endpoint) |
| `MEDIA_BUCKET` | _(unset)_ | S3 bucket name when `MEDIA_BACKEND=s3` |
| `MEDIA_REGION` | _(unset)_ | S3 region when `MEDIA_BACKEND=s3` |
| `MEDIA_ACCESS_KEY_ID` | _(unset)_ | S3 access key when `MEDIA_BACKEND=s3` (omit when using IAM roles) |
| `MEDIA_SECRET_ACCESS_KEY` | _(unset)_ | S3 secret key when `MEDIA_BACKEND=s3` (omit when using IAM roles) |
| `MEDIA_USE_SSL` | `true` | Set to `false` to use plain HTTP for S3-compatible endpoints |
| `GITHUB_CLIENT_ID` | _(unset)_ | GitHub OAuth App client ID (enables GitHub sign-in) |
| `GITHUB_CLIENT_SECRET` | _(unset)_ | GitHub OAuth App client secret |
| `GOOGLE_CLIENT_ID` | _(unset)_ | Google OAuth client ID (enables Google sign-in) |
| `GOOGLE_CLIENT_SECRET` | _(unset)_ | Google OAuth client secret |
| `LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT` | `text` | Log format: `text` (human-readable) or `json` (structured) |

## OAuth Sign-in (optional)

By default the relay uses a simple device-name form for authentication. To enable **Sign in with GitHub / Google**:

1. **Register a GitHub OAuth App**
   - Homepage URL: `https://your-relay.example.com`
   - Callback URL: `https://your-relay.example.com/auth/oauth/github/callback`

2. **Register a Google OAuth Client** (optional)
   - Redirect URI: `https://your-relay.example.com/auth/oauth/google/callback`

3. **Set env vars and restart:**

```bash
BASE_URL=https://your-relay.example.com
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
```

If neither `GITHUB_CLIENT_ID` nor `GOOGLE_CLIENT_ID` is set, the relay falls back to the username form — self-hosters who skip OAuth are unaffected.

See cinchcli.com/docs for production deployment guidance.

## API Overview

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check — returns `{"status":"ok"}` |
| `GET` | `/auth/browser` | Device sign-in page (OAuth or username form) |
| `GET` | `/auth/oauth/github/start` | Redirect to GitHub OAuth |
| `GET` | `/auth/oauth/github/callback` | GitHub OAuth callback |
| `GET` | `/auth/oauth/google/start` | Redirect to Google OAuth |
| `GET` | `/auth/oauth/google/callback` | Google OAuth callback |
| `POST` | `/auth/login` | Create/resume account (device-code flow) |
| `POST` | `/auth/pair` | Exchange pair token for device token |
| `POST` | `/v1/clips` | Push a clipboard clip |
| `GET` | `/v1/clips` | Fetch latest clip |
| `GET` | `/v1/stream` | WebSocket real-time clip stream |

Full Connect-RPC service definitions live in [`proto/cinch/v1/`](proto/cinch/v1/).

## Wire Schema

The `.proto` files at `proto/cinch/v1/` are **vendored from the [cinch monorepo](https://github.com/cinchcli/cinch)**. The canonical source of truth lives at `crates/client-core/proto/cinch/v1/` in that repo. Changes to the wire schema flow into this repo via an auto-PR from the cinch monorepo's `proto-sync-relay.yml` workflow.

To regenerate Go bindings after a sync:

```bash
make generate
```

To verify your local proto matches upstream:

```bash
make verify-proto                                          # uses ../../cinch/main as upstream
UPSTREAM=/path/to/cinch make verify-proto                  # custom path
```

The generated Go code lives at `internal/cinchv1/` (imported as `cinchv1 "github.com/cinchcli/relay/internal/cinchv1"`). Connect-RPC service stubs are at `internal/cinchv1/cinchv1connect/`.

## Building from Source

```bash
git clone https://github.com/cinchcli/relay.git
cd relay
go build -o dist/relay ./cmd/relay
./dist/relay --port 8080
```

Requires Go 1.24+. No CGO needed (`CGO_ENABLED=0`).

## Documentation

Full docs at [cinchcli.com/docs](https://cinchcli.com/docs).

Operator runbooks:

- [Plan management](docs/operator/plan-management.md) — setting per-user
  device / retention caps, grace periods, and the self-host carve-out.

## Related Repos

- [cinchcli/cinch](https://github.com/cinchcli/cinch) — CLI client (`cinch push` / `pull` / `auth`)
- [cinchcli/desktop](https://github.com/cinchcli/desktop) — Tauri v2 desktop app (macOS)

The wire-format DTOs (`Clip`, `Device`, push/pull/auth requests, etc.) are
defined in the cinch monorepo at `crates/client-core/proto/cinch/v1/*.proto`
and vendored into this repo under `proto/cinch/v1/`. The Rust CLI and
desktop generate their types from the same `.proto` source via
`client-core` in [cinchcli/cinch](https://github.com/cinchcli/cinch).
See [Wire Schema](#wire-schema) above for the sync workflow.

## License

Cinch is dual-licensed:

- **AGPL-3.0** — free for personal use, open-source projects, and self-hosted deployments that comply with AGPL terms. See [LICENSE](LICENSE).
- **Commercial License** — for closed-source products, SaaS deployments, or organizations that need a commercial support agreement. See [LICENSE-COMMERCIAL](LICENSE-COMMERCIAL) or contact [jingmuio@gmail.com](mailto:jingmuio@gmail.com).
