# Cinch Relay

Self-hostable relay server for [Cinch](https://cinchcli.com) — Your clipboard. Across every machine.

The relay receives clipboard clips pushed by the CLI (`cinch push`) and delivers them in real time to connected devices via WebSocket. It is the only component you need to self-host; the CLI and desktop app work with any relay URL.

## Quick Start (Docker)

```bash
docker run -p 8080:8080 ghcr.io/cinchcli/relay
```

Data is stored in-memory by default. To persist across restarts, mount a volume:

```bash
docker run -p 8080:8080 \
  -v cinch-data:/data \
  -e DB_PATH=/data/cinch.db \
  ghcr.io/cinchcli/relay
```

Then point the CLI at your relay:

```bash
cinch auth login --relay http://your-server:8080
```

## Docker Compose

```yaml
services:
  relay:
    image: ghcr.io/cinchcli/relay:latest
    ports:
      - "8080:8080"
    volumes:
      - relay-data:/data
    environment:
      - PORT=8080
      - DB_PATH=/data/cinch.db
      - BASE_URL=https://relay.example.com
    restart: unless-stopped

volumes:
  relay-data:
```

Save as `docker-compose.yml` and run:

```bash
docker compose up -d
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | TCP port the server listens on |
| `DB_PATH` | `cinch.db` | Path to the SQLite database file |
| `BASE_URL` | _(unset)_ | Public HTTPS root of the relay, e.g. `https://relay.example.com`. Required for OAuth sign-in. |
| `RELAY_REGION` | _(unset)_ | Optional region label returned in health responses |
| `CORS_ORIGINS` | _(unset)_ | Comma-separated extra allowed CORS origins |
| `GITHUB_CLIENT_ID` | _(unset)_ | GitHub OAuth App client ID (enables GitHub sign-in) |
| `GITHUB_CLIENT_SECRET` | _(unset)_ | GitHub OAuth App client secret |
| `GOOGLE_CLIENT_ID` | _(unset)_ | Google OAuth client ID (enables Google sign-in) |
| `GOOGLE_CLIENT_SECRET` | _(unset)_ | Google OAuth client secret |

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

See [`DEPLOY.md`](DEPLOY.md) for a full production runbook (OCI, Cloudflare proxy, systemd).

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

## Related Repos

- [cinchcli/cinch](https://github.com/cinchcli/cinch) — CLI client (`cinch push` / `pull` / `auth`)
- [cinchcli/desktop](https://github.com/cinchcli/desktop) — Tauri v2 desktop app (macOS)

The wire-format DTOs (`Clip`, `Device`, push/pull/auth requests, etc.) are
defined in `proto/cinch/v1/*.proto` here; the Rust CLI and desktop generate
their types from this same schema via the `proto-cinch` crate in
[cinchcli/cinch](https://github.com/cinchcli/cinch).

## License

Cinch is dual-licensed:

- **AGPL-3.0** — free for personal use, open-source projects, and self-hosted deployments that comply with AGPL terms. See [LICENSE](LICENSE).
- **Commercial License** — for closed-source products, SaaS deployments, or organizations that need a commercial support agreement. See [LICENSE-COMMERCIAL](LICENSE-COMMERCIAL) or contact [jingmuio@gmail.com](mailto:jingmuio@gmail.com).
