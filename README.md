# Cinch Relay

Self-hostable clipboard relay server for [Cinch](https://cinchcli.com) — the remote clipboard tool for developers.

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
    restart: unless-stopped

volumes:
  relay-data:
```

Save as `docker-compose.yml` and run:

```bash
docker compose up -d
```

Then point the CLI at your relay:

```bash
cinch auth pair --relay http://your-server:8080
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | TCP port the server listens on |
| `DB_PATH` | `cinch.db` | Path to the SQLite database file |
| `RELAY_REGION` | _(unset)_ | Optional region label returned in health responses |

## API Overview

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check — returns `{"ok":true}` |
| `POST` | `/auth/login` | Create anonymous account |
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

Requires Go 1.26+. No CGO needed for the relay binary (`CGO_ENABLED=0`).

## Documentation

Full docs at [cinchcli.com/docs](https://cinchcli.com/docs).

## Related Repos

- [cinchcli/cinch](https://github.com/cinchcli/cinch) — CLI client (`cinch push` / `pull` / `auth`)
- [cinchcli/protocol](https://github.com/cinchcli/protocol) — Shared Go types (auth tokens, clip encoding, WebSocket framing)
- [cinchcli/desktop](https://github.com/cinchcli/desktop) — Tauri v2 desktop app (macOS)

## License

AGPL-3.0 — see [LICENSE](LICENSE).
