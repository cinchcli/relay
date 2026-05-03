## Project Overview

Cinch Relay is a self-hostable clipboard relay server. It receives clipboard clips pushed by the Cinch CLI and delivers them in real time to connected devices via WebSocket. Clients authenticate with tokens; all persistence uses SQLite.

### Architecture

- **cmd/relay/** — Entry point. Wires together store, hub, and HTTP handler. Reads `PORT` and `DB_PATH` env vars.
- **internal/relay/** — Server-side logic:
  - `store.go` — SQLite store (clips, devices, auth tokens, key bundles). Uses `modernc.org/sqlite` (no CGO).
  - `hub.go` — In-memory WebSocket hub. Broadcasts new clips to subscribed devices.
  - `handler.go` — Legacy HTTP routes (`/v1/clips`, `/v1/stream`, `/health`, CORS).
  - `connect_*.go` — Connect-RPC service implementations (auth, clips, devices, event stream).
- **internal/gen/cinch/v1/** — Generated protobuf + Connect-RPC Go code. Do not edit by hand; regenerate with `make generate`.
- **proto/cinch/v1/** — Protobuf service and message definitions.

### Dependencies

- `connectrpc.com/connect` — Connect-RPC framework.
- `modernc.org/sqlite` — Pure-Go SQLite driver (CGO_ENABLED=0 compatible).
- `google.golang.org/protobuf` — Protocol Buffers runtime.
- `github.com/gorilla/websocket` — WebSocket upgrade for the legacy `/v1/stream` endpoint.

The previously separate `github.com/cinchcli/protocol` Go module has been
folded in: WSMessage and the demo/auth-status DTOs now live at
`internal/protocol/`, and every other shared type comes from
`internal/gen/cinch/v1/` (generated from `proto/cinch/v1/*.proto`).

### Build & Run

```bash
make build          # builds relay binary to dist/relay
make test           # go test ./... -race
make generate       # buf generate + go mod tidy
make lint           # buf lint + go vet
make docker-build   # docker build -t ghcr.io/cinchcli/relay:latest .
```

Direct run:

```bash
go run ./cmd/relay --port 8080
```

Environment variables: `PORT` (default `8080`), `DB_PATH` (default `cinch.db`), `RELAY_REGION` (optional).

### Module

```
module github.com/cinchcli/relay
```

This module no longer depends on the external `github.com/cinchcli/protocol`
repo. All formerly-shared types live in-tree: `internal/protocol/` (the WS
envelope and HTTP-only DTOs) and `internal/gen/cinch/v1/` (everything
covered by `proto/cinch/v1/*.proto`).

### URLs

- **Hosted relay API:** `api.cinchcli.com`
- **Docker image:** `ghcr.io/cinchcli/relay`
- **Docs:** `cinchcli.com/docs`

### Communication

All code comments, commit messages, PR descriptions, and documentation must be written in English.
