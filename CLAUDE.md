## Project Overview

Cinch Relay is a self-hostable clipboard relay server. It receives
clipboard clips pushed by the Cinch CLI and delivers them in real time
to connected devices via WebSocket. Clients authenticate with tokens;
persistence uses Postgres (clip rows) plus a local media store on disk.

### Architecture

- **cmd/relay/** — Entry point. Wires together store, hub, and HTTP
  handler. Reads `PORT` and `DATABASE_URL` env vars.
- **internal/relay/** — Server-side logic:
  - `store.go` — Postgres store (clips, devices, auth tokens, key
    bundles).
  - `hub.go` — In-memory WebSocket hub. Broadcasts new clips to
    subscribed devices; also fans out Connect-RPC events.
  - `handler.go` — Legacy HTTP routes (`/v1/clips`, `/v1/stream`,
    `/health`, CORS).
  - `connect_*.go` — Connect-RPC service implementations (auth, clips,
    devices, event stream).
- **internal/protocol/** — Hand-written `WSMessage` envelope plus the
  HTTP-only demo/auth-status DTOs that aren't part of the shared proto
  schema.
- **internal/wire_test/** — Cross-language wire-format gate
  (`//go:embed testdata/wire-vectors.json`). Round-trips both the
  cinch-core proto types and the local `WSMessage` envelope.

### Wire types

All shared DTOs (`Clip`, `Device`, `PushClipRequest`, etc.) come from
[`cinchcli/cinch-core`](https://github.com/cinchcli/cinch-core), which
ships generated Go bindings as a regular Go module:

```go
import cinchv1 "github.com/cinchcli/cinch-core/go/cinch/v1"
import "github.com/cinchcli/cinch-core/go/cinch/v1/cinchv1connect"
```

Wire changes flow PR → cinch-core → publish + tag → `make
update-cinch-core REV=v0.1.x` here. There is no relay-side proto
codegen anymore.

### Dependencies

- `github.com/cinchcli/cinch-core` — wire schema and generated Go bindings.
- `connectrpc.com/connect` — Connect-RPC framework.
- `google.golang.org/protobuf` — Protocol Buffers runtime.
- `github.com/gorilla/websocket` — WebSocket upgrade for the legacy
  `/v1/stream` endpoint.

### Build & Run

```bash
make build                              # → dist/relay
make test                               # go test ./... -v -race -count=1
make lint                               # go vet ./...
make update-cinch-core REV=v0.1.x       # bump the cinch-core go.mod entry
make docker-build                       # docker build -t ghcr.io/cinchcli/relay:latest .
```

Direct run:

```bash
go run ./cmd/relay --port 8080
```

Environment variables: `PORT` (default `8080`), `DATABASE_URL` (Postgres
DSN), `RELAY_REGION` (optional).

### Module

```
module github.com/cinchcli/relay
```

The previously separate `github.com/cinchcli/protocol` Go module was
folded into `internal/protocol/` (WSMessage + HTTP-only DTOs). The
proto-generated types that used to live in-tree under
`internal/gen/cinch/v1/` were extracted into `cinchcli/cinch-core` and
are now imported as `github.com/cinchcli/cinch-core/go/cinch/v1`.

### URLs

- **Hosted relay API:** `api.cinchcli.com`
- **Docker image:** `ghcr.io/cinchcli/relay`
- **Docs:** `cinchcli.com/docs`

### Communication

All code comments, commit messages, PR descriptions, and documentation
must be written in English.
