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
  vendored proto types and the local `WSMessage` envelope.

### Wire types

All shared DTOs (`Clip`, `Device`, `PushClipRequest`, etc.) are defined
in `.proto` files **vendored from the [cinchcli/cinch monorepo](https://github.com/cinchcli/cinch)**.
The canonical source of truth lives at `crates/client-core/proto/cinch/v1/`
in that repo. The vendored copies sit at `proto/cinch/v1/` here, and Go
bindings are generated locally into `internal/cinchv1/`:

```go
import cinchv1 "github.com/cinchcli/relay/internal/cinchv1"
import "github.com/cinchcli/relay/internal/cinchv1/cinchv1connect"
```

Wire changes flow:

1. PR against `cinchcli/cinch` editing `crates/client-core/proto/cinch/v1/*.proto`.
2. The cinch monorepo's `proto-sync-relay.yml` workflow auto-opens a PR
   here updating `proto/cinch/v1/` and regenerated `internal/cinchv1/`.
3. CI gate (`make verify-proto`) enforces byte-equality between the
   vendored copies and upstream.

### Dependencies

- `connectrpc.com/connect` — Connect-RPC framework.
- `google.golang.org/protobuf` — Protocol Buffers runtime.
- `github.com/gorilla/websocket` — WebSocket upgrade for the legacy
  `/v1/stream` endpoint.

### Build & Run

```bash
make build                                                # → dist/relay
make test                                                 # go test ./... -v -race -count=1
make lint                                                 # go vet ./...
make generate                                             # regenerate internal/cinchv1/ from proto/
make verify-proto                                         # gate: proto/ matches ../../cinch/main
UPSTREAM=/path/to/cinch make verify-proto                 # custom upstream path
make docker-build                                         # docker build -t ghcr.io/cinchcli/relay:latest .
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
proto-generated types that used to live under `internal/gen/cinch/v1/`
moved to `internal/cinchv1/`, generated from the vendored `.proto` files
at `proto/cinch/v1/`. There is no external Go module dependency for the
wire schema — the source of truth is the cinch monorepo, kept in sync
via the `proto-sync-relay.yml` auto-PR workflow.

### URLs

- **Hosted relay API:** `api.cinchcli.com`
- **Docker image:** `ghcr.io/cinchcli/relay`
- **Docs:** `cinchcli.com/docs`

### Communication

All code comments, commit messages, PR descriptions, and documentation
must be written in English.
