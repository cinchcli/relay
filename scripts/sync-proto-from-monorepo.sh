#!/usr/bin/env bash
# Syncs .proto files from the cinch monorepo and regenerates Go code.
#
# Usage:
#   ./scripts/sync-proto-from-monorepo.sh
#   UPSTREAM=/path/to/cinch ./scripts/sync-proto-from-monorepo.sh

set -euo pipefail

cd "$(dirname "$0")/.."

UPSTREAM="${UPSTREAM:-../../cinch/main}"
UPSTREAM_PROTO_DIR="$UPSTREAM/crates/client-core/proto/cinch/v1"

if [ ! -d "$UPSTREAM_PROTO_DIR" ]; then
  echo "Upstream proto dir not found: $UPSTREAM_PROTO_DIR" >&2
  exit 1
fi

cp "$UPSTREAM_PROTO_DIR"/*.proto proto/cinch/v1/

# Fix go_package — upstream points at cinchcli/cinch, relay needs its own path.
for f in proto/cinch/v1/*.proto; do
  sed 's|github.com/cinchcli/cinch/go/cinch/v1|github.com/cinchcli/relay/internal/cinchv1|g' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
done

make generate

echo "Proto sync complete. Run 'make test' to verify."
