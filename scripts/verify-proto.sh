#!/usr/bin/env bash
# Verifies the vendored .proto files match the upstream cinch monorepo.
# Fails with diff output if drift is detected.
#
# Usage:
#   ./scripts/verify-proto.sh                    # compare against ../../cinch/main (sibling checkout)
#   UPSTREAM=/path/to/cinch ./scripts/verify-proto.sh

set -euo pipefail

cd "$(dirname "$0")/.."

UPSTREAM="${UPSTREAM:-../../cinch/main}"
UPSTREAM_PROTO_DIR="$UPSTREAM/crates/client-core/proto/cinch/v1"
LOCAL_PROTO_DIR="proto/cinch/v1"

if [ ! -d "$UPSTREAM_PROTO_DIR" ]; then
  echo "Upstream proto dir not found: $UPSTREAM_PROTO_DIR" >&2
  echo "Set UPSTREAM=/path/to/cinch monorepo checkout" >&2
  exit 1
fi

drift=0

# A .proto is "in sync" if its only diff from upstream is the go_package option.
# That option intentionally differs (monorepo uses cinchcli/cinch path, relay
# uses cinchcli/relay/internal path). All other content must match byte-for-byte.
strip_go_package() {
  grep -v '^option go_package' "$1"
}

for upstream_file in "$UPSTREAM_PROTO_DIR"/*.proto; do
  base=$(basename "$upstream_file")
  local_file="$LOCAL_PROTO_DIR/$base"
  if [ ! -f "$local_file" ]; then
    echo "MISSING: $local_file (exists upstream)" >&2
    drift=1
    continue
  fi
  if ! diff <(strip_go_package "$upstream_file") <(strip_go_package "$local_file") >/dev/null; then
    echo "DRIFT in $base (excluding go_package line):" >&2
    diff <(strip_go_package "$upstream_file") <(strip_go_package "$local_file") >&2 || true
    drift=1
  fi
done

for local_file in "$LOCAL_PROTO_DIR"/*.proto; do
  base=$(basename "$local_file")
  if [ ! -f "$UPSTREAM_PROTO_DIR/$base" ]; then
    echo "EXTRA: $local_file (not in upstream)" >&2
    drift=1
  fi
done

if [ "$drift" != "0" ]; then
  echo "" >&2
  echo "Proto drift detected. Run scripts/sync-proto-from-monorepo.sh to update." >&2
  exit 1
fi

echo "Proto vendor is in sync with upstream."
