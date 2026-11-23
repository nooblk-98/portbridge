#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
port=${1:?port}
state=${FAKE_STATE:?FAKE_STATE must point at the harness state directory}
mkdir -p "$state"
rm -rf "$state/data"
cp -R "$repo/parity/seed-data" "$state/data"
: >"$state/commands.log"
: >"$state/restore.log"
rm -f "$state/genkey.count"
export PATH="$repo/parity/fakebin:$PATH"
export APP_HOST=127.0.0.1
export APP_PORT="$port"
export DATA_DIR="$state/data"
export WG_CONFIG_PATH="$state/data/wg0.conf"
export WG_INTERFACE=wg0
export WG_NETWORK=10.8.0.0/24
export WG_HOST=203.0.113.10
export ADMIN_PASSWORD=parity-password-123
export SEED_FORWARDING=0
exec "$repo/target/release/portbridge"
