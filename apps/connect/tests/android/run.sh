#!/usr/bin/env bash
# Run the Android journey: a headless Connect node on this machine runs the
# network in a disposable world (its own state, sealed store and master key),
# the app runs on an emulator that adb already reaches, and the second_device
# example, through ../desktop/device.sh, plays a laptop that receives files.
# Usage: run.sh <debug test APK> <node binary> <second_device binary> <authority binary>
set -euo pipefail
here=$(cd -- "$(dirname -- "$0")" && pwd)
apk=$(realpath "$1"); node_bin=$(realpath "$2"); device=$(realpath "$3"); authority=$(realpath "$4")
world=$(mktemp -d)
out=${CONNECT_OUT:-$world/out}
mkdir -p "$out"
# The node runs in its own process group; stopping the group stops the node
# and the authority it started, and nothing else.
trap 'kill -- -"${server:-0}" 2>/dev/null || true; sleep 1; cp "$world/node.log" "$out/" 2>/dev/null || true; rm -rf "$world"' EXIT
mkdir -m 700 "$world/credentials"
head -c 32 /dev/urandom > "$world/credentials/connect-master-key"
export CONNECT_SEALED_STORE="$world/store" CREDENTIALS_DIRECTORY="$world/credentials"
"$node_bin" init --name "Journey home" --state "$world/node" --authority "$authority"
setsid "$node_bin" run --state "$world/node" --authority "$authority" > "$world/node.log" 2>&1 &
server=$!
for _ in $(seq 1 120); do [ -S "$world/node/control.sock" ] && break; sleep 0.5; done
[ -S "$world/node/control.sock" ] || { cat "$world/node.log"; echo "The node did not start"; exit 1; }
adb install -r -t "$apk"
CONNECT_DEVICE="$device" CONNECT_DEVICE_SCRIPT="$here/../desktop/device.sh" \
  CONNECT_WORLD="$world" CONNECT_OUT="$out" node "$here/journey.mjs"
