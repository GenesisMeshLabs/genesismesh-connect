#!/usr/bin/env bash
# The headless test device (the second_device example) with its own home and a
# throwaway keyring, never the account's own.
# Usage: device.sh <profile> <command> [args...]; join reads <profile>.link.
set -euo pipefail
profile=$1; shift
world="$(dirname "$profile")/world"
mkdir -p -m 700 "$world"/{home,data,config,runtime}
export HOME="$world/home" XDG_DATA_HOME="$world/data" XDG_CONFIG_HOME="$world/config" XDG_RUNTIME_DIR="$world/runtime"
exec dbus-run-session -- bash -c '
  printf connect-journey | gnome-keyring-daemon --unlock --components=secrets >/dev/null 2>&1
  bin=$1; profile=$2; shift 2
  if [ "$1" = join ]; then exec "$bin" "$profile" join "$(tr -d "\r\n" < "$profile.link")" "${2:-Test laptop}"; fi
  exec "$bin" "$profile" "$@"
' _ "${CONNECT_DEVICE:?Set CONNECT_DEVICE to the second_device example}" "$profile" "$@"
