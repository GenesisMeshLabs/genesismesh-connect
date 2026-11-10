#!/usr/bin/env bash
# Run the desktop journey against the real Linux app in a disposable world:
# its own home, data and config directories, a private D-Bus session with a
# throwaway keyring, a virtual display, and tauri-driver with WebKitWebDriver.
# Usage: run.sh <app binary> <second_device binary> [WebKitWebDriver]
set -euo pipefail
here=$(cd -- "$(dirname -- "$0")" && pwd)
app=$(realpath "$1"); device=$(realpath "$2")
native=${3:-$(command -v WebKitWebDriver)}
world=$(mktemp -d)
# The driver runs in its own process group; stopping the group stops the
# display, the driver, the app and the authority it started, and nothing else.
trap 'kill -- -"${driver:-0}" 2>/dev/null || true; sleep 1; rm -rf "$world"' EXIT
mkdir -m 700 "$world"/{home,data,config,cache,runtime}
# The file the app sends: its debug test build takes it instead of a picker.
# The journey writes it; the app, started by the driver, inherits the name.
export CONNECT_TEST_PICK="$world/send/journey.bin"
HOME="$world/home" XDG_DATA_HOME="$world/data" XDG_CONFIG_HOME="$world/config"   XDG_CACHE_HOME="$world/cache" XDG_RUNTIME_DIR="$world/runtime" WAYLAND_DISPLAY= DISPLAY=   setsid dbus-run-session -- bash -c '
    printf connect-journey | gnome-keyring-daemon --unlock --components=secrets >/dev/null 2>&1
    exec xvfb-run -a -s "-screen 0 1280x900x24" tauri-driver --port 4444 --native-driver "$1"
  ' _ "$native" &
driver=$!
for _ in $(seq 1 60); do curl -sf localhost:4444/status >/dev/null && break; sleep 0.5; done
CONNECT_APP="$app" CONNECT_DEVICE="$device" CONNECT_DEVICE_SCRIPT="$here/device.sh" \
  CONNECT_WORLD="$world" CONNECT_OUT="${CONNECT_OUT:-$world/out}" node "$here/journey.mjs"
