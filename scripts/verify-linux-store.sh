#!/usr/bin/env bash
# A private D-Bus session and disposable keyring; never unlock or modify the
# user's login keyring. Rust dependencies must already be available.
set -euo pipefail
connect_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
if [[ ${CONNECT_PRIVATE_KEYRING_SESSION:-} != 1 ]]; then
  connect_fixture=$(mktemp -d)
  trap 'rm -rf -- "$connect_fixture"' EXIT
  mkdir -m 700 "$connect_fixture/runtime" "$connect_fixture/data" "$connect_fixture/config"
  env CONNECT_PRIVATE_KEYRING_SESSION=1 XDG_RUNTIME_DIR="$connect_fixture/runtime" XDG_DATA_HOME="$connect_fixture/data" XDG_CONFIG_HOME="$connect_fixture/config" dbus-run-session -- bash "$0" "$@"
  exit
fi
cd -- "$connect_root"
python3 -c 'import secrets; print(secrets.token_urlsafe(32),end="")' | gnome-keyring-daemon --unlock --components=secrets > /dev/null
if [[ $# -gt 0 ]]; then
  cargo "$@"
else
  cargo test -p connect-core --lib native_store_persists_private_identity --locked -- --ignored --nocapture
fi
