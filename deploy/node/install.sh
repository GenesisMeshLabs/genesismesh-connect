#!/usr/bin/env bash
# Install the Genesis Mesh Connect node on a systemd Linux server.
#
#   sudo ./install.sh --from DIR [--require-tpm]
#   sudo ./install.sh --uninstall (--keep-state | --yes)
#
# DIR holds genesismesh-connect-node and genesismesh-authority for this
# machine's architecture. The master key is sealed with systemd-creds: to the
# TPM2 (without a PCR policy, so firmware updates cannot lock it) and the host
# key where the machine has a TPM, to the host key alone otherwise; with
# --require-tpm, a machine without a TPM is refused. Nothing here creates a
# network; run `genesismesh-connect init` or `genesismesh-connect restore FILE`.
set -euo pipefail

user=genesismesh-connect
prefix=/opt/genesismesh-connect
unit=/etc/systemd/system/genesismesh-connect-node.service
credential=/etc/credstore.encrypted/genesismesh-connect-master-key
command=/usr/local/bin/genesismesh-connect
state=/var/lib/genesismesh-connect
here=$(cd -- "$(dirname -- "$0")" && pwd)

fail() { echo "install: $*" >&2; exit 1; }
[[ $(id -u) == 0 ]] || fail "run as root"
command -v systemd-creds >/dev/null || fail "systemd-creds is required (systemd 250 or newer)"

# Only a user this script created (its home is the node's state) is ours.
ours() { [[ $(getent passwd "$user" | cut -d: -f6) == "$state" ]]; }

from="" require_tpm=0 uninstall=0 keep_state=0 yes=0
while [[ $# -gt 0 ]]; do
  case $1 in
    --from) from=${2:?--from needs a directory}; shift 2 ;;
    --require-tpm) require_tpm=1; shift ;;
    --uninstall) uninstall=1; shift ;;
    --keep-state) keep_state=1; shift ;;
    --yes) yes=1; shift ;;
    *) fail "unknown option $1" ;;
  esac
done

if [[ $uninstall == 1 ]]; then
  [[ $keep_state == 1 || $yes == 1 ]] || fail \
    "uninstalling deletes the network's keys for good; add --yes, or --keep-state to keep them"
  systemctl disable --now genesismesh-connect-node.service 2>/dev/null || true
  rm -f "$unit" "$command"
  rm -rf "$prefix"
  systemctl daemon-reload
  if [[ $keep_state == 0 ]]; then
    # The sealed records are useless without the credential; remove both.
    rm -rf "$state"
    rm -f "$credential"
    if id "$user" >/dev/null 2>&1 && ours; then userdel "$user"; fi
  fi
  echo "Genesis Mesh Connect node removed."
  exit 0
fi

[[ -n $from ]] || fail "give --from DIR with genesismesh-connect-node and genesismesh-authority"
for binary in genesismesh-connect-node genesismesh-authority; do
  [[ -f $from/$binary ]] || fail "missing $from/$binary"
done

tpm=no
systemd-creds has-tpm2 >/dev/null 2>&1 && tpm=yes
[[ $require_tpm == 1 && $tpm == no ]] && fail "this machine has no usable TPM2; on Azure, use a Trusted Launch VM"

network=no
[[ -f $state/network-owner/owner.json ]] && network=yes
# A new key cannot open records sealed under the lost one.
[[ $network == yes && ! -f $credential ]] && fail \
  "this server has a network but its master key ($credential) is missing; bring the network back from a recovery file: --uninstall --yes, install again, then restore"

if id "$user" >/dev/null 2>&1; then
  ours || fail "a user named $user already exists and is not this node's"
else
  useradd --system --user-group --home-dir "$state" --no-create-home --shell /usr/sbin/nologin "$user"
fi
install -d -m 0755 "$prefix"
install -m 0755 "$from/genesismesh-connect-node" "$from/genesismesh-authority" "$prefix/"
install -m 0644 "$here/genesismesh-connect-node.service" "$unit"

new_key=0
if [[ ! -f $credential ]]; then
  new_key=1
  install -d -m 0700 "$(dirname "$credential")"
  if [[ $tpm == yes ]]; then
    keying=(--with-key=host+tpm2 --tpm2-pcrs=)
  else
    keying=(--with-key=host)
  fi
  # 32 random bytes, encrypted before they reach the disk.
  head -c 32 /dev/urandom | systemd-creds encrypt --name=connect-master-key "${keying[@]}" - "$credential"
  chmod 0600 "$credential"
fi

cat >"$command" <<'EOF'
#!/usr/bin/env bash
# Run a Connect node command as the service user. Only init and restore
# receive the master key; the service itself is managed with systemctl.
set -euo pipefail
case ${1:-} in
  run) echo "Start the node with: systemctl start genesismesh-connect-node" >&2; exit 1 ;;
  init|restore) key=(-p LoadCredentialEncrypted=connect-master-key:__CREDENTIAL__ -E CONNECT_SEALED_STORE=__STATE__/sealed) ;;
  *) key=() ;;
esac
# systemd expands $VAR in command lines; keep every argument literal.
args=()
for arg in "$@"; do args+=("${arg//\$/\$\$}"); done
exec systemd-run --quiet --pipe --wait --collect \
  -p User=__USER__ -p Group=__USER__ \
  -p StateDirectory=genesismesh-connect -p StateDirectoryMode=0700 -p UMask=0077 \
  "${key[@]}" \
  __PREFIX__/genesismesh-connect-node "${args[@]}" --state __STATE__
EOF
sed -i "s|__CREDENTIAL__|$credential|g; s|__STATE__|$state|g; s|__USER__|$user|g; s|__PREFIX__|$prefix|g" "$command"
chmod 0755 "$command"
systemctl daemon-reload
systemctl enable genesismesh-connect-node.service >/dev/null
# An upgrade takes effect at once; a stopped node stays stopped.
was_running=no
systemctl is-active --quiet genesismesh-connect-node.service && was_running=yes
systemctl try-restart genesismesh-connect-node.service

if [[ $new_key == 0 ]]; then
  echo "Kept the existing master key."
elif [[ $tpm == yes ]]; then
  echo "Master key sealed to this machine's TPM2 and host key."
else
  echo "No TPM2 found: the master key is sealed to this machine's host key only, which"
  echo "does not protect a copied disk. Prefer a machine with a TPM (Azure Trusted Launch)."
fi
if [[ $network == no ]]; then
  echo "Next: genesismesh-connect init --name \"Home network\"  (or: genesismesh-connect restore FILE)"
  echo "Then: systemctl start genesismesh-connect-node, and genesismesh-connect pair"
elif [[ $was_running == no ]]; then
  echo "Upgraded. The node is not running; start it with: systemctl start genesismesh-connect-node"
else
  # The unit counts as started once forked: give it time to fail.
  pid=$(systemctl show -p MainPID --value genesismesh-connect-node.service)
  sleep 5
  systemctl is-active --quiet genesismesh-connect-node.service \
    && [[ $(systemctl show -p MainPID --value genesismesh-connect-node.service) == "$pid" ]] \
    || fail "the node did not stay up after the upgrade; see: journalctl -u genesismesh-connect-node"
  echo "Upgraded. The node restarted with the new programs."
fi
