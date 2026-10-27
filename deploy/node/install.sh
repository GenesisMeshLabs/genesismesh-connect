#!/usr/bin/env bash
# Install the Genesis Mesh Connect node on a systemd Linux server.
#
#   sudo ./install.sh --from DIR [--require-tpm]
#   sudo ./install.sh --uninstall [--keep-state]
#
# DIR holds genesismesh-connect-node and genesismesh-authority for this
# machine's architecture. The master key is sealed with systemd-creds: to the
# TPM2 and the host key where the machine has a TPM, to the host key alone
# otherwise (--require-tpm refuses that). Nothing here creates a network; run
# `genesismesh-connect init` or `genesismesh-connect restore FILE` afterwards.
set -euo pipefail

prefix=/opt/genesismesh-connect
unit=/etc/systemd/system/genesismesh-connect-node.service
credential=/etc/credstore.encrypted/genesismesh-connect-master-key
command=/usr/local/bin/genesismesh-connect
state=/var/lib/genesismesh-connect
here=$(cd -- "$(dirname -- "$0")" && pwd)

fail() { echo "install: $*" >&2; exit 1; }
[[ $(id -u) == 0 ]] || fail "run as root"
command -v systemd-creds >/dev/null || fail "systemd-creds is required (systemd 250 or newer)"

from="" require_tpm=0 uninstall=0 keep_state=0
while [[ $# -gt 0 ]]; do
  case $1 in
    --from) from=${2:?--from needs a directory}; shift 2 ;;
    --require-tpm) require_tpm=1; shift ;;
    --uninstall) uninstall=1; shift ;;
    --keep-state) keep_state=1; shift ;;
    *) fail "unknown option $1" ;;
  esac
done

if [[ $uninstall == 1 ]]; then
  systemctl disable --now genesismesh-connect-node.service 2>/dev/null || true
  rm -f "$unit" "$command"
  rm -rf "$prefix"
  systemctl daemon-reload
  if [[ $keep_state == 0 ]]; then
    # The sealed records are useless without the credential; remove both.
    rm -rf "$state" "/var/lib/private/genesismesh-connect"
    rm -f "$credential"
    id genesismesh >/dev/null 2>&1 && userdel genesismesh
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

id genesismesh >/dev/null 2>&1 || useradd --system --home-dir "$state" --shell /usr/sbin/nologin genesismesh
install -d -m 0755 "$prefix"
install -m 0755 "$from/genesismesh-connect-node" "$from/genesismesh-authority" "$prefix/"
install -m 0644 "$here/genesismesh-connect-node.service" "$unit"

if [[ ! -f $credential ]]; then
  install -d -m 0700 "$(dirname "$credential")"
  # 32 random bytes, encrypted before they reach the disk.
  head -c 32 /dev/urandom | systemd-creds encrypt --name=connect-master-key --with-key=auto - "$credential"
  chmod 0600 "$credential"
fi

cat >"$command" <<EOF
#!/usr/bin/env bash
# Run a Connect node command as the service user, with its master key.
exec systemd-run --quiet --pipe --wait --collect \\
  -p User=genesismesh -p Group=genesismesh \\
  -p StateDirectory=genesismesh-connect -p StateDirectoryMode=0700 -p UMask=0077 \\
  -p LoadCredentialEncrypted=connect-master-key:$credential \\
  -E CONNECT_SEALED_STORE=$state/sealed \\
  $prefix/genesismesh-connect-node "\$@" --state $state
EOF
chmod 0755 "$command"
systemctl daemon-reload
systemctl enable genesismesh-connect-node.service >/dev/null

if [[ $tpm == yes ]]; then
  echo "Master key sealed to this machine's TPM2 and host key."
else
  echo "No TPM2 found: the master key is sealed to this machine's host key only, which"
  echo "does not protect a copied disk. Prefer a machine with a TPM (Azure Trusted Launch)."
fi
echo "Next: genesismesh-connect init --name \"Home network\"  (or: genesismesh-connect restore FILE)"
echo "Then: systemctl start genesismesh-connect-node, and genesismesh-connect pair"
