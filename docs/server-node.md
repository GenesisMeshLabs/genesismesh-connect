# Connect on a server

A Linux server can be the network computer, so the network stays available
when your desktop is off. It runs the same Genesis Mesh authority and the same
device protocols as the desktop app, without a window: `genesismesh-connect-node`
under systemd, with a few terminal commands for the owner.

## What it needs

- Linux with systemd 250 or newer (`systemd-creds`), x86-64 or arm64, and the
  `genesismesh-connect-node` and `genesismesh-authority` builds for it.
- Ideally a TPM 2.0. On Azure, a Trusted Launch VM provides a virtual TPM.
  Without one, the master key is sealed to the machine's host key only, which
  does not protect a copied disk.

## Install

```sh
sudo ./deploy/node/install.sh --from DIR      # add --require-tpm to insist on a TPM
sudo genesismesh-connect init --name "Home network"
sudo systemctl start genesismesh-connect-node
```

`install.sh` creates the `genesismesh-connect` service user, installs both
programs in `/opt/genesismesh-connect`, and seals a new 32-byte master key with
`systemd-creds` into `/etc/credstore.encrypted/`: to the TPM2 and host key
where a TPM is present, to the host key otherwise. It installs and enables the
`genesismesh-connect-node` unit (which waits until a network exists) and the
`genesismesh-connect` command. It never creates a network. Running it again
upgrades the programs and restarts a running node.

The TPM sealing uses no PCR policy, so a firmware or Secure Boot update cannot
lock the key away; the key still opens only on that machine's TPM, so a copied
disk is useless. Losing the TPM or the disk loses the network unless you have a
recovery file, so write one right after `init`.

At start, systemd decrypts the master key into the service's private
credential directory (`LoadCredentialEncrypted=`); it never reaches disk
unencrypted (like any process memory, it could reach swap; use encrypted or no
swap). Owner keys and the server's device identity are kept as records in
`/var/lib/genesismesh-connect/sealed`, each encrypted under that key with
AES-256-GCM. The node refuses to run without its sealed store, and there is no
plaintext fallback. The unit runs as `genesismesh-connect` with no
capabilities, a read-only system, private `/tmp` and devices, and only the
network families it needs. One node process owns the state at a time.

`genesismesh-connect` runs a node command as the service user through
`systemd-run`; only `init` and `restore` receive the master key, and `run` is
left to systemd. The owner never handles the master key.

## Move a desktop network onto the server

Create a recovery file on the desktop (Settings → Recovery), copy it to the
server somewhere the `genesismesh-connect` user can read, then give its full
path:

```sh
sudo genesismesh-connect restore /tmp/home.gmrecovery    # asks for the recovery key
sudo systemctl start genesismesh-connect-node
```

The server becomes the same network computer: paired devices keep trusting it
and reconnect when they next reach it. Delete the copy you placed in `/tmp`,
and stop using the desktop as the network computer; see the
[recovery file notes](everyday-workflow.md#keep-a-recovery-file).

## Everyday commands

```sh
sudo genesismesh-connect status
sudo genesismesh-connect pair --name "Home server"   # prints an invitation, then asks to approve
sudo genesismesh-connect connection public            # or: private
sudo genesismesh-connect recovery home.gmrecovery
```

`pair` prints a join invitation: on the device, open Connect, choose **Join a
network** and paste it. When the device asks to join, `pair` shows its name and
six-digit code; compare it with the device and answer `y` to allow it. These
commands reach the running service through a control socket in its state
directory that only the service user can open; they are never exposed to the
network. Approving from the phone instead of a terminal comes with Requests.

`recovery NAME` writes `/var/lib/genesismesh-connect/recovery/NAME` and shows
its key once; it never replaces an existing file. Copy the file somewhere safe,
apart from the key, then delete the server's copy.

## Limits

- **Private mode** works for devices on the server's own network. Devices away
  from it need public relays until the server runs its own relay.
- **Files:** the server shares no folders yet; files stay on your devices.
- **Unlocking:** a machine without a TPM gets no boot-passphrase option yet;
  it relies on the host key.
- **Tested:** the node runs under systemd in WSL Ubuntu 24.04, without a TPM:
  install, init, service start, status, connection, recovery file, restart and
  uninstall. Integration tests cover pairing, enrollment and reconnecting after
  a restart, and moving a desktop network onto the node: a phone paired with the
  desktop reaches the node from its saved addresses after the restore, without
  pairing again. Not yet tested on a cloud VM with a TPM.

Remove everything with `sudo ./deploy/node/install.sh --uninstall --yes`, which
deletes the network's keys for good, or keep the state and master key with
`--uninstall --keep-state`.
