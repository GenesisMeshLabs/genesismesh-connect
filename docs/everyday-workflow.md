# Everyday Connect workflow

This is the normal application flow. Keys, authority URLs, transport tickets,
attestation IDs and policy IDs stay inside the native implementation. Technical
controls remain available under Settings → Advanced tools.

## Set up the network computer

On a supported desktop build, choose **Start on this computer**, name the network and computer,
then choose **Create my network**. The bundled Genesis Mesh 1.8.1 runtime uses
the real core initializer and authority routes. End users do not need Python,
a source checkout, WSL or a separately started authority. The authority listens
only on loopback and follows the Connect application's lifetime.

**Use an existing network on this computer** opens a native settings-file
picker. It reads the selected local Genesis Mesh TOML configuration and uses
that authority's root and operator identity. The existing authority must be
running on a numeric loopback address. Connect does not replace existing device
profiles or network roots. Existing technical profiles can still use Advanced.

Managed root, authority and operator key files are protected with account-scoped
Windows DPAPI after initialization. macOS/Linux desktop helpers use the native
credential store through their private pipe to the Rust host. The owner adapter accepts only fixed local
pipe operations; private keys and arbitrary administrative HTTP routes are not
exposed to the web UI or phone. A recovery/backup assistant is still pending;
do not describe this preview as having account recovery or portable backups.

## Add the phone

1. On the computer, choose **Devices → Add device**.
2. Scan the QR with the phone's camera or copy its invitation into **Join a
   network**. Name the phone and choose **Ask to join**.
3. Compare the six-digit code on both devices, then choose **Allow device** on
   the computer. Declining, closing or consuming an invitation invalidates it.
4. Connect enrolls the phone and verifies an authenticated session in both
   directions. No key or transport ticket needs to be copied separately.

The join link expires after five minutes and produces one request. Approval
must arrive within two minutes. The link pins the network root, owner node and
temporary Iroh endpoint, plus a 256-bit secret. The owner proves its certificate
and node key before the client sends the secret. Both proofs bind challenges,
endpoint identities, roles, the Pair ALPN and the local TLS exporter. A name
alone never establishes identity. Invitations are bound to the proved client
node and enrollment still performs the existing authority/SDK verification.

The iPhone generates its own node key. Its private record uses a non-syncing
WhenUnlockedThisDeviceOnly Keychain item; the app container holds an opaque UUID
reference. Windows uses DPAPI. Separate persisted transport keys allow approved
devices to reconnect. Consumer sessions and authority bridges use public Iroh
relays and n0 endpoint address publication/resolution to find the same endpoint
after an address change. Address lookup does not establish Genesis Mesh trust.
The temporary pairing endpoint itself is not published in the address directory.

Keep both apps open and the computer awake. This is a foreground companion app,
not a system-wide VPN, background iPhone service or unattended Windows service.
The current controller supports up to 32 saved devices. Choose one by name in
Devices before browsing or checking a connection. Adding a second device keeps
the first; forgetting a device stops its local connections without revoking its
membership throughout the network. Existing single-device profiles migrate
without replacing their keys. See [platform evidence and limits](cross-platform.md).

## Share and browse

On the computer, choose **Files → Share a folder**, then select the folder with
the native picker. The authority creates a policy and host attestation scoped
to the exact collection and paired node. The phone chooses **Refresh files**,
filters the returned list, and selects a file to open. There are no remote path
fields in the normal UI. **Stop sharing this folder** stops serving it locally;
the stored authority policy/attestation can remain until expiry.

The everyday interface has Files, Devices and Settings, with bottom navigation
on phones. Choose a device by name to browse its files. Technical controls and
error details stay in Settings > Advanced.

Metadata-only catalog pages require their own authenticated proof and
`connect.collection.list` decision. Downloads use disk-backed snapshots and a
fresh `connect.collection.read` decision for each short transfer window. The
policy always receives the **full file size**, never the window size. Signed
receipts and window hashes are verified, and the whole-file SHA-256 must match
before native viewing/export. No local paths or bulk bytes cross frontend IPC.

Current bounds: one selected folder tree, up to 16 subfolder levels, files up to
1 GiB, at most 512 entries scanned per folder, pages of 32, one active transfer,
bounded cache/receipt storage. Links, junctions, unsafe
names and oversized files are omitted; source versions are checked on each
window. Downloads offer progress/cancel, small UTF-8 text previews and OS
view/save actions. Android FileProvider covers only the verified-download cache.
Tap a folder to open it; use the breadcrumbs to return to its parent or the
shared root. Search filters the current folder. Each directory component is
opened through a capability-relative no-follow handle. Directory segments are
bound to the signed browse intent and nested-download token, and the authority
receives the relative file path for any path-based read gates. Durable resume,
uploads and mobile folder sharing remain pending.

Existing 64-KiB permissions stay unchanged. **Share a folder again** and select
the folder to issue a new larger-file permission. Both apps need the new build
for nested browsing: the new Browse ALPN and nested Download v2 have distinct
proof/exporter domains. Legacy flat list/catalog/download remains available for
older clients, including installed build 5.
Mobile viewing, export and large-file physical acceptance are still pending.

Folder permission records currently expire after 30 days. Re-sharing creates
new scoped records. Saved sharing is restored only for the guided consumer flow,
after its authority is rebound; older advanced profiles still reopen unshared.

## Verification boundary

The real-authority integration suite verifies pairing and final mutual session
proofs, remote enrollment, list/read capability separation, bounded pages,
file-version changes, policy denial and authority outage. It runs both device
identities on one host. Windows UI setup uses a disposable network and bundled
runtime. iOS compile/archive/install results and physical Windows/iPhone pairing,
Keychain persistence, browsing and lifecycle tests must be recorded separately
in [two-device acceptance](two-device-acceptance.md).
