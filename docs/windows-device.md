# Windows device development

The **Device** tab enrolls a Windows desktop, exchanges authenticated messages
and reads small files from an authorized collection over the local network.
See [protected-read setup](protected-read.md) for the additional edge invite,
host attestation and live policy. There is no VPN or background Windows service yet.
**Transport test** remains an unauthenticated Iroh diagnostic.

## Enroll and connect

1. For a local authority, run a Genesis Mesh Network Authority using its native Windows setup.
   Keep its operator keys and admin interface separate from Connect.
2. Choose **Authority runs on this desktop**. Enter its numeric loopback address (for example
   `http://127.0.0.1:9443`), network name and root public key obtained directly from
   the operator. Check these before selecting **Prepare device**; this creates a
   durable profile and there is no reset/change-network UI yet.
3. Give the displayed **Node public key** to the operator. Request an invite
   bound to that exact key, paste the invite and select **Enroll device**.
   The input clears on submission. Operator credentials never enter Connect.
4. Enter the other enrolled device's node public key, confirmed directly with its
   owner. Both devices must trust the same network/root and choose each other's
   keys. Select **Start session**, then exchange the displayed session tickets.
5. Paste the peer ticket and send an authenticated message. A reply is confirmed
   only after certificate verification and proof of the expected node key over
   that Iroh connection. A ticket by itself grants no permission.

For a device using another desktop, choose **Use another desktop** and follow the
[remote enrollment flow](remote-enrollment.md). That profile has no local HTTP
authority configured. The HTTP adapter remains restricted to loopback. Tests use
separate identities on one Windows host with a disposable authority; physical
device and off-LAN results remain pending.

## Use the desktop authority bridge

1. On the desktop with the local authority, select the enrolled client's node
   public key and start a session. This starts the diagnostic endpoint and a
   restricted authority listener for that selected client.
2. Share **This desktop's authority ticket** and the desktop's node public key
   with that client. The authority ticket is different from a session ticket.
3. On an already-enrolled client, stop its session, expand **Authority
   connection**, enter the desktop key and authority ticket, and select **Use
   desktop bridge**. A successful mutual authentication and renewal must complete
   before the new route and certificate are saved together.
4. Start the client's session normally. Its trust refresh and renewal now use
   Iroh. Failed bridge calls suspend the session; Connect never falls back to the
   local HTTP origin automatically. **Use local authority** explicitly switches
   back while stopped.

The control channel forwards public trust records and renewal for the exact
authenticated credential. A separate enrollment channel forwards a device-signed
join after host/client proof and an operator-issued invitation. No administrative
operation is exposed. Stops and app shutdown close both host listeners. Host
restart requires exchanging its new authority ticket; a client keeps the saved
route and must explicitly update it while stopped. Clients using a bridge do
not host another bridge. See the [protocol and test details](authority-bridge.md).

While a session endpoint runs, Connect refreshes trust every 30 seconds and renews
its certificate at four minutes of age. A failed refresh suspends diagnostics.
**Refresh trust** retries; **Stop** closes the endpoint. Reopening the app restores
the device identity but leaves sessions stopped. Restarting a session creates a
new transport ticket; trust refresh preserves the current transport identity.
See the [freshness policy and revocation limits](authority-spike.md#freshness-and-live-invalidation).

## Storage and recovery

The profile lives in the OS application-data directory for
`org.genesismesh.connect`, under `device/`. `device.bin` contains the node seed,
certificate, trust pin and configuration encrypted with user-scoped Windows
DPAPI. Sharing hosts also store their executor seed and edge registration in the
encrypted vault. A selected bridge route persists in the same record. Only public
status reaches the frontend. `trust.json` contains public
verification checkpoints protected against concurrent writers and accidental
rollback through ordinary refresh. Both files are atomically replaced.

DPAPI protects stored data for the Windows account; it does not protect against
malicious software already running as that user. Private buffers are zeroized
where owned by the vault. There is no plaintext key export, fallback, migration
or backup/recovery workflow. Do not copy a Windows vault to a phone.
[Microsoft's DPAPI documentation](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata).

Missing or corrupt existing state fails closed. A pending enrollment after an
error means the invite may already have been consumed; contact the operator with
the existing public key before trying another invite. Expired credentials need
operator-assisted recovery; Connect never silently replaces the device key.
Mac/iOS persistent enrollment remains unavailable until Keychain support exists;
the transport spike still works independently.

## Checks and isolated UI testing

```powershell
cargo test -p connect-core --all-targets --locked
$env:CONNECT_NA_PYTHON = 'C:\Source\GenesisMeshLabs\genesismesh\.venv\Scripts\python.exe'
cargo test -p connect-core --test live_authority --locked -- --ignored --nocapture
cargo clippy --workspace --all-targets --locked -- -D warnings
cd apps/connect
npm run tauri build -- --debug --no-bundle --ci
```

Debug builds accept an absolute `CONNECT_TEST_PROFILE` directory to isolate a UI
test from the user's normal device. Set it only in the launching process. Release
builds ignore it and always use the OS application-data directory. Use disposable
authority identities for tests, and stop the fixture afterward. Local test notes
belong in the Git-ignored `temp/` directory.
