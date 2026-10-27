# Authority control over Iroh

An enrolled client can obtain verified trust records and renew through the
desktop's Connect listener. The desktop contacts its numeric-loopback authority;
the client needs no HTTP authority adapter for these operations. The implementation
is under `crates/connect-core/src/session/bridge/` and is exposed by the Tauri
Device tab. See the [Windows workflow](windows-device.md#use-the-desktop-authority-bridge).

The real-authority tests run on one Windows host with separate device identities
and real Iroh/QUIC connections. Physical iPhone, cellular and off-LAN behavior
remain unverified. A separate [enrollment channel](remote-enrollment.md) now adds
initial onboarding through the same desktop endpoint. Apple key storage remains
pending. Guided bridge endpoints follow the network's
[connection setting](everyday-workflow.md#choose-how-devices-connect);
advanced profiles use local mode with relays disabled.

## Fixed operations

On the control ALPN, every connection permits one bidirectional stream and one operation, selected
by a strict versioned request. There is no URL, method, path or header parameter.

| Operation | Local authority access | Client requirement |
| --- | --- | --- |
| `trust` | GET `/na/key-history`, then GET `/crl` | Explicit desktop reachability ticket; signed documents must verify against the client's independently pinned root/network and persisted checkpoints |
| `renew` | POST `/renew` | Mutual node authentication plus a valid node-signed body naming the exact certificate authenticated in that connection |
| `settings` | None | Mutual node authentication with a currently valid certificate and an empty body; returns the network's connection setting and the computer's current bridge and session tickets, which the device accepts only for the endpoints it already trusts |
| `spaces` | None | Mutual node authentication of a device the computer saved, and an empty body; returns the Spaces it hosts (with their policy, attestation, devices and expiry) and those naming it (name and sharing device only), from the copy of the owner runtime's registry the computer publishes at least every 30 seconds and after each change, so listing never waits for the runtime |
| `share_space` | None (the owner runtime publishes and activates the policy and issues the attestation) | A saved device names a collection, a name and 1–31 devices, each a device the computer saved or the computer itself, never the caller; the caller is always the host, only it can change its Space, and a new Space never reuses a collection that already has a policy |
| `unshare_space` | None (the owner runtime deactivates the policy) | A saved device names one of its own Spaces |
| `members` | None | Mutual node authentication with a currently valid certificate and a body holding only the device's own current session ticket (or none); returns the computer's other saved devices (name, node key, session ticket of at most 2 KiB, in one canonical spelling), never the caller. Only devices the computer has saved get an answer, and none before it has published its list. The computer keeps a reported ticket only for the endpoint that device paired with |

Trust documents are public and can be fetched before node authentication. This
allows a client resuming after several minutes to obtain current trust before
proving its existing credential. Responses never enroll a device, grant access,
or replace its root pin. Invalid root/signature, stale trust, rollback or
equivocation leaves verification unsuccessful; there is no cached-success
fallback. A suspended host refuses connections.

Renewal bodies pass to the authority unchanged. The bridge checks the exact
allowed fields, certificate ID, expected node key, validity request of 1–24
hours, timestamp, UUID v4 nonce and SDK node-request signature before forwarding.
The authority independently checks the signature, replay state, certificate
status/time and server-assigned roles. Connect never adds operator credentials.
Unknown operations, extra envelope fields, admin routes, enrollment on the control ALPN, oversized
frames, additional payloads and a different credential are refused.

## Separate authentication scope

The control ALPN is `genesismesh-connect/authority/1`. It reuses the session
certificate, challenge, endpoint/credential binding and proof implementation,
with domain `genesismesh-connect/authority-proof` and TLS exporter label
`EXPORTER-GenesisMesh-Connect-authority-v1`. Its exporter context is the control
ALPN. Captured diagnostic proofs cannot authenticate this channel.

Both parties must present the selected node's valid, unrevoked certificate under
the pinned network and authority horizon. Unlike diagnostic sessions, control
authentication permits a certificate issued more than five minutes ago if it
remains valid. That credential can authorize its own renewal only. Expired,
revoked or untrusted credentials remain refused; this is not an expired-device
recovery path. No file or general service operation exists on this ALPN.

The client verifies the returned certificate and unchanged roles before adopting
it. Device route changes require the diagnostic session to be stopped, complete
a mutually authenticated renewal, and atomically persist the new certificate
and bridge route. Ordinary renewed certificates are likewise persisted before
session activation. Existing profiles without a bridge route continue to open.
Bridge failures never silently switch to HTTP. Bridge clients do not host a
second bridge, preventing accidental forwarding chains.

The [freshness and certificate-specific revocation limits](authority-spike.md#freshness-and-live-invalidation)
still apply. The host verifies its own fresh trust/credential before serving,
fetches public records from the authority for each trust call, and periodically
refreshes its control credentials. Refresh or suspension cancels current control
operations. An interrupted renewal may already have committed at the authority;
Connect cannot undo that commit. Operator-assisted recovery and predecessor
overlap remain relevant when a reply or durable write is lost.

## Bounds and lifecycle

- At most four admitted host connections; at most two concurrent client calls.
- Host admission: 1,024 arrivals per fixed 60-second window, shared by every
  operation. Per fixed 60-second window: eight forwarded renewals, 480 collection
  decisions and attestation reads, three enrollments, and 120 each of settings
  and member lists, 120 Space lists (each device asks once per 30-second
  refresh) and 16 Space changes. Rejected admissions do not contact the NA.
- Fifteen-second transport acceptance and operation deadlines on the host;
  fifteen-second connection-plus-exchange deadlines on the client. Each upstream
  HTTP call retains its five-second deadline, no redirects and no proxy routing.
- Request/authentication frames are capped at 16 KiB. A trust response is capped
  at 512 KiB plus 1 KiB for the envelope, accommodating two bounded public records.
  Lengths are checked before allocating. Responses carry no arbitrary error text.
- Stop closes both the diagnostic and authority listeners. Trust refresh retains
  their transport identities. Host restart creates new tickets; the saved client
  route must be updated explicitly. Public network conditions can change ticket
  addresses while an endpoint ID remains stable.

The admission budget limits application work after Iroh produces an incoming
connection; it is not a network-wide denial-of-service defense. Shared upstream
NA address limits also apply. These defaults support one chosen peer and need
measuring before expanding to multiple devices or public relays.

## Validation

```powershell
cargo test -p connect-core --all-targets --locked
$env:CONNECT_NA_PYTHON = 'C:\Source\GenesisMeshLabs\genesismesh\.venv\Scripts\python.exe'
cargo test -p connect-core --test live_authority --locked -- --ignored --nocapture
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Tests cover root verification; older-but-valid control credentials versus normal
session refusal; protocol-domain separation; request/credential/route injection;
bounded frames and renewal budgets; peer revocation; control suspension; real
authority renewal over Iroh; use of the renewed credential for a diagnostic;
persisted bridge routes; explicit route changes; and authority outage. Local
execution results and platform blocks are recorded in ignored
`temp/authority-bridge-results.md`. An ignored or blocked test is not a pass.
