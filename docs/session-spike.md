# Session authentication spike

Spike B runs independently of iPhone provisioning. The portable Rust library and
headless example implement a mutually authenticated diagnostic exchange. The
Tauri Device tab now uses these authenticated sessions with the Windows device
lifecycle. Its separate Transport test tab retains Spike A's unauthenticated probe.

## Run locally

From the repository root:

```powershell
cargo test -p connect-core --locked
cargo run -p connect-core --example session --locked -- self-test
```

The example creates an ephemeral synthetic root, authority and two node
identities in memory. It verifies their signed Genesis block, certificates and
CRL, sends an authenticated echo over real local QUIC, then reconnects with a
fresh client endpoint. It writes no private keys. This is a same-host experiment;
it does not enroll devices in the user's real network.

## Trust and connection proof

The SDK is pinned to `v1.8.1`, resolved by Cargo.lock to
`e554ca482a3ef4bc1e7a2ef205ac1d537daa169d`, with its HTTP client disabled.
Connect uses its certificate, CRL and root-pinned key-history verification,
canonical encoding and strict signature verification. Join certificates use
`verify_join_certificate` with `keys_vouching_at`; `verify_record_for_present`
does not accept join certificates as a record kind.

Each endpoint receives a locally provisioned `SessionIdentity`, `TrustSnapshot`
and expected peer node public key. Reachability tickets carry the Iroh public
endpoint and addresses. An arbitrary member of the same mesh is not accepted as
the selected peer. Iroh's transport key remains separate from the node key.

Under ALPN `genesismesh-connect/session/1`, each side exchanges a versioned hello
containing its certificate, endpoint ID, network/root identity, role and a fresh
32-byte OS-random challenge. The claimed endpoint must equal Iroh's authenticated
remote endpoint. Both node keys sign a canonical transcript covering:

- The Connect domain, version, ALPN and pinned network/root identity.
- Both endpoint IDs, client/server roles, challenges and certificate digests.
- A 32-byte TLS exporter derived locally from this completed Iroh connection.
- The signer's role, preventing reflection of the opposite side's proof.

The exporter label is `EXPORTER-GenesisMesh-Connect-session-v1`; its context is
the ALPN. Exporter bytes and private keys are never logged or sent as wire fields.
There is no early-data path. Both sides verify the proof and confirm acceptance
before the single diagnostic message is exchanged. A new connection always
requires a new proof; there is no persistent transport-binding record in core.

## Refusals and limits

Trust is locally pinned, never adopted from the connecting peer. Certificates
must be valid now, name the selected node and network, verify under an authority
key that still vouches, and be absent from the signed CRL. This spike accepts no
clock skew. CRL signatures, signed issue time and next-update time are checked;
local snapshot age and a monotonic process timer also bound reliance. The maximum
configured trust age is 300 seconds; the example uses that maximum and zero extra
vouching grace. A new receipt cannot freshen an old signed CRL in that standalone
example. The device lifecycle uses the [renewal-based freshness policy](authority-spike.md#freshness-and-live-invalidation): a daily signed CRL plus a certificate issued within five minutes and a trust snapshot fetched within one minute.

Caller-provided minimum key and CRL sequences reject snapshots below those
watermarks. Provision these alongside the root, not from the peer. The
[authority integration](authority-spike.md) now persists these watermarks, checks
equivocation and verifies refreshed records from the native loopback authority.
A snapshot alone cannot prove that no newer succession exists; the refresh
transport and freshness policy still matter. Initial signed CRL sequence 0 is
valid; lower sequences after a newer observation remain refused.

Connections get ten seconds for transport establishment and ten seconds for the
whole authenticated diagnostic exchange. There are at most eight incoming tasks
and two outgoing operations per endpoint, one accepted bidirectional stream per
connection, no accepted unidirectional streams, 16 KiB frames and 1,024-byte UTF-8
diagnostic messages. Lengths are checked before allocating frame bodies. Duplicate
JSON fields, unknown envelope fields and trailing or second messages are refused.
Certificate/trust validity is rechecked before the server echoes a message and
before the client reports success. Refresh or suspension invalidates in-flight
diagnostics; an invalid replacement leaves the endpoint suspended. Valid refresh
preserves the Iroh endpoint identity and existing reachability tickets.

Tests include real QUIC reconnects, wrong protocol fields and endpoint claims,
captured-proof replay on a new TLS connection, role reflection, transcript
tampering, certificate substitution, revocation, expiry, stale/future trust,
sequence rollback, an ended authority's vouching horizon, oversized data and an
incomplete-handshake deadline.

## What remains

This diagnostic ALPN exposes only local-network echoes. Authentication alone
does not grant file or service permission. No production readiness or
physical-iPhone success is claimed.

Real native-authority enrollment, renewal, persisted trust, Windows protected
device state and the Tauri Device tab are implemented in the [next milestone](authority-spike.md).
The [authority control channel](authority-bridge.md) now uses a separate ALPN,
proof domain and TLS exporter label while reusing the certificate/proof machinery.
Initial [remote enrollment](remote-enrollment.md) uses its own certificate-free
client bootstrap and verifies the desktop before sending an invite.
[Protected collection reads](protected-read.md) now use another ALPN, with live
decisions, storage confinement and signed Connect receipts. Resume physical-iPhone
tests when setup is available. Operator-assisted recovery and measured
active-transfer revocation remain separate milestones. No core or SDK source
changes were required.
