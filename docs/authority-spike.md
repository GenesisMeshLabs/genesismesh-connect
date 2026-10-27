# Native authority integration

Connect can now enroll and renew diagnostic device identities against the native
Python Network Authority, refresh verified trust and preserve rollback protection
across restarts. This Rust library work does not require Mac provisioning. The
Tauri Device tab exposes this lifecycle on Windows; see the [desktop guide](windows-device.md).

## Run the real-authority integration

From the Connect repository root, point to a Python environment with the current
Genesis Mesh source/package installed:

```powershell
$env:CONNECT_NA_PYTHON = 'C:\Source\GenesisMeshLabs\genesismesh\.venv\Scripts\python.exe'
cargo test -p connect-core --test live_authority --locked -- --ignored --nocapture
```

The test starts the actual `NetworkAuthorityService` on a random loopback port,
with an in-memory database and ephemeral root, authority and operator keys. A
separate Python fixture owns the operator credentials and issues invitations and
revocations through the real signed admin routes. Connect receives only public
trust pins and single-use invitations through the local fixture control pipe.
It calls the real HTTP `/join`, `/renew`, `/crl` and `/na/key-history` routes.

Expected result: two nodes enroll, a used invitation is refused, renewal issues a
new certificate, persisted trust reopens, an authenticated QUIC echo succeeds,
then revocation prevents renewal and another echo at a refreshed receiver.
Stopping the authority makes subsequent refresh fail. The child service and
temporary checkpoint files are cleaned up by the test, including failure paths.
No existing authority, network, device or user key is modified.

Run the independent tests and compiler checks with:

```powershell
cargo test -p connect-core --all-targets --locked
cargo clippy -p connect-core --all-targets --locked -- -D warnings
cargo check -p genesismesh-connect --locked
```

The live test is deliberately ignored by the default command because it needs
Python and the real authority. Run it explicitly as above; an ignored test does
not count as a pass.

## Library boundaries

`authority::LocalAuthority` accepts an explicit numeric loopback HTTP origin,
such as `http://127.0.0.1:9443`. DNS names, remote addresses, embedded credentials,
paths, queries and fragments are refused. Its fixed operations cover enrollment,
edge-host enrollment, renewal, trust refresh, public attestation fetch and the
read boundary evaluation; callers cannot supply arbitrary methods or paths. It does
not follow redirects or environment proxies. Each response is limited to 256 KiB
and five seconds, including chunked bodies. Duplicate JSON fields are refused.
Errors omit server response bodies so invitations cannot be reflected into logs.

Request signatures and canonical forms come from SDK v1.8.1. The SDK HTTP client
remains disabled; this small adapter provides Connect's strict origin, body-size
and timeout bounds. The node key signs each request with a fresh timestamp and
UUID nonce. Connect never receives operator keys, requests role escalation, or
retries single-use enrollment automatically. A renewal response must still name
the node, preserve its roles and pass the same certificate/trust checks before
replacing its in-memory certificate.

`TrustStore::create` explicitly bootstraps an unused checkpoint path from an
out-of-band `TrustPin`; `TrustStore::open` requires that same pin and an existing
valid checkpoint. Missing, corrupt or wrong-network state fails closed. The
caller must place the store in an application-owned directory protected by OS
permissions. The checkpoint is public trust metadata, not a secret-key store or
protection against an attacker who can replace the application's entire disk
state.

Refresh first verifies the root-signed genesis, complete succession chain and
signed CRL. The checkpoint retains the genesis digest, exact succession-digest
prefix, CRL sequence/digest, CRL issue time and local observation time. It refuses:

- Lower sequences, shortened histories or a changed previously accepted chain.
- Different signed content at an already accepted CRL sequence.
- A changed genesis under the same root, or backwards CRL/observation times.
- Invalid signatures, stale/future trust or authority keys beyond their horizon.

A fresh authority's signed CRL legitimately starts at sequence **0**. The store
distinguishes that verified value from an uninitialized checkpoint; once it sees
sequence 1, it refuses sequence 0.

Verification happens before committing any checkpoint changes. A held file lock
prevents concurrent writers; a synced temporary file is persisted beside the
destination using atomic replacement. A persistence failure poisons the current
handle until it is reopened, so uncertain disk state cannot be reused. The code
uses [Rust file locks](https://doc.rust-lang.org/std/fs/struct.File.html#method.try_lock)
and [tempfile persistence](https://docs.rs/tempfile/3.27.0/tempfile/struct.NamedTempFile.html#method.persist).
Power-loss durability still depends on the filesystem and OS; checkpoint loss
must fail closed, not trigger silent bootstrap.

## Freshness and live invalidation

The ordinary authority issues CRLs valid for 24 hours and republishes near its
12-hour refresh margin or when revocations/signing keys change. Connect's device
lifecycle accepts this signed validity window, capped at 24 hours, and requires:

- A certificate issued less than **300 seconds** ago for each side of a session.
- A verified trust snapshot observed less than **60 seconds** ago, also bounded
  by a monotonic process timer. The desktop refreshes every 30 seconds while running.
- Renewal when the local certificate is at least **240 seconds** old. The NA
  checks that credential's validity and revocation before issuing its successor.
- Zero extra vouching grace, valid signatures, pinned network/root and the same
  persisted sequence, digest and rollback checks as before.

A still-valid older certificate may authenticate renewal, but cannot authenticate
a diagnostic session. Expired or revoked certificates do not get a recovery
bypass. Verified renewals are atomically persisted before session activation.

Refresh invalidates in-flight diagnostic exchanges and replaces credentials on
the existing endpoint. Failure suspends new and in-flight diagnostics; it does
not fall back to old credentials. A successful later refresh can resume that
endpoint. Readiness and validity checks also refuse stale trust if the periodic
task stalls. Each exchange remains bounded to ten seconds and one message.

This is a diagnostic freshness policy, **not an instant device-wide revocation
guarantee**. A specific certificate ceases being acceptable once its revocation
is observed or it reaches the five-minute issue-age limit. Ordinary NA revocation
targets a certificate; another unrevoked certificate for the same node key,
including a renewal predecessor during its overlap, can still renew. Operators
must revoke all active credentials for a compromised node. Whole-device lifecycle
and a measured active-transfer cutoff remain necessary before broad file-sharing
deployment. The [small-read prototype](protected-read.md) uses live decisions,
per-chunk validity checks and a bounded release window; it does not claim an
instant cutoff for bytes already queued to the network.
The frequent renewal policy also needs load evaluation before deployment.

## Current limits and next work

The integration uses real authority code and disposable test identities. Windows
stores node credentials using user-scoped DPAPI. Other platforms refuse persistent
enrollment until their platform key store is implemented. There is no plaintext
fallback. An invite can be consumed even if its reply is lost: the vault persists
the attempt before submission, retains the same node key, and shows a recovery
notice after an uncertain result. It does not automatically reuse an invite.

The Windows live test also verifies protected-profile restart, single-writer
locking, endpoint refresh, revoked-peer refusal and outage suspension. These are
same-host tests; no physical-iPhone result is implied.

The [Iroh authority bridge](authority-bridge.md) now forwards public trust and
authenticated node renewal, including valid certificates older than the normal
five-minute diagnostic limit. Initial [remote enrollment](remote-enrollment.md)
also uses a separate channel through that desktop. [Protected collection reads](protected-read.md)
now use a separate authenticated protocol and live decisions from an edge-enrolled
host. Operator-assisted recovery and Apple Keychain integration remain pending.
iPhone linking, signing, installation and physical-device behavior remain
separate validation gates.
