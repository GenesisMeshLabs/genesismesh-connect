# Owner-control contract: pairing administration foundation

`connect_core::owner_control` implements a separate, bounded administrative
enrollment and request contract. **It is not exposed by a Tauri command, the
member authority bridge, the node socket or the operation registry.** No phone
has gained administrator access through this work. Native key custody and
controller preparation are implemented; host enrollment UI, the authenticated
owner-control wire protocol and Requests remain the next integration gates.
The public-core administrator journey stays planned.

## Three independent prerequisites

1. A current member certificate is checked with the existing pinned
   `TrustSnapshot` verifier, including certificate expiry, revocation, trust
   freshness and authority-key horizon. The node identity must come from an
   already mutually authenticated connection, not a request field.
2. The device proves possession of a **separate administrative Ed25519 key**.
   Enrollment binds that key, the member node, pinned root/network, host audience,
   exact permissions, request identity and expiry. The SDK canonical JSON and
   signature helpers sign a domain-separated payload.
3. The authority host explicitly approves the exact canonical enrollment digest
   locally. The host persists its approval before returning a grant. Merely
   receiving a signed enrollment request grants nothing. No remote action can
   enroll or revoke another administrator.

An enrollment review expires within two minutes. A requested grant lasts at most
30 days; local revocation takes effect at the next reservation. The initial
allowlist contains only listing, approving and rejecting pairing requests.
It cannot replace a root, issue arbitrary attestations, change network-wide
policy, run a command or provide generic HTTP access.

These are **Connect host delegations**, not core operator keys, role attestations
or independently signed authority capabilities. The eventual fixed adapter
still needs the host's real core operator and operation-specific role/key-tier
checks. A second tap by the same owner is not independent approval.

## Exact requests and durable replay refusal

### Native key custody

The device keeps a separate purpose-bound administrative credential. Its private
seed is not added to the member identity or encrypted recovery export. The
private profile holds public binding metadata plus an opaque provider/account
reference, or a current-user DPAPI blob on Windows. Existing device DPAPI uses
its original entropy domain; administrative blobs use a separate domain. Other
platforms reuse the existing explicit Keychain, Keystore-backed, Secret Service
or headless sealed-store adapters, with purpose/account/context checks.

`AdministrativeKey` retains public metadata only. Each typed enrollment/command
signature rereads the reference and protected credential and checks the exact
network, host, member, account and public key. Locked, missing, substituted,
corrupt or changed-provider credentials fail without replacing a key. Only
explicit enrollment preparation can create one. A persistent creation marker
and exclusive no-clobber commit prevent automatic regeneration after interrupted
or missing initialized state. Failed/unconfirmed first creation needs an explicit
future recovery/reset ceremony; opening/signing never creates a new key.

`DeviceController::prepare_owner_enrollment` and `prepare_owner_command` derive
scope from the current native profile and paired authority host, require an
enrolled connected device and refresh trust before signing. They accept typed
choices/actions, without caller-selected identities, URLs or private keys. They
dispatch nothing and grant no administrative rights. They remain unavailable
through app IPC until exact user review, client workflow recovery, native user
presence and authenticated host control are integrated.

Leave/discard cleanup removes only a purpose-checked credential for that
network/member and supports retry after native-secret deletion. An older host
binding can be removed when the device leaves the same network. A foreign root
or member is preserved. Recovery restores membership separately and requires
fresh administrative enrollment. A missing reference can leave an unreachable
native credential; creation is refused rather than silently generating a new
identity. The app does not claim universal orphan erasure or hardware anti-rollback.

Reopening OS protected storage is **not** a fresh biometric or user-presence
ceremony. Actual lock behavior follows each OS/store; DPAPI access in a logged-in
process does not itself detect Windows screen lock. Native lifecycle and
high-risk user-presence acceptance remain separate gates.

Each signed command contains a version, grant ID, nonce, controller node, pinned
scope, host audience, action and a two-minute validity window. Approval/rejection
also names the exact pending request ID, candidate node, display name and
six-digit comparison code. Altering any field invalidates the signature. Strict
parsing rejects duplicate JSON keys, unknown fields, unsupported actions and
envelopes larger than 16 KiB.

`VerifiedController::from_session` takes the host's trusted scope, fresh local
trust snapshot and the certificate/node from the authenticated session. It is
not deserializable. Its context expires after five seconds; the future adapter
must refresh membership and reconstruct this context for **every dispatch**.
The primitive validates freshness according to the supplied host trust policy;
it does not itself fetch the latest authority state or authenticate a socket.
Two device clocks must agree on the command window; future-dated requests are
refused, rather than silently extending administrative validity.

`ControlStore::reserve` checks all three prerequisites and current permission,
grant expiry and revocation. It then saves an **unconfirmed** nonce reservation
before returning a non-deserializable `Reservation`. A failed save returns no
dispatch permission and poisons the in-memory store until reopened. A reserved
request cannot be submitted again after restart, even if the reply was lost.
Recording that a reply was observed does not permit replay or prove that the
candidate completed enrollment.

The fixed adapter must hold the exclusive host store through its final live
target/core checks and immediate dispatch. Before issuing an invitation or
rejecting a request it must call `OwnerAction::require_pending` against the
current `PairHost` request under the same pairing lock. A matching signature is
not sufficient when the pending request has changed or vanished. Root custody,
new member invitations and enrollment completion remain separate facts.

## Persistence and recovery limits

The store uses a separate host-local file with an exclusive lock, atomic
replacement, file sync and directory sync on Unix. Creation is explicit;
opening missing, malformed, oversized, foreign-scope or linked state fails
without resetting it. A lock marker prevents silently recreating an initialized
but missing registry. A persisted timestamp high-water mark refuses clock
rollback, including after expired nonces were pruned.

Bounds are 64 retained grants, 256 unexpired reservations and a 4 MiB state file.
Capacity exhaustion refuses new activity rather than evicting active replay
protection. Expired reservations can be pruned because their signed validity
window and the timestamp high-water mark still prevent reuse. This replay ledger
is **not** a complete, indefinitely retained operation history. Grant-history
compaction, operation-specific uncertain-result reconciliation and owner-control
Activity integration remain future work.

The trusted native application directory and OS account are the storage
boundary. This module does not prevent a malicious local administrator from
rewriting approvals or restoring an entire old file. It does not provide
hardware-backed anti-rollback or multi-host consensus. It is excluded from the
network recovery file. Restoring/cloning an old owner-control registry onto an
active authority is unsupported; recovery must explicitly fence old control
state and re-enroll administrators. It never recreates a missing device key.

## Qualification and remaining gates

Portable refusal tests cover membership without approval, wrong review digest,
administrative-key separation, exact signed fields, role/expiry/revocation,
fresh peer context, strict envelopes, exact current pairing target, replay after
restart, clock rollback after pruning, concurrent writers, corruption/loss,
oversized storage, links, capacity and persistence failure.

The real-core fixture creates a disposable authority, uses the same registered
edge-host enrollment as guided Connect devices, and verifies that a genuine
member still needs local administrative enrollment. A real core revocation then
prevents rebuilding its current controller context despite a retained grant.
This is membership/revocation qualification, **not remote pairing dispatch**.

Linux qualification now includes the real isolated native store, typed native
controller signing with a disposable real authority, restart, recovery-export
exclusion, disconnect refusal, missing native credential and leave/discard
cleanup. Mock-store cases additionally cover lock/unlock, account/purpose/seed
substitution, provider changes, concurrent access and failed reference commit.
An isolated headless-process test also qualifies the actual Linux sealed store,
including encrypted-record corruption and missing-key refusal. Its master key
is a disposable fixture; it does not establish TPM/systemd deployment acceptance.
Windows DPAPI and Apple/Android adapters are implemented but have not been
compiled/installed/tested anew for this slice. The prior Windows Application
Control blocker remains unresolved. No new browser or physical-device acceptance
is claimed for these native-only changes.

Before exposure: authenticate and bind the owner transport separately;
add explicit local enrollment/revocation UX; enforce final core readiness and
target checks in fixed app/node adapters; retain durable enrollment/dispatch
recovery; then implement Requests with plain scope, approval and uncertainty.
Qualify real core/QUIC negative cases, native user presence, lock/suspend and
physical platforms. No new Windows, Mac, iOS or Android installation is claimed.
