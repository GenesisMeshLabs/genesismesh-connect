# Owner-control contract: host pairing Requests

`connect_core::owner_control` implements a separate, bounded administrative
enrollment and request contract. The authenticated authority bridge supplies the
actual session node and certificate to the native `HostControl` adapter. Both
desktop and headless host dispatch use that adapter. Ordinary membership grants
no pairing administration. An initialized host-local registry and exact local
approval are required; remote requests never create the registry or approve an
administrator. Missing initialized state is preserved and refused.

This is backend and guided local host integration, not a completed phone-owner
journey. Devices → Manage administrators exposes narrow local status, review,
commit and readback IPC. Device-side signing/request preparation and the general
operation registry do not expose administrator privileges. Production host UI
mutations remain refused by the unavailable native-presence adapter. Mobile
Requests UX, qualified native user presence, installed-app and physical acceptance
remain open. Embedded Android authority work stays isolated; this host adapter
does not satisfy phone-hosted ownership or enable public Create.

The headless host has an explicitly advanced, local Unix-socket review surface:
`requests enable`, `requests list`, `requests approve ID DIGEST`,
`requests decline ID DIGEST`, and `requests revoke ID`. List shows the complete
signed enrollment intent and canonical digest. Approve requires that exact saved
pending request and fresh member verification. No corresponding remote operation
exists. The desktop guided review uses the same fixed APIs, with a separate
native-presence gate. The existing headless local-operator profile is unchanged.

## Guided local host review

`LocalAdministration` derives host/network scope from the live native device and
checks the actual managed authority's fixed readiness. It resolves the requesting
node to a saved device name plus fingerprint, retains the exact signed enrollment
digest, and shows the specific pairing permissions, expiry and consequences.
An unidentified member cannot be approved by supplying a name. Review payloads
are held natively (at most 32, at most two minutes) and bound to a canonical digest.
Commit accepts only that exact reference; it cannot select keys, URLs, methods,
presence providers or arbitrary core actions. Scope, intent, expiry and current
membership for approval are checked before and after native confirmation.

The current production `UnavailableAdminPresence` refuses all local UI mutations.
No caller boolean, environment/config override, DOM click or protected-storage
reopen can turn it into a qualified provider. The UI makes the gate visible and
keeps confirmation unavailable. Inspection and exact review remain useful for
already-enabled hosts. A qualified provider and installed-app acceptance are
future work, not inferred from the fixture's test-only consent adapter.

Reviews are single-use in the native session; after restart an old review cannot
be committed again. The frontend stores only a public, scoped readback bookmark
before dispatch. Native readback re-resolves the original enrollment/digest from
the exclusive host registry; it never dispatches. Approval, decline and revocation
records survive reopening under the existing bounded retention. Missing/pruned
records remain unconfirmed. A matching current state is reported as observed
state, not proof of which UI click caused it. Changed/expired context and canceled
or unavailable confirmation are refused before dispatch; a lost or uncertain
dispatch reply offers Check status and never automatic resubmission.

Closing the dialog, pressing Escape or leaving Devices invalidates its presentation
session. Abandoned status, review and readback replies (including their busy-state
cleanup) cannot restore a review or replace a reopened view. Submitted mutations
remain tracked separately by host scope and exact reference: closing preserves
their bookmark and eventual outcome, without replay. A newer explicit state
observation takes presentation precedence over an older submission reply; both
results remain tracked while the app is running. Readback requests have their own
sequence, independent of submission settlement: an older Approved submission
reply cannot invalidate a newer Revoked observation, in either delivery order.
The bookmark remains while a submission or its latest readback is unresolved,
including a failed or abandoned check. Reloaded bookmarks offer readback only,
not a new commit. Each check and reply must match the exact saved scope/reference;
superseded check replies cannot replace a newer observation.

The host app uses the existing owner → device lock order and a nonblocking busy
response while another operation owns them. Local review is desktop/owner only;
member/mobile and unqualified external authority paths remain unavailable.

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
30 days; local revocation takes effect at the next dispatch or result readback. The initial
allowlist contains only listing, approving and rejecting pairing requests.
It cannot replace a root, issue arbitrary attestations, change network-wide
policy, run a command or provide generic HTTP access.

These are **Connect host delegations**, not core operator keys, role attestations
or independently signed authority capabilities. Before each pairing operation,
the fixed inherited-pipe adapter checks its actual pinned managed core, operator
public key, privileged key tier, operator revocation and allowed invitation role.
An attached external authority is refused because its feature contract has not
been qualified. The actual edge invitation still passes core's signed admin
route and its independent tier/role checks. No operator credential crosses QUIC.
A second tap by the same owner is not independent approval.

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
through app IPC pending exact user review, client workflow recovery and native
user presence. The authenticated host control transport is integrated separately.

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
not deserializable. Its context expires after five seconds; the host adapter
refreshes membership and reconstructs this context for **every dispatch**.
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

`HostControl` holds the exclusive host store through final live target/core
checks and dispatch. `PairHost::control_dispatch` holds its pairing mutex across
exact request validation, current host trust checks, the fixed core readiness
check, invitation issuance and delivery/rejection. It checks expiry and device
disconnect again after the core call. No invitation is issued against a different
pending request. A matching signature is insufficient when the request vanished.
The adapter rebuilds the controller context from a fresh authority refresh before
every exchange and again immediately before dispatch. The five-second context,
signed command window and active grant are checked inside the gate.

Approval persists `Started` after delivery and waits for enrollment, an
authenticated round trip bound to the exact candidate node, fresh controller
membership/grant checks, and durable local relationship storage before final
confirmation and `Approved`. `Approved` describes this host's completed checks;
it is not proof that a human viewed the reply. Failure or process interruption
leaves a consumed nonce with an unconfirmed/started result. No automatic invite
reissue or execution retry occurs. Rejection and listing save exact results.

The native round trip retains the exact authenticated candidate certificate in
a non-deserializable peer proof. Immediately before synchronous local storage
and confirmation, one fresh authority snapshot verifies the host, controller
and that candidate proof, including revocation and certificate validity. A
candidate revoked while enrollment was waiting receives no success confirmation
and is not added to the saved device list. Failed final verification explicitly
refuses completion and saves `Unconfirmed`; readback never permits nonce replay.
The refresh observes core state at fetch time; later core revocations retain
their normal effect.

The outer native host/device locks serialize an exchange, including the bounded
80-second enrollment wait. Other Requests can time out or be busy meanwhile;
they must read a saved result rather than replay execution. Result readback
is also required when candidate preparation changes the host peer set: the
existing bridge deliberately fences connections on that change, so an execution
reply can be lost while the independently queued native adapter continues.
Current-membership verification itself fetches trust without republishing bridge
credentials, preserving read-only Requests connections. Result readback
rechecks current membership and the original grant, permission and device binding,
even after the command's dispatch window ends. Expired/revoked administrators
cannot use readback to inspect a saved pairing target. Unknown/pruned results
are refused; neither response permits redispatch.

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
compaction, deeper uncertain-result reconciliation and owner-control
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

The membership fixture creates a disposable authority, uses the same registered
edge-host enrollment as guided Connect devices, and verifies that a genuine
member still needs local administrative enrollment. A real core revocation then
prevents rebuilding its current controller context despite a retained grant.
The separate `owner_requests_authority` fixture exercises the actual host adapter
over mutually authenticated QUIC: explicit opt-in, pending submission/status,
local decline/approval, ordinary-member denial, lost-reply durable readback,
duplicate execution refusal, expired commands, stale targets, rejection, real
candidate enrollment/final proof, grant revocation and current core CRL refusal.
The timing regression independently signs a real core revocation after candidate
enrollment but before final pairing completion. Retained-trust diagnostics still
succeed, while fresh commit verification refuses storage/success, keeps durable
unconfirmed readback and refuses replay.
CI repeats that fixture against the packaged standalone authority executable,
not only the Python source entry point.
Portable tests cover grant expiration, exact mutex scope, suspended hosts and
core readiness refusals. Fixture evidence is not physical phone acceptance.

Linux qualification now includes the real isolated native store, typed native
controller signing with a disposable real authority, restart, recovery-export
exclusion, disconnect refusal, missing native credential and leave/discard
cleanup. Mock-store cases additionally cover lock/unlock, account/purpose/seed
substitution, provider changes, concurrent access and failed reference commit.
An isolated headless-process test also qualifies the actual Linux sealed store,
including encrypted-record corruption and missing-key refusal. Its master key
is a disposable fixture; it does not establish TPM/systemd deployment acceptance.
The Python owner adapter tests also exercise native Windows DPAPI. CI checks the
Rust core on Windows and Linux, Android APK packaging, and Linux desktop/headless
compilation. These automated checks do not establish Windows application launch,
Apple platform acceptance, native user presence or physical Android ownership.
The prior local Windows Application Control blocker remains unresolved. No new
browser or physical-device acceptance is claimed for these native-only changes.

Before enabling app mutations: qualify the native user-presence adapter and the
installed local enrollment/revocation journey; complete the client Requests
workflow with plain scope, approval and uncertainty. Qualify native user
presence, lock/suspend, recovery after every product interruption point, and
physical platforms. No new Windows, Mac, iOS or Android installation is claimed.
