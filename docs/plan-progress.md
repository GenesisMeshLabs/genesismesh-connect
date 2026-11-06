# Developer-plan alignment

The supplied 5 November 2026 plan remains the full programme: supported public
core outcomes, understandable manual workflows and optional assistance through
the same typed authorization path. It includes CLI/Python-only capabilities.
The latest supplied attachment matches the retained `temp/connect-developer-plan.md`.

The inventory maps 419 public declarations to 25 journeys. These are overlapping
declarations, not 419 user features. No complete outcome has passed every
manual/assisted/platform acceptance gate; no parity percentage is claimed.

| Ticket | Implemented foundation / existing workflow | Remaining product acceptance |
| --- | --- | --- |
| CONNECT-01 coverage | Reviewed immutable inventory, pin qualification, drift and false-acceptance checks | Hosted CI execution and continued release/platform qualification |
| CONNECT-02 typed operations | Closed resource/local-history registry, generated schemas, exact access review | General core outcome schemas and manual/assisted parity |
| CONNECT-03 durable workflows | Access dispatch/readback journal, archives; owner nonce reservations | Durable join/renewal/recovery/admin enrollment and operation-specific reconciliation |
| CONNECT-04 prerequisites | Authenticated resource-host release/profile/ownership discovery | General feature, verifier, actor and deployment discovery |
| CONNECT-05 owner Requests | Pairing-only signature/replay contract; separate native key custody; authenticated transport and bounded durable enrollment/result records | Fixed core/target dispatch, explicit enrollment/revocation UI, usable phone Requests and recovery; default host still refuses unsupported control |
| CONNECT-06 lifecycle | Existing disconnect/reconnect/leave; administrative native-store refusal and cleanup | Physical lock/suspend/force-quit/reboot/network switching and user-presence handling |
| CONNECT-07 distribution/hosting | Existing Tauri packaging and headless Linux server | Signed fresh-machine installer/update/service/uninstall acceptance and guided host setup |
| CONNECT-08 continuity | Existing encrypted recovery and server restore | Checkpoints, missing-history reconciliation, restricted restore and old-host fencing |
| CONNECT-09 agents | Existing member/edge mechanisms | Generic agent onboarding, separate identities/descriptors, allowed/refused real operations and independent revocation |
| CONNECT-10 general policies | Resource recipients/expiry/size/duration and extra gates | Visual general policy templates/selectors/gates, impact preview and semantic round-trip |
| CONNECT-11 Activity/evidence | Ordinary local access history, attention filtering, status readback and unsigned record export | Core signed evidence timeline/audit packs/independent verification and execution attribution |
| CONNECT-12 assistance | Shared typed operation boundary; no model configured or enabled | Opt-in constrained assistance using the exact manual review/authorization/dispatch path and privacy controls |

The remaining programme also includes attestations, agreements/delegation,
federation/trust paths, remediation/oversight, offline grants, data governance,
invocation/freshness, selective disclosure/integrity, interop, fleets,
succession/HA and exit. The [complete journey mapping](../contract/connect-journeys.json)
retains their scope and acceptance gaps. Core remains responsible for trust and
policy semantics; Connect supplies the usable workflows and fixed adapters.

## Independent phone hosting requirement — 5 November 2026

The user requires **both** a genuine authority hosted by the Android phone and
an optional always-on NAS/server host. The NAS/server is not a prerequisite or a
substitute for phone creation. This supersedes earlier desktop-host-only scope.
Android is first; embedded iOS authority hosting needs separate qualification.

`network.setup` must let a fresh Android installation create its own network,
retain the same authority and membership identity after restart, recover safely,
enroll a second device and perform real allowed/refused authority decisions with
no desktop authority, NAS/server or remote authority running. This outcome is
**not implemented or accepted**. Neither an Android client APK nor delegated
phone administration demonstrates independent hosting.

The first implementation gate is packaging the unchanged pinned Python core,
including its native dependencies, with Android Keystore-backed owner custody.
Missing compatible wheels are a dependency build/qualification task, not a
reason to downgrade the core or replace its policy/trust engine. Initial hosting
is foreground-only. Sleep, termination, reboot, lock and background restrictions
must be tested and explained before claiming continuous availability.

Dependency build evidence on 5 November 2026: all four missing native bindings
were built and checked for Android arm64/API24, CPython 3.13 ABI and 16 KiB
alignment. The unchanged core requirements resolved with 28 reachable packages
under Android target markers. The repeatable source-build/closure gate is in
merged PR #20. This removes the missing-wheel obstacle; it does not establish
embedded-core execution, owner custody, independent Create, persistent hosted
identity or second-device enrollment on the phone.

Runtime evidence on 6 November 2026: the isolated engine-check APK built in
hosted CI run `42129762152` from head `5be515a` (tested merge source
`4f66e1f7576be7e77076275ad980b35bc1019fd0`). On the physical Samsung SM-A176B,
Android API 36, embedded Python 3.13.16 and core 1.9.1 passed all seven checks:
real core loading, signatures including refusal cases, native FFI, authenticated
encryption and tamper refusal, model validation, SQLite close/reopen and temporary
loopback HTTP. The passed screen was verified separately from installation.
The first device runs exposed the build-time/device API distinction and missing
shared Python linkage; both were fixed without changing core or crypto versions.
Process-wide execution and unique run IDs prevent stale activity results;
a deterministic Java regression covers overlapping runs and delayed UI updates.
Physical recreation/process-death tests remain separate and unperformed.

The harness creates no network or owner identity. This does not qualify authority
creation, owner custody, persisted hosted identity, actual authority decisions,
second-device enrollment/revocation, production library support, or lifecycle
availability. The full Create workflow remains disabled until those gates pass.

## Next user-visible acceptance milestones

Embedded owner adapter progress on 6 November 2026 (PR #22): fixed in-memory core
initialization, signed self-enrollment, purpose-separated Android Keystore custody
and create/open/close persistence are implemented behind the developer harness.
Twenty-six Windows host tests pass using the real core and explicitly test-only
encrypted custody, including interrupted creation/key generation, missing/corrupt
state or keys, domain swaps, erased profile with existing custody, lock contention,
revoked/missing membership, invalid names and stable public identities. These are
not Android hardware or end-user acceptance results.

Review reproductions also drove bounded HTTP shutdown, durable key sealing before
first core use, and explicit member-credential recovery. Time-controlled host/core
tests cover exact expiry, the former grace boundary, owner reopen days later,
fresh core re-enrollment with unchanged identity keys, expired-certificate refusal,
lost replies, failed commits, delayed reconciliation, tampered intents and explicit
cancel/retry without automatic write replay. Incomplete requests terminate;
unsettled handlers retain keys and the exclusive state lock until safe shutdown.
Failure to start the serving thread closes the unused listener/database and
releases custody/state exclusivity; a genuine existing profile reopens unchanged.
These are hosted/host simulations, not physical elapsed-time or lifecycle tests.

The first Samsung attempt passed the seven runtime checks, then was refused by
the native device readiness guard before creating an owner network. Its specific
result is `secure_screen_lock_required`; configuring a credential is a local user
step. Real Android create/reopen and
process-restart identity acceptance remain pending; production Create stays off.

**“Create and run my network on this Android phone.”** The independent-phone
proof above is required alongside the optional server profile. Native dependency
qualification and lifecycle work remain open; no unsupported Create button is
enabled by the plan update.

**“Use my phone to review and approve a new device joining my network.”**

An existing member explicitly requests limited administration; the host owner
reviews the exact device, permissions, duration and consequences. Only then may
the phone see the permitted pairing queue over separately authenticated host
control. It compares the actual candidate's code, reviews membership effects,
confirms one exact request, and sees a verified result or explicit uncertainty.
No public-key copying, terminal command, raw JSON or model is required.

Acceptance must cover an ordinary member's refusal, changed targets or scope,
revoked/expired credentials, replay, interrupted approval, lost replies and
restart. The host still checks actual core role/key tier and current pending
target. A model may propose the same operation only after the manual flow exists;
it receives no separate privilege. Native custody alone does not complete this
journey or justify enabling a phone's administrator button.

Each delivery records code, automated/core integration, native build,
installation, physical lifecycle and first-time usability as separate facts.
Current Windows Application Control and unperformed mobile/signing/device gates
remain explicit. A compiled adapter or signed intent is not evidence that a
nontechnical person completed the installed-app workflow.
