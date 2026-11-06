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
| CONNECT-01 coverage | Reviewed immutable inventory, pin qualification, drift/refusal checks and repeatable hosted CI | Continued release/platform qualification |
| CONNECT-02 typed operations | Closed resource/local-history registry, generated schemas, exact access review | General core outcome schemas and manual/assisted parity |
| CONNECT-03 durable workflows | Access dispatch/readback journal, archives; owner nonce reservations | Durable join/renewal/recovery/admin enrollment and operation-specific reconciliation |
| CONNECT-04 prerequisites | Authenticated resource-host release/profile/ownership discovery | General feature, verifier, actor and deployment discovery |
| CONNECT-05 owner Requests | Authenticated transport; fixed managed-core/target dispatch and fresh candidate verification; native key custody; durable enrollment/result records; guided local host review, typed IPC and scoped readback | Qualified native user presence for UI mutations; installed host opt-in/review/revocation acceptance; usable phone Requests, recovery, assisted parity and physical gates |
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

### Host backend and guided local administration — 6 November 2026

The host now receives separately authenticated administrative enrollment requests,
requires exact local approval and dispatches only the granted pairing operations.
Its actual managed-core operator/tier/role readiness, current membership, exact
live candidate and nonce reservations are checked. Candidate certificates are
reverified against fresh core state before saving a pairing or confirming success.
The candidate-revocation timing regression reproduced false success on the earlier
implementation and now passes against source and packaged authorities.

Devices → Manage administrators now provides local opt-in review, actual saved
device identification, exact pairing permissions, expiry/time zone, consequences,
decline and revocation review. Narrow native status/review/commit/check commands
derive host scope and device identity locally. Reviews are bounded, expire and
cannot be committed twice; a saved readback bookmark grants no authority.
Confirmed current state, a refused change and uncertainty have separate messages.
After interruption, checking status observes the same enrollment/digest in the
same host/network and never repeats the change. Matching state is not attributed
to a particular click, and missing retained records stay unconfirmed.
Dialog close, Escape and navigation now fence abandoned asynchronous reviews,
loads and readbacks. Reopening loads fresh state without waiting for an old
presentation. Already-submitted changes retain their scoped bookmark and eventual
outcome independently; status checking never resends them. Delayed browser
fixtures cover these lifecycle cases separately from native/device acceptance.
Readback ordering is independent of submission replies, so a newer Revoked
observation wins even when an older Approved reply arrives first. Unresolved
readbacks retain their recovery bookmark across navigation/reload.

**Production administration mutations remain gated.** No native user-presence
provider has been qualified for this app. A DOM confirmation, OS-store reopening,
caller flag or debug environment does not substitute for one. The current native
adapter allows inspection/review and refuses privilege changes. Positive fixtures
use an explicitly test-only native presence adapter; they do not enable a
production path. Unsupported mobile/member/external-authority paths remain gated.

| Evidence class | Current scope and limit |
| --- | --- |
| Build and automated fixtures | Core tests, real-core local reviews/readback with fixture presence, source and packaged authority coverage; frontend state tests and installed-Chrome browser fixtures with simulated native replies |
| Installed native application | Not newly accepted for this slice; local Windows Application Control remains an environment gate |
| Physical lifecycle and native presence | Not performed; no device/security changes in this slice; Android owner PR #22 remains isolated/draft |
| Usability | Browser fixture inspection includes desktop/narrow layouts and lost replies; nontechnical first-use acceptance in an installed app remains open |

The backend milestone is implemented; the whole phone-owner journey remains
partial. Production mobile Create stays disabled and independent phone-local
real-core authority remains mandatory alongside optional NAS/server hosting.

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
