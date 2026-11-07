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
| CONNECT-03 durable workflows | Access dispatch/readback journal, archives; owner nonce reservations; bounded native client admin-enrollment/status journal | Durable join/renewal/recovery, complete admin enrollment UX/replacement and operation-specific reconciliation |
| CONNECT-04 prerequisites | Authenticated resource-host release/profile/ownership discovery | General feature, verifier, actor and deployment discovery |
| CONNECT-05 owner Requests | Authenticated transport; fixed managed-core/target dispatch and fresh candidate verification; native key custody; durable host records and native client same-ID enrollment/status recovery; guided host review and read-only member status/recovery screens; access requests from devices and agents, answered on the owner's Requests card (#29) | Qualified native user presence for UI mutations; installed host opt-in/review/revocation acceptance; phone request creation/pairing actions, complete recovery, assisted parity and physical gates |
| CONNECT-06 lifecycle | Existing disconnect/reconnect/leave; administrative native-store refusal and cleanup | Physical lock/suspend/force-quit/reboot/network switching and user-presence handling |
| CONNECT-07 distribution/hosting | Existing Tauri packaging and headless Linux server; CI builds the full Android owner app with the embedded authority (#25) | Signed fresh-machine installer/update/service/uninstall acceptance and guided host setup |
| CONNECT-08 continuity | Existing encrypted recovery and server restore; recovery file for a phone-run network, exported after root authentication and restored onto another phone with the same identity (#27) | Physical save/restore on the phone, checkpoints, missing-history reconciliation, restricted restore, and old-host fencing (key succession after a lost phone) |
| CONNECT-09 agents | `genesismesh-connect-agent`: own identity through pairing, MCP read tools and `ask_for_access`; real-core fixture of two agents on one machine with separate Spaces and independent revocation (#28, #29) | Approving each read on the phone, write/service tools, descriptors and an agent label in the owner's view |
| CONNECT-10 general policies | Resource recipients/expiry/size/duration and extra gates; plain end choices and a review naming who gains and loses access (#30) | Visual general policy templates/selectors/gates, impact preview and semantic round-trip |
| CONNECT-11 Activity/evidence | Ordinary local access history, attention filtering, status readback and unsigned record export | Core signed evidence timeline/audit packs/independent verification and execution attribution |
| CONNECT-12 assistance | Shared typed operation boundary; no model configured or enabled | Opt-in constrained assistance using the exact manual review/authorization/dispatch path and privacy controls |

The remaining programme also includes attestations, agreements/delegation,
federation/trust paths, remediation/oversight, offline grants, data governance,
invocation/freshness, selective disclosure/integrity, interop, fleets,
succession/HA and exit. The [complete journey mapping](../contract/connect-journeys.json)
retains their scope and acceptance gaps. Core remains responsible for trust and
policy semantics; Connect supplies the usable workflows and fixed adapters.

## State on 7 November 2026

Merged from 6 to 7 November (#24 to #36):

- **Phone-run network in the app:** the owner test build
  (`org.genesismesh.connect.ownerqualification`) offers *Start on this phone*.
  Create and Open run the foreground setup coordinator; the network reopens at
  launch and after a stopped session, one setup at a time, never repeating a
  write. The bridge keeps serving while another screen covers the app, and
  calls from async commands no longer panic. A Create whose root prompt is
  declined or times out leaves nothing behind and can be tried again (#25).
- **Recovery** of a phone-run network onto another phone (#27).
- **Agents** with their own identity, MCP read tools and independent
  revocation (#28), and **access requests** answered on the owner's screen (#29).
- **Everyday UX:** administrator screens hidden until a presence check exists,
  the comparison code shown large on the joining device, plain wording, name
  wrapping, accessibility fixes (#26), and a plain Manage access (#30).
- **Opening and picking:** items this device shares open in their app, and
  Photos & videos uses the system photo picker (#33).
- **Everyday screens redesigned** from a designer's proposal: one token-based
  stylesheet, compact type, list rows, bottom sheets, a sidebar on wide windows
  (#34).
- **Reads across restarts and refreshes:** a host that cannot ask its network
  computer answers busy, not refused, and devices ask again for about 15 seconds
  on lists and reads, also when a trust refresh ends the connection (#35, #36).
- **Recovery export** keeps the key when the share sheet fails, and a declined
  export no longer ends the session (#32).

Observed on the Samsung SM-A176B (Android 16), owner test build:

| Step | Result |
| --- | --- |
| Create through the app, root key behind the system authentication prompt | Passed (build `8a4e85d`) |
| A second device (headless, in WSL) joins with the comparison code | Passed; the phone's authority issued its certificate |
| Share a file from the phone; the second device reads it with a receipt | Passed |
| Force-stop and relaunch | Passed: reopens without a prompt; the second device's read succeeded 34 seconds after launch, on its third attempt |
| Open an item this device shares; Photos & videos | Passed: the file opened through the Android chooser; the system photo picker opened, and cancelling changed nothing (#33) |
| 25 consecutive reads from the second device, Connect on screen | Passed: 25 of 25 over 78 seconds (#36) |
| Process paused for 5 minutes in the background, then resumed | Passed: stayed ready |
| Create whose prompt timed out | Rolled back and offered a retry with a plain message (builds `9c42045`, `87c6025`) |

Known limits and open findings on the phone:

- **Foreground only:** other devices reach the network only while Connect is on
  screen. With it in the background, reads timed out and Android later ended the
  process.
- **Unexplained, seen once:** a process left running for about 12 hours kept
  reporting "Authority relay did not become ready", in the foreground too, with
  the phone online. A force-stop and relaunch cleared it at once. Pausing the
  process for 5 minutes did not reproduce it; the cause is unknown.

Not yet run on the phone: saving and restoring a recovery file, and removing a
device. Saving and restoring need the owner at the phone to confirm the system
prompt. Public Create in the normal app stays off.

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

At that runtime-only revision, the harness created no network or owner identity. It did not qualify authority
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

The next native dependency retains the exact reviewed client enrollment before
its first send. After reservation/lost reply/restart it only checks the same ID;
it does not generate another request/key, resend enrollment or dispatch pairing
commands. Native context and fresh core membership are checked around transport,
returned requests/grants are matched exactly, and status observations stay
distinct from uncertainty and remembered history. This bounded coordinator is
not exposed through mutation IPC. Full phone enrollment UX, explicit replacement/
recovery, qualified presence and installed/physical/usability acceptance remain
open; it does not substitute for independent phone-local authority hosting.

Member phones/computers now have Devices → View joining permissions for their
saved administration request. Two read-only native commands return a minimal
display projection and check the retained ID; signed requests, grants and keys
do not cross this IPC. Empty inspection creates no credentials or workflow
marker. Each state explains its next step, previous approvals stay historical
until a fresh check, and abandoned/network-changed screens ignore late replies.
Request creation, approval and joining controls remain unavailable pending
qualified native presence and their complete reviewed workflows. Browser fixture
coverage and native source/packaged projection checks are recorded separately
from installed-app, physical lifecycle and first-time usability acceptance.

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
| Physical lifecycle and native presence | Not performed; no device/security changes in this slice; Android owner acceptance remains separate from this slice |
| Usability | Browser fixture inspection includes desktop/narrow layouts and lost replies; nontechnical first-use acceptance in an installed app remains open |

The backend milestone is implemented; the whole phone-owner journey remains
partial. Production mobile Create stays disabled and independent phone-local
real-core authority remains mandatory alongside optional NAS/server hosting.
### Embedded owner qualification — 6 November 2026
Embedded owner adapter progress on 6 November 2026 (PR #22): fixed in-memory core
initialization, signed self-enrollment, purpose-separated Android Keystore custody
and create/open/close persistence are implemented behind the developer harness.
Twenty-eight Windows host tests pass using the real core and explicitly test-only
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
An actual child-process exit at the post-fsync/pre-replace boundary leaves a
complete staged state and recorded core issuance. Authenticated reconciliation
recovers that outcome without new enrollment, preserves identity keys and the
staging file, and indexes its digest in signed local state. Ordinary open refuses
unrecorded staging; unsigned or changed staging is refused without discarding it.
These are hosted/host simulations, not physical elapsed-time or lifecycle tests.

The first Samsung attempt at that revision passed the seven runtime checks, then was refused by
the native device readiness guard before creating an owner network. Its specific
result is `secure_screen_lock_required`; configuring a credential is a local user
step. Real Android create/reopen and
process-restart identity acceptance were pending at that checkpoint; production Create stayed off.

### Later storage proof and separate root/integration gates — 6 November 2026

The Android atomic-publication repair at `3a1c7e9` subsequently passed genuine
phone-local create/close/reopen on the Samsung SM-A176B/API36, followed by a cold
process launch with unchanged root, authority, operator and member fingerprints
and certificate ID. That was the earlier combined-root custody format. It proves
that positive storage/persistence slice, not the newer per-use root ceremony,
device-loss recovery, app Create or second-device acceptance.

The checkpoint at `1423db5` separates root ciphertext/custody, leaves the root
encrypted during ordinary reopen, matches core's founding-key lifetime and
maintains routine membership through signed intents without automatic write
replay. Focused host/native and contract CI passed there. At that checkpoint the
newer GM Root Check profile was an unfinished initialization: no completed owner
identity was recorded. Key-policy metadata alone did not accept physical per-use
root authentication or create/reopen under that root format.
That profile was preserved during the following source/build work. Later on
6 November, the user authorized clearing only the unfinished GM Root Check test
data. Two creation retries reached Android's system dialog but timed out without
local authentication; those attempts did not complete root custody. The fixed
Root Check package now waits for a local **Start check** tap, so its authentication
window is not consumed while exchanging chat messages. Connect data is unchanged;
no automatic custody replacement or reset action is added to either app.

The first manually started check recorded native root authentication as
`authenticated`, followed by `IllegalBlockSizeException` while wrapping the root;
the profile still contained only initialization state. This accepts the local
system-confirmation event, not completed root custody or network creation. A
subsequent fix authenticates the exact cipher before submitting GCM context or
payload. The host regression reproduces cached pre-authentication AAD failure
and checks denial plus real GCM context integrity.

The corrected standalone Root Check build at `69a8e17` then passed on the
Samsung SM-A176B/API36: local system confirmation, root wrapping, genuine
phone-local authority/member creation, purpose-separated custody and close/reopen.
A separate force-stop/cold-process run passed as `reopen` with all four identity
fingerprints, certificate ID, sealed custody files and committed state unchanged.
That run requested no root authentication. The completed test network is retained;
no further reset is authorized by this validation result. These are positive
qualification-app results, not full Connect, recovery, second-device or general
background-lifecycle acceptance. See the [dated observation record](evidence/android-root-custody-2026-11-06.json).

The next independent dependency is now implemented behind the opt-in
`android-owner-qualification` feature and fixed
`org.genesismesh.connect.ownerqualification` identifier. A private native bridge
connects `NativeOwnerTransport` to `ConnectOwner`, using native-selected no-backup
storage and the existing vault. Registration activates nothing. A Rust catch-all
rejects frontend plugin commands; no automatic startup, public Create or
administrative mutation path is enabled. Native calls reserve their session and
sequence before dispatch, have bounded queues/deadlines/replies, reject stale or
foreign outcomes, and stop reuse after uncertainty. Lifecycle stop/destroy fences
the session and queues shutdown; reopening is not automatic. This conservative
qualification behavior also needs physical review around system-authentication
screens. It is not a background or continuous-availability promise.

This continuation's permitted host checks passed: three real-core bootstrap
tests, three correlation tests, four existing transport tests, one native session
guard test and two isolated packaging tests. The Android Kotlin/Java bridge and
whitelisted Python closure compiled into a build-only AAR against the pinned
Tauri SDK; all 74 packaged native objects passed 16 KiB ELF/RELRO inspection.
The full Windows Android-app build stopped because Application Control blocked
a Cargo build script (`OS4551`). It was not retried or bypassed. The Android Rust
app boundary and complete APK therefore remain uncompiled/unaccepted locally.
No device operation, install, data/key reset, excluded startup-failure suite,
publication, merge or deployment was performed for this continuation.

See [build-only bridge instructions](../spikes/android-owner-bridge/README.md).

A subsequent local Phase 1 dependency adds fresh read-only pending-membership
inspection. It authenticates saved daily custody and signed intent, then checks
an idle offline core database without starting an authority or writing state.
The typed result distinguishes an exact linked outcome, no new issuance observed,
ambiguous/invalid evidence and no pending intent. Inspection cannot unpoison a
writer, approve recovery, retry enrollment or clear the intent. An active lock or
unsettled WAL/journal is refused rather than repaired.

Legacy schema-1 intents cannot establish the exact operation-to-outcome link;
even one compatible new certificate stays ambiguous. Schema-2 exact signed
references are reader-only fixture coverage, not a production writer. Reports
are local observations, not independent core audit evidence. Focused host tests
and build-only native compilation support this dependency; the full app build,
root-custody recovery and end-to-end phone-owner journey remain open. The later
standalone Root Check positive result above does not qualify this app bridge.
No device state was touched and no publication or merge was performed here.

**“Create and run my network on this Android phone.”** The independent-phone
proof above is required alongside the optional server profile. Native dependency
qualification and lifecycle work remain open; no unsupported Create button is
enabled by the plan update.

A subsequent local source/host-fixture slice adds the portable foreground
setup/open coordinator. Native embedded discovery replaces desktop-file
assumptions on this path. Durable reservations bind one authority setup and one
saved device; lost invitations or unfinished enrollment are not replayed. Fresh
Open can finish an already persisted matching credential and rebind only the
same pin/device to a new loopback port. Five refusal fixtures and seven explicit
disposable real-core fixtures pass; existing native/inspection checks also pass.
The disabled private Android workflow factory now calls `android_owner::prepare`;
it is not invoked by frontend commands or startup. Source glue defers saved
local-owner maintenance until rebinding. Full-app compilation, actual phone
setup/lifecycle, recovery and second-device acceptance remain open; no device,
reset, installation, publication or merge operation occurred in this slice.

The next isolated host chain uses that embedded `ForegroundNetwork` for two
separate sealed profiles through the actual comparison-code ceremony, QUIC
authority bridge and core enrollment. Six integration fixtures passed after
exposing/fixing four gaps: approval callback replay after an uncertain response,
pairing retries during pending enrollment, client relationship persistence
before final confirmation, and local commit using pre-revocation trust. Local
consumer actions now share the tested portable pairing orchestration; Requests
retains its controller checks and shares the fresh candidate-trust check.
With the prior focused regressions and shared-gate test, 29 checks passed.
This is [source/host integration evidence](android-authority.md#embedded-owner-comparison-code-pairing-chain),
not physical second-device, human comparison or first-use acceptance. App-shell
compilation, phone lifecycle and full recovery remain open. Gates, inspector and
retained app/phone data are unchanged; nothing was installed or published.

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

## Embedded protected-resource chain — 6 November 2026

The qualified lost-confirmation recovery from `76885bd` now leads to actual
protected operations, rather than only diagnostic messages. Six explicitly
selected disposable host fixtures use the embedded `ForegroundNetwork`, genuine
comparison-code pairing and core enrollment, sealed independent profiles, and
real Iroh QUIC. They cover:

- Nested folders and verified multi-window binary downloads in both directions,
  after the joining client reopens and explicitly finishes its original pairing.
  Each listing and download window reaches the genuine core decision route.
- A paired, cryptographically authenticated member without that folder's
  permission receives neither a directory page nor any file output.
- Narrowing the full-file size policy stops the next window at the confirmed
  offset. An explicit later policy version permits the same snapshot to resume.
- Revocation refuses protected metadata and further download bytes even before
  cached diagnostic-session trust is refreshed. Normal shutdown of an already
  running authority also refuses further protected operations.
- A joined device creates a TCP service through the authenticated bridge and the
  fixed embedded owner adapter. A real echo works; wrong kind/collection never
  reaches the target; a live policy change closes the stream and refuses new
  connections. A stale policy version cannot overwrite the newer one.

The TCP fixture reproduced excessive stack use in the composed forwarding path.
Moving its two bounded I/O buffers to the heap fixed that failure on the normal
test stack without changing protocol, authorization, buffer capacity or shared
byte-budget rules. Both existing service-limit unit tests pass alongside the six
resource fixtures. These are eight checks run for this slice; the earlier
41-check recovery checkpoint is historical evidence, not a newly rerun total.

[Validation record](evidence/embedded-resources-2026-11-06.json).
The focused workflow selects these exact source/host checks for future CI; no
hosted run was dispatched. This is not installed-app, physical-phone,
nontechnical-user or full lifecycle acceptance. Public Create/administration/
recovery gates and the completed read-only membership inspector remain unchanged.
No device data was accessed, reset or installed; no blocked app-boundary build,
excluded startup-failure test, publication, merge or deployment was attempted.

## Native phone Requests commands — 6 November 2026

The next client dependency now retains the exact reviewed List/Approve/Reject
pairing command before its first send. It is bound to the protected profile,
network/root, authority host, member, separate administrative key, current grant,
original nonce/digest and candidate. A native presence seam gates dispatch; the
production adapter is unavailable and no mutation IPC is registered.

Interrupted/lost replies or reopen permit only authenticated Result readback for
that same operation. Current observation, historical observation and retained
terminal outcome remain separate. Matching membership/relationships or an Active
enrollment do not prove execution. Explicit retirement freshly checks a terminal
result and preserves history before a separate new review may occur.

The real embedded-core/QUIC fixtures cover the three pairing actions, changed
candidate, review/presence refusal, lost replies/restart, expiry, grant revocation
before/immediately after dispatch, controller membership revocation, and an
independent local approval that must not be attributed to the old command.
See [native coordinator contract](owner-client-commands.md) and the
[dated validation record](evidence/owner-client-commands-2026-11-06.json).

Phone-local authority hosting remains required and optional hosting stays
optional. This library qualification does not complete app-shell, installed
native presence, physical Requests, lifecycle, assisted or first-use acceptance.
The completed membership inspector, pairing-completion recovery and production
gates are preserved. No device operation or blocked full-app retry is implied.

## Saved device-request story — 6 November 2026

Devices now provides a read-only saved-request view: the original action, result
at last check, retained history and one explicit Check status action. It links to
joining permissions separately and keeps review codes/check timestamps in
details. The display distinguishes unsent, unknown, in-progress, confirmed,
retired, missing, damaged and unsupported states. A queue result stays a saved
snapshot. No review, signing, Execute, archive or presence-provider IPC is added;
production device-approval controls stay locked.

The native projection derives current profile/host/network/key context and
matches the exact saved reference around readback. Empty status checks create no
command or administrative key. Browser lifecycle tests fence late results after
close, Escape, navigation and network changes; errors retain historical evidence
and untrusted names remain plain text. Phone-width layout was visually reviewed
using a local browser fixture, with simulated native responses clearly separate
from the real-core native checks.

[Validation record](evidence/requests-display-2026-11-06.json) separates source,
browser, embedded-core/QUIC and unperformed app/physical gates. The focused CI
workflow explicitly selects the display/coordinator and browser files; no hosted
run, device operation or full-app build retry was performed. Phone-local hosting
remains required, and optional NAS/server hosting stays optional.

## PR 24 interruption follow-up — 6 November 2026

The ordinary pairing protocol retains its already approved, freshly verified
host route before final confirmation, so a lost final reply no longer leaves an
enrolled device without a reconnect path. The ceremony still returns an error;
the route is not proof of original completion. Default-feature restart coverage
requires the same key/certificate, no new invitation/enrollment and refusal after
revocation. Qualified exact-completion recovery remains separate.

Foreground owner Open accepts a changed certificate ID only after the same
pinned root/network/member passes current signed authority trust. The checkpoint
is then updated; no renewal or enrollment is replayed. Finishing setup requires
that verification. Real-core fixtures cover persisted renewal and refusal of
revoked, tampered and another node's valid certificate.

Expired Requests reviews may be explicitly archived locally only when the
durable record shows they were never submitted. History remains and another
command requires a separate explicit review. Dispatch expiry is unchanged;
submitted uncertainty cannot use this path. The display explains that an unsent
archive was never sent rather than describing a checked host result.

The existing owner-app branch and committed second-device helper are retained.
These are local source/disposable-core tests, not new app/physical acceptance;
public Create and production administrative authentication gates remain as they
were. No device, security, publication or full-app build operation is implied.

See the [follow-up validation record](evidence/pr24-continuity-2026-11-06.json)
for selected checks and separate app/physical/hosted gates.

Validation: 55 selected source/disposable-core/frontend checks passed, plus
TypeScript, scoped Rust formatting, focused workflow lint, contract and whitespace
checks. Hosted CI, full-app/workspace and physical acceptance were not rerun.
