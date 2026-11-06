# Independent Android authority

Connect must support two host choices: the Android phone itself, and an optional
always-on NAS/server. No desktop app or other authority may be required to create
the phone-hosted network. Android hosting is required work, not implemented yet.
The current Android APK is a member client. This document is a qualification plan,
not a supported-host announcement. iOS hosting has separate platform gates.

The phone must run the unchanged pinned Python core and its genuine policy,
membership, revocation and evidence paths. Rust/Tauri remains the client shell
and fixed native adapter; it must not become an alternative authority engine.

## Embedded owner adapter qualification

`apps/connect/authority/embedded` supplies a fixed create/open/close adapter over
the real core. It constructs and signs core GenesisBlock/PolicyManifest models
in memory, starts NetworkAuthorityService on loopback, persists an initial
no-service policy, and enrolls its member through signed admin invite and join
requests. It avoids the desktop CLI's intermediate plaintext private-key files.
No generic HTTP proxy, path selection, key export or Python console is exposed.

The Android bridge in `apps/connect/native/android` uses separate non-exportable
Keystore wrapping keys and authenticated domains for owner and member custody.
Owner custody contains distinct root, authority and operator signing keys; it
does not reuse the existing device/controller credential stores. This first
owner profile requires Android API 28 or newer, an existing PIN/password/pattern,
and an unlocked device. The existing client platform minimum and Join flow are
unchanged. The app does not set credentials or weaken protection if unavailable.
Android Keystore protection is not a claim of independent hardware attestation.

Initialization reserves state before native key creation. Interrupted or existing
keys/state cannot be silently replaced. Sealed records use bounded no-follow
reads and fsynced no-replace commits under a live exclusive file lock. Reopen
checks signatures, keys, policy, member certificate and the existing database
before starting core; it never creates a replacement database for an old network.
Complete snapshot rollback protection and recovery remain separate work.

Identity keys are durably sealed before the authority starts or enrolls its member.
Public credential state is authenticated with an application-domain operator
signature. An expired member credential does not prevent loading owner custody,
but it grants no member access. Explicit owner recovery uses signed core admin
invite plus proof-of-possession join, preserving every identity key. This is
owner-authorized re-enrollment, not an extension of an expired certificate or a
relaxation of the core node renewal grace. Revoked/missing membership is refused.
The authority key's own validity/succession remains a separate lifecycle gate.

A signed application-local recovery intent is persisted before any enrollment
write. Uncertain outcomes block ordinary reopen and automatic retry. Explicit
reconciliation adopts only a genuine, already-issued core certificate; even an
expired outcome can be recorded without granting expired access. Cancellation
is explicit and permitted only when core has no enrollment outcome. These local
intent signatures are not independent core audit evidence.

An actual process exit after a staged ready-state fsync can leave a `.state-*`
file. Ordinary open refuses unrecorded staging. Explicit member reconciliation
accepts only bounded regular staging records with the existing operator's valid
application signature, matching immutable key records and identities, and the
single genuine core enrollment outcome. Recovered staging remains in place as
content-addressed evidence indexed by the newly signed committed state. Unknown,
unsigned, changed or ambiguous evidence is preserved and refused, never silently
removed or treated as an arbitrary allowed file. Initial setup without committed
state and complete snapshot/device-loss recovery remain separate gates.

Loopback serving has bounded connections and socket reads. Shutdown closes input,
waits a bounded time for handlers to settle, and retains custody/state exclusivity
if a handler has not finished. It never closes the database or releases its state
lock while an operation can still write.

The isolated engine APK exercises this adapter with genuine Android Keystore.
On first use it creates only its private qualification network; later starts
reopen it. Within each check it closes/reopens and compares public identities,
checks signed membership liveness and unsigned-request refusal, and checks that
owner ciphertext fails in the member custody domain. No production Create UI
is enabled by this harness. Physical process restart, missing/locked/corrupt key
behavior, recovery and second-device lifecycle require separate evidence.

Host tests in `test_embedded_owner.py` use the real core and a clearly test-only
encrypted vault; these tests do not qualify Android Keystore. CI runs them against
the single pinned core. Native build/installation and actual device acceptance
are recorded separately in `docs/plan-progress.md`.

## Android state publication

Android app domains forbid hard links. The Android custody adapter therefore
publishes fsynced staging files with Bionic `renameat2(RENAME_NOREPLACE)` through
the already-pinned CFFI runtime. Existing targets are refused atomically; there
is no check-then-overwrite or permission-policy fallback. Desktop publication
is unchanged. This owner qualification profile requires Android API35 or later
and a successful private-storage capability probe; the general runtime/client
minimum is unchanged.

Before owner creation/reopen, the harness verifies publication and collision
preservation using public bytes in a fresh temporary directory. It never probes
over existing authority files. A directory containing only the advisory lock
can enter explicit initial creation only when both fixed native custody aliases
are absent. Native create rechecks aliases and the core adapter rechecks files
under its lock. Existing markers, sealed state, staging, unknown files or either
alias always reopen/refuse; nothing is cleared or replaced. This handles a
failure before the initialization marker without resetting initialized custody.

These operations change no device security settings. Public Create stays
disabled; physical evidence is recorded separately from host tests and builds.

On 6 November 2026, source `3a1c7e9` passed on the physical Samsung SM-A176B
(API36) in the isolated engine-check package. The in-place update preserved
application data. Atomic publication/collision preservation, genuine local
authority/member checks, purpose-separated custody and close/reopen passed.
A separate cold process launch reopened the existing qualification network with
the same four public identity fingerprints and certificate ID. The source and
installed APK hashes and both run IDs/fingerprints are retained locally under
the isolated storage-fix worktree's ignored `temp/` directory.

This qualifies that positive storage/create/reopen/process-persistence slice,
not public Connect Create, device reboot/lock/suspend, missing/corrupt custody,
recovery, second-device integration or nontechnical usability. Production mobile
Create stays disabled. No PIN automation, permission changes, app-data reset,
startup-failure revalidation or merge was performed for this repair.

## Dependency gate

### Application adapter integration boundary

`embedded/connect_owner.py` supplies bounded fixed Connect operations over the
embedded core, reusing the desktop invitation, Space, policy and revocation
implementation. Native activation uses routine membership maintenance. Public
Space metadata is signed and root-bound in a separate private registry; missing
or changed initialized metadata is refused rather than reset. No attach,
private-key backup/restore, arbitrary route, filesystem or Python-name operation
exists on this boundary. Uncertain results stop automatic reuse. The registry
does not provide hardware anti-rollback protection.

`OwnerRuntime::from_native` is a native-code-only transport seam with existing
typed operations and readiness checks. It bounds requests/replies, refuses
key export and desktop import, and stops reuse after an uncertain result. It
does not expose a Tauri command or enable Create. Opt-in qualification packaging
and a private Android plugin now connect it to `ConnectOwner`: the plugin rejects
frontend invocation, uses a fixed native directory and fences uncertain or stale
sessions. The default app still has no embedded-owner activation. The Android
bridge library compiles, but the full Rust/app build and app-integrated
system-prompt/lifecycle checks remain open; see [the build-only bridge](../spikes/android-owner-bridge/README.md).
The focused CI workflow runs an explicit
allowlist of host real-core and native transport tests, not the full excluded
startup-failure suite.

App activation uses `EmbeddedOwner.open_for_use`: an expired membership, or one
with at most an hour left, is renewed automatically through the same genuine
core enrollment and signed durable intent as explicit recovery. Identity keys
and root ciphertext stay unchanged; a healthy reopen issues nothing. An existing
intent or an uncertain reply requires explicit readback/reconciliation and is
never replayed on reopen. Revoked membership is not re-enrolled. The low-level
`open` operation remains read-only for recovery tools. This does not enable
Create in the main app or make a background-availability promise.

### Read-only interrupted-membership inspection

A separate native-only inspection path reads an existing protected profile and
signed renewal intent without activating the authority. It uses a fresh inspection
session, never the uncertain writer session, and does not clear that writer's
poisoned state. The profile must be idle: an active owner lock, changed snapshot,
nonempty SQLite WAL/journal, invalid evidence or bounded-history limit produces
an unavailable/ambiguous observation. Inspection never checkpoints or repairs
the database, creates a lock file, renews, enrolls, reconciles, cancels, resets,
commits state or decrypts the root. Only daily owner/member custody is opened.

The bounded typed report distinguishes an exact linked recorded outcome, no
new issuance observed in the snapshot, ambiguous/invalid evidence, and no pending
update. Authenticated reports carry the network/device identity, operation UUID
and signed-intent digest. None of these statuses authorizes a retry or adoption;
even a matching expired certificate remains expired.

Existing schema-1 intents lack an exact operation-to-certificate link. A single
new compatible certificate therefore remains ambiguous. The reader also accepts
a schema-2 signed reference containing the exact certificate ID and digest; this
is exercised only by disposable real-core fixtures. No production schema-2 writer
or recovery action is introduced, and existing activation/reconciliation fences
remain unchanged. That reference is a local authenticated observation, not an
independently verifiable core audit receipt or proof of complete issuance history.

Host checks cover scope/signature/reference failures, multiple or missing
outcomes, revoked/expired/future certificates, journal refusal, unchanged file
bytes/inventory/mtime, and preservation of poisoned-session/activation fences.
The private Java/Kotlin/Python library compiles with the inspector included;
this does not qualify a complete Android app or physical custody/recovery.

### Separate root custody

New embedded profiles use schema 3: `root.sealed` is wrapped under a separate
Android Keystore alias, with authentication required for each cryptographic
operation. A native `BiometricPrompt.CryptoObject` binds a fresh strong biometric
or screen-lock confirmation to that exact cipher operation. Daily owner custody
contains only authority/operator keys; the member has a separate envelope.
Ordinary reopen checks root-ciphertext integrity, the root alias policy and the
public signed founding record, and never decrypts the root. No root export or
generic signing command is added. Root signing in Python cannot promise complete
memory zeroization; this is wrapped software identity custody, not a hardware
Ed25519 signing implementation.

Per-use root operations authenticate the initialized cipher before sending any
GCM authenticated context or payload. Android's provider can cache an early AAD
failure and report it later from `doFinal`; a successful prompt cannot repair
that already-failed operation. The shared `ProtectedRecordCipher` keeps this
order for both wrapping and unwrapping, with a host regression for exact-cipher
authorization, denial, cached failures and real GCM context integrity. Root policy
and the sealed-record format are unchanged. Host tests do not qualify a device.
See [Android Keystore's AAD/error handling](https://android.googlesource.com/platform/frameworks/base/+/5e1b258dd5beca122cef6dc2cb857bd559db9bc3/keystore/java/android/security/keystore2/AndroidKeyStoreCipherSpiBase.java).

On 6 November 2026, standalone Root Check source `69a8e17` passed on the Samsung
SM-A176B/API36. Native system confirmation completed, the root was wrapped, and
the real core created and checked the local authority/member. In-process
close/reopen passed. After force-stop and cold launch, the check reopened the
same four public identities and certificate, requested no root authentication,
and preserved the root/owner/member ciphertext and committed state bytes.
The completed qualification network is retained. This accepts that positive
creation/reopen slice only: root decryption/recovery, destructive interruptions,
second-device enrollment and the full Connect bridge remain unqualified. The
[observation record](evidence/android-root-custody-2026-11-06.json) contains no
credential or key material and is not independent core audit evidence.

The owner profile now requires Android 15/API35 to avoid older Android
unlocked-device-key lifecycle defects. General client Join remains unchanged.
Schema-2 qualification profiles are preserved and refused before decryption;
an explicit migration/recovery ceremony is not implemented. Qualify new custody
without touching the installed old profile by building the isolated engine APK
with `-ProotCustodyQualification=true` and installing with `-AppKind RootCheck`.
Its fixed package is `org.genesismesh.connect.authoritycheck.rootcheck`.
Creation asks for system authentication on the phone; never enter its credential
through automation. Root succession, mobile recovery and production Create
remain gated.

References: [Android auth-per-use crypto](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt.CryptoObject),
[Keystore authentication and unlocked-device policy](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder).

Root policy qualification accepts both per-use timeout representations: `-1`
in the public KeyInfo documentation and `0` in current Keystore2. It still
requires authentication and the exact strong-biometric/device-credential types,
rejects positive cached-authentication windows and binds every use to its
own system CryptoObject prompt. See [KeyInfo](https://developer.android.com/reference/android/security/keystore/KeyInfo)
and [AOSP Keystore2 metadata](https://github.com/aosp-mirror/platform_frameworks_base/blob/master/keystore/java/android/security/keystore2/AndroidKeyStoreSecretKeyFactorySpi.java).

The embedded owner follows core's founding-key lifetime semantics: the genesis
authority's legacy `valid_to` is informational. Its `valid_from` retains a
five-minute clock tolerance. This does not relax successor-key lifetimes or
membership validity. A real-core, controlled-clock regression reopens the same
identity on day 91 while refusing the expired member credential. Verification
reports the particular signature, key binding, time, policy or membership check
that failed, without including private values.

Run from the repository root, using a Python environment with pip:

```text
python scripts/probe-android-authority.py --output temp/android-authority-probe
```

The output directory must be new. This downloads binaries only for arm64
Android API24 and compatible older API levels, CPython3.13, using the single
core requirements pin. It resolves the full dependency closure, not just the
core's pure-Python wheel. It does not install or execute downloaded code.
`report.json` records availability and hashes; `resolver.log` identifies the first
unavailable dependency. A partial download or timeout cannot pass. Success is
wheel availability only, never proof that hosting works.

The manual GitHub workflow **Android authority dependency gate** runs the same
probe and retains its report even on failure. It deliberately fails while a
dependency is missing; it does not weaken the normal Android client build gates.
It should be rerun after core dependency changes or supplying new Android builds.

On 5 November 2026, qualification with core 1.9.1 failed at its exact
cryptography 50.0.0 requirement. The Chaquopy index offered 42.0.8; official PyPI
listed no Android wheel for 50.0.0 or the required PyNaCl 1.6.2. Build and qualify
the supported versions and their native/transitive dependencies for Android.
Do not downgrade requirements, use Linux wheels, skip dependency checks or
replace cryptographic implementations. An independently built wheel directory
can be supplied with `--wheelhouse`; the requirements still constrain versions.

## Implementation sequence and acceptance

The **Android authority source wheels** GitHub workflow builds all four native
packages and resolves the complete binary dependency set on relevant pull
requests. It can also build one package manually for diagnosis. The collected
artifacts must match the source lock and pass the original core requirement
resolver plus an Android-specific dependency graph check. This is a build
qualification gate, not a complete embedded authority.
The workflow verifies the exact installed dependency against the core pin,
downloads the hash-locked upstream sdist, cross-builds arm64/API24/CPython3.13,
and checks CPython 3.13 interpreter/ABI compatibility, matching expanded filename
and WHEEL tags, native architecture and 16 KiB ELF alignment. Older compatible
CPython abi3 wheels remain valid. It
retains source provenance, compiler diagnostics and produced wheels. On x86
runners, arm64 execution is untested and remains a physical-device gate.

The source lock lives in `scripts/android-authority-sources.lock.json`. After a
core release update, install its requirements and run:

```text
python scripts/android_authority_sources.py lock
```

This derives exact versions from the released core and its model dependency;
it does not introduce another core release pin. Review the new source hashes
and rerun qualification. The source lock deliberately refuses an unreviewed
release change. It currently covers four missing native dependencies,
not the full transitive wheel closure or a production software bill of materials.

Cryptography's Android build uses two narrowly scoped build patches:
its CFFI build script assumes a different Python SDK header layout. The recorded
patch queries the cross environment's target `INCLUDEPY` on Android and checks
for `Python.h`. The original sdist and patch are separately hash-locked and
reported. It changes header discovery, not cryptographic operations or core
policy/identity semantics. The second declares an explicit dependency on the
target shared Python runtime: the physical engine check found unresolved Python
symbols in the abi3 extension when Python was embedded in Android's local loader
namespace. It changes linkage rather than loading libraries globally. Both
patches are separately hash-locked. Runtime qualification remains a separate gate.

CI also checks the cryptography extension's ELF dynamic dependencies. The new
check was verified against both actual artifacts: it refuses the original
device-failing wheel and accepts the corrected build. It is a necessary linkage
check, not a replacement for loading and exercising the extension on a phone.

PyNaCl builds its complete bundled libsodium source as a static target library.
CFFI builds the separately hash-locked libffi source in
`scripts/android-authority-native.lock.json`, also statically. Both builds refuse
a host compiler or host Python library. Cross-compilation does not execute
Android native tests on the x86 runner. CFFI's selected version must satisfy the
active Android requirements of both cryptography and PyNaCl; it is locked as a
build constraint so later host resolution cannot silently change the binding.

Build records on 5 November 2026: pydantic-core, cryptography, PyNaCl and CFFI
source wheels passed Android arm64/API24, CPython 3.13 ABI/metadata and 16 KiB
checks. The unchanged core requirements resolved, and target-marker validation
found 28 reachable packages. This check uses Android and CPython 3.13 markers,
including transitive extras, instead of trusting pip's build-host marker
evaluation. The minimum marker profile is recorded in its report; it is not a
device execution result. Physical embedded-core, linked-library and hosting
lifecycle qualification remain open. No phone authority is enabled.

The final resolver result is bound to a manifest of the exact collected native
wheel filenames, versions and SHA-256 hashes, plus both source locks. A newer
compatible index version or a different build of the same version cannot replace
them. Every incoming active dependency constraint is validated before repeated
graph expansion is deduplicated; compatible cycles terminate without hiding a
conflicting diamond constraint. Graph validity alone is not a qualified bundle.

1. Build missing wheels reproducibly from verified upstream sources. Keep source
   digests, compiler/NDK/ABI/API versions, linkage, licenses and vulnerability
   qualification with the artifacts. Require 16 KiB native alignment checks.
2. Package embedded CPython (Chaquopy is the first candidate) and the exact
   resolved closure. On the physical phone, import the core and exercise real
   signing, verification, model parsing, SQLite and HTTP operations.
   The isolated `spikes/android-authority` engine-check APK now supplies this
   fixed test harness. CI packaging and physical execution must pass before
   treating the runtime as qualified; it does not enable authority creation.
3. Adapt the existing fixed owner runtime to a serialized native-local embedded
   boundary. No generic Python execution, command/path dispatch or admin listener
   belongs in frontend IPC. Keep owner secrets in Android Keystore-backed storage
   with separate purposes. Do not reuse device or controller-key custody domains.
4. Create a network from the fresh phone app. Keep the same authority/root/member
   identity across restart. Preserve interrupted or locked state; do not silently
   generate replacements. Prove recovery and refusal after tampering.
5. Enroll a second device and perform actual allowed/refused operations while
   all other authorities are stopped. Revoke it and prove its next operation is
   refused. Test interrupted approval and uncertain replies without auto replay.
6. Integrate the guided Create/Join flow only after real runtime support exists.
   Share owner-control semantics with the NAS/server host. Prove its independent
   setup/phone administration rather than treating a desktop app as prerequisite.

Initial Android hosting is foreground-only. Clearly show when the network is
unavailable. Test lock, sleep, network switching, force-stop, process death and
reboot. Background service/notification and battery-policy work is a separate
gate before any continuous-availability claim. Moving to a server must preserve
identity with old-host fencing; it must not run cloned competing authorities.

References: [Chaquopy Gradle integration](https://chaquo.com/chaquopy/doc/current/android.html),
[Chaquopy package guidance](https://chaquo.com/chaquopy/doc/current/faq.html),
[cibuildwheel Android builds](https://cibuildwheel.pypa.io/en/latest/platforms/),
[Android 16 KiB support](https://developer.android.com/guide/practices/page-sizes).
