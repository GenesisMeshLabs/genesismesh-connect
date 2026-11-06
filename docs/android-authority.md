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

## Dependency gate

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
