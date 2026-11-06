# Disabled Android owner bridge qualification

This source/build dependency connects the existing native owner transport and
embedded application adapter. It does not enable phone Create, administrative
mutations, automatic authority activation or a recovery/reset operation.
Do not install or operate a device as part of these build checks.

The call path is `OwnerRuntime` → private native plugin →
`android_connect_owner` → `ConnectOwner` → the unchanged pinned core. Native code
selects the app's no-backup directory and vault. Requests contain no selectable
directory, HTTP route, Python name or key material. Registration starts no
Python/authority and creates no custody keys. A Rust plugin handler explicitly
rejects every frontend call, including mobile's otherwise automatic fallback.

Each process permits one session. Calls reserve their sequence before Python
execution; queues, request/reply sizes and deadlines are bounded. An uncertain
result, stale scope or lifecycle stop prevents reuse. Shutdown waits behind
in-flight work; unsettled owner state is retained. No request is automatically
replayed or resumed after restart. This process-local fence is not a new durable
audit journal: the existing core/application intents retain their own semantics.
System-authentication/background interactions need separate physical acceptance;
the qualification session currently stops conservatively on Activity stop/destroy.

## Source generation and app build

The source-only private workflow factory now selects the portable foreground
coordinator, explicitly choosing Create or Open over this injected backend. It
uses native custody status and OS-selected paths, and retains durable reservations
around existing device preparation/invitation/enrollment. It is not called by
public commands or startup. See [foreground coordination and its remaining gates](../../docs/android-authority.md#foreground-setupopen-coordination).
The seven explicit real-core fixtures exercise this coordinator on the host;
neither those fixtures nor this library build compile/qualify its Android Rust
workflow boundary. No phone operations are part of that source/host slice.

The following bounded host chain adds a second sealed device, the actual
comparison-code ceremony, QUIC bridge enrollment, fresh core revocation checks
and interrupted/lost-response refusals. The app consumer flow shares the same
portable orchestration. See [chain evidence and limits](../../docs/android-authority.md#embedded-owner-comparison-code-pairing-chain).
It adds no physical-device, first-use or full-app acceptance to this library.

The native-only `inspectMembership` path has its own single-use read sessions.
It does not reuse, close or unpoison the writer, and it is still rejected from
frontend invocation. It reads the fixed existing profile without a publisher,
root authorization, authority startup or a state-changing action. The strict
report is at most 4 KiB; busy/changed snapshots and unsettled journals are refused.
See [inspection semantics and the legacy intent limitation](../../docs/android-authority.md#read-only-interrupted-membership-inspection).

From `apps/connect`, after `npm ci`, run:

```text
npm run android:owner:init
```

This generates an isolated Tauri project/configuration. Only the
`android-owner-qualification` Cargo feature registers the bridge. It is off by
default, refused outside debug builds and requires the fixed package identifier
`org.genesismesh.connect.ownerqualification`. The existing `workflow` Create and
production presence gates are unchanged. The native `prepare` entry is not wired
to setup, a frontend command or an automatic startup task.

For a permitted future full build, supply the exact qualified wheel closure via
Gradle properties `runtimeWheelhouse` and `runtimeRequirements`, plus a matching
Python build interpreter via `ownerBuildPython`. Gradle also accepts these as
`ORG_GRADLE_PROJECT_...` environment variables. Run:

```text
npm run tauri -- android build --debug --apk --target aarch64 --ci --features android-owner-qualification --config temp/owner-qualification.conf.json
```

`android:owner:init patch-existing` refreshes only that isolated project's
packaging. It refuses ordinary application IDs or a changed Chaquopy pin. Source
generation is idempotent. The source Sync task packages only the listed adapter
files, never test fixtures, and runs before Python asset merging. Core reads its
single packaged requirements pin; pip uses the exact hash-locked binary closure
with no index or source-build fallback.

## Independent library compile

The build-only AAR project checks the actual Kotlin/Java plugin, purpose-separated
vault and Python packaging independently of the Rust app executable. It has no
application/launcher and cannot stand in for a complete app APK.

From the repository root:

```text
node apps/connect/scripts/android-owner-qualification.mjs bridge-only
gradle -p spikes/android-owner-bridge assembleDebug --no-daemon -PownerRepository=<absolute-checkout> -PtauriAndroidDir=<pinned-tauri-crate>/mobile/android -PruntimeWheelhouse=<qualified-wheel-directory> -PruntimeRequirements=<hash-locked-requirements> -PownerBuildPython=<python-3.13>
python scripts/check-android-owner-aar.py spikes/android-owner-bridge/build/outputs/aar/genesis-mesh-owner-bridge-build-only-debug.aar
```

Use the Tauri SDK selected by `Cargo.lock`; the project verifies its version
against the app's dependency pin. Match the generated Tauri template's Gradle
and JDK toolchain. The independent project uses the same tracked packaging
fragment as the generated application, including its whitelist and hashed
requirements. The artifact checker verifies the compiled bridge/vault classes,
exact Python file inventory, core pin/metadata and arm64 16 KiB native ELF/RELRO.

## Recorded validation and remaining gates

On 6 November 2026 the initial library assembled successfully. Its 11 application files
and 74 native objects passed inventory/alignment inspection. Three bootstrap,
three correlation, four transport, one Java session-guard and two packaging host
checks passed. These host fixtures do not qualify Android Keystore or presence.

The subsequent read-only inspection dependency compiles into the same build-only
library with 12 application files (including `membership_inspection.pyc`) and the
separate `RecoveryInspectionGuard` class. All 74 native objects pass the existing
arm64/16 KiB checks. Host-only inspection fixtures preserve every profile file's
bytes, inventory and modification time, and forbid activation/network/root use.
They test a signed exact-outcome reference only in disposable setup; the existing
production intent format cannot confirm that linkage. No recovery action or
complete app/device acceptance follows from this library result.

The full Windows app build was blocked by Application Control while executing a
Cargo build script (`OS4551`). That blocked executable was not retried, renamed
or copied. No complete APK or Android Rust app-boundary build is accepted from
that build-only run. No publication, merge, install or device operation was
performed during that source/build continuation.

The earlier Samsung storage/create/process-reopen success used the older root
custody format. A later, separately authorized standalone Root Check run at
`69a8e17` passed per-use root wrapping, real authority/member creation and cold
process reopen on the Samsung. All identity/custody/state comparisons matched;
reopen requested no root authentication. See the [dated observation record](../../docs/evidence/android-root-custody-2026-11-06.json).
That completed test profile is retained. Recovery/root decryption, second-device
behavior, app-integrated lifecycle and nontechnical usability remain open. The
standalone result does not qualify this Tauri bridge or its full app APK.
