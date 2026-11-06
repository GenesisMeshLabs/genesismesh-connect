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

On 6 November 2026 the library assembled successfully. Its 11 application files
and 74 native objects passed inventory/alignment inspection. Three bootstrap,
three correlation, four transport, one Java session-guard and two packaging host
checks passed. These host fixtures do not qualify Android Keystore or presence.

The full Windows app build was blocked by Application Control while executing a
Cargo build script (`OS4551`). That blocked executable was not retried, renamed
or copied. No complete APK or Android Rust app-boundary build is accepted from
this run. No publication, merge, install or device operation was performed.

The earlier Samsung storage/create/process-reopen success used the older root
custody format. The newer Root Check profile remains preserved and unfinished;
per-use root authentication, recovery, second-device behavior, lifecycle and
nontechnical usability remain open. The older result must not be presented as
acceptance of this bridge or the new root ceremony.
