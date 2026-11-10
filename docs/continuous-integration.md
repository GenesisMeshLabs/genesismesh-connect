# Continuous qualification

Every main push and pull request runs the existing contract/provenance workflow
and `Connect qualification`. The latter can also be started manually. It checks:

- Frontend state tests, TypeScript and Vite.
- Core and generated-schema tests on Linux and Windows at the declared minimum Rust.
- Released pinned Python authority tests; disposable Linux native-key lifecycle;
  real core/QUIC, access and owner-control checks; standalone authority/recovery;
  Linux desktop and headless-host compilation.
- Journeys on a real node, in their own job: the app's own command tests (waits,
  downloads, sends, sharing, lifecycle), then the headless node with the
  packaged authority while devices pair, share a folder, send into an inbox,
  resume transfers, restart, and read through a network computer restart. They
  run one at a time, about 13 minutes. Then the desktop app itself, a debug
  build with the bundled pages, is driven through its screens over WebDriver
  (`tauri-driver` with WebKitWebDriver, a virtual display and a throwaway
  keyring): create a network, invite the headless test device, compare codes
  and approve; the device receives files, the app sends it an 8 MB file and
  is closed partway, then restarts, shows the unfinished send and continues it,
  and the received file's SHA-256 is compared; then remove the device, restart
  and reopen (`apps/connect/tests/desktop`). Screenshots of each step are kept
  with the run.
- The same desktop journey on Windows, in its own job: the Windows app in
  WebView2 with the authority it bundles and the owner key protected by DPAPI,
  driven by `tauri-driver` with the Microsoft Edge WebDriver that matches the
  runner's WebView2. Windows keeps app data and keys in the account's own
  folders and Credential Manager, so `run.ps1` refuses to run outside CI
  unless given `-OnThisAccount`. Both journeys build the app with the
  debug-only `webdriver` feature: on Windows it passes Edge WebDriver's
  debugging arguments on to WebView2, and on both it takes the file to send
  from `CONNECT_TEST_PICK` instead of the native picker, which WebDriver cannot
  reach. Release builds cannot contain it. A preflight first checks that
  the app starts on its own, and Edge WebDriver's verbose log is kept with the
  screenshots.
- The send interruption journey on Android, on an emulator, in its own job.
  The headless node runs the network on the runner. An x86_64 debug test
  APK, built with the same debug-only `webdriver` feature, runs on an API 35
  x86_64 emulator, and its WebView is driven over the DevTools protocol, which
  debug builds allow (`apps/connect/tests/android`). The phone joins and the
  comparison codes are checked. The test device joins and receives files. The
  phone sends it an 8 MB file and is force-stopped partway, as Android ends an
  app. It must keep its send record and its copy of the file. It opens again,
  shows the unfinished send and continues it. The received file must have the
  same SHA-256 with no second copy, and the phone's copy and record must be
  gone. Then it is stopped and opened once more. The Android test build takes
  a file the journey places in its cache instead of the system picker, so the
  picker itself is not covered. Screenshots, the node's log and the
  emulator's logcat are kept with the run. This is emulator evidence; a
  physical phone is a separate check.
- An arm64 Android debug APK built with the existing initialization/branding/
  permission patches, followed by signature verification, 16 KiB ELF/RELRO/ZIP
  alignment refusal checks and SHA-256 inventory.

Download the Android APK from the run's **Artifacts** section. Its package is
`org.genesismesh.connect.qualification`, shown as **Genesis Mesh Connect Test**,
so installing it preserves the ordinary app and its network. It is a development
build with a runner-local development signing identity, not a store release. Updating a device
requires compatible package/signing identity; do not automatically uninstall a
user's app or erase its data after a signature mismatch.

On the Windows development computer, install a downloaded qualification APK with:

```powershell
./scripts/install-android-test.ps1 -Apk <downloaded-test.apk>
```

The installer checks the exact test package, native alignment and APK signature,
then signs a local copy with the existing standard Android debug key and updates
the connected phone in place. It refuses other package IDs, unauthorized devices
and failed signatures. It never uninstalls or clears data. Supply `-Python` if
Python is not on PATH, and `-DeviceSerial` when multiple phones are connected.
Its local JSON record distinguishes installation from visual/hosting acceptance.
This script uses only the standard development key, never a production identity.

Caches reuse compiler/dependency work; a newer push cancels older work for the
same ref. Actions are pinned to commits, workflow permissions are read-only,
and no user network, account key, mobile signing secret or deployment credential
is required. Test authorities/keyrings are created inside disposable runners.
No cloud resource or production authority is deployed by these workflows.

The authority release still has one source in its requirements file and the SDK
has one source in Cargo.toml. The build never upgrades those pins on its own.
The runtime packaging job reads the installed pinned wheel rather than requiring
a sibling source checkout. Local checks remain useful for fast feedback, while
the hosted run is the repeatable review record for each pushed commit.

CI establishes the checks actually executed by each job. It does not establish
first-time usability, physical Android/iOS behavior, mobile background hosting,
or successful signing/distribution on Apple devices. Physical lifecycle,
credential prompts and the real phone Requests journey remain distinct gates.
