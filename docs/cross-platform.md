# Cross-platform Connect

Connect is one Tauri application with a shared Rust core. A device's ability to
connect is separate from its ability to run the network authority, grant access,
or use an OS document provider. The implementation plan and running evidence
are under the ignored `temp/` directory.

## Implemented foundation

- Device identities use Windows DPAPI, Apple Keychain, Android Keystore-backed
  storage, or Linux Secret Service. A locked, missing or substituted credential
  fails without silently replacing the device or network root. Windows and iOS
  keep their existing protected-record/reference formats.
- Up to 32 saved devices, selected by name in Devices. The old single-device
  record migrates without changing keys. Selection does not erase another peer.
  Forgetting a peer cancels local sessions; it does not revoke network
  membership or policies on other devices. Only the network computer removes a
  device from the network, which revokes it and takes it off every Space. The
  authority route cannot be forgotten until another route is configured.
- Devices learn the network's other devices (name, node key, current address)
  from the network computer over the authority bridge and accept authenticated
  connections from them; together with paired devices, at most 32. The list
  never grants file access and follows the network computer's saved devices.
- One session endpoint accepts only the explicit approved identities. Outbound
  operations pin the selected node independently of its address. Each proof
  still binds the certificate, network/root, role, ALPN, challenges and TLS
  connection. Membership changes interrupt active operations.
- Desktop authority packaging supports native Windows, Linux and macOS hosts.
  Windows keeps DPAPI; Unix desktop helpers use a bounded inherited-pipe protocol
  to store owner keys through the Rust host's native credential store. Only
  opaque references persist in managed key files. A native target's sidecar is
  built on that OS/architecture, never relabeled from another platform.
- The network computer's connection setting (public relays, or private: local
  network only) reaches every guided device through the authority bridge; see
  [choose how devices connect](everyday-workflow.md#choose-how-devices-connect).
  Local network discovery (mDNS) is built for Windows, macOS, Linux and Android;
  iOS needs Apple's multicast entitlement first and uses saved addresses.
  Router port mapping (UPnP, NAT-PMP, PCP) is built for desktops only and used
  only by their own endpoints under public relays.
- New sharing hosts get separate sovereign identities and executor namespaces.
  Existing `connect-host` profiles remain usable. Collection policy selectors
  match the collection so unrelated folders do not veto one another.
- The authority bridge supports remote host enrollment with executor proof,
  renewal, public signed trust, and authenticated collection attestation/decision
  requests. It exposes fixed routes and read/list capabilities, with strict
  fields, audience, node/certificate binding, signatures and budgets. Remote
  sharing uses the same verified decisions and receipts as local sharing.

Normal pairing still starts on the network computer. It can add multiple peers.
New peers receive a host-capable enrollment, which alone grants no file access.
Desktop members can share folders and manage their own resources through the
fixed authority bridge. Files, media copies and inboxes have native mobile
picker paths. Shared TCP services and access-policy editing use the same device
identity and authority decision boundary; see [service sharing](service-sharing.md).

## Current platform evidence

| Platform | Implemented | Validation boundary |
| --- | --- | --- |
| Windows | Native app, DPAPI, bundled owner, device picker, sharing | Latest sharing/service source built and launched on 2026-10-28 with the freshly packaged authority. The native Shared screen and existing device names were observed after network permission was allowed. Core tests: 69 passed, 7 ignored. App-unit test rebuilding was blocked by the running authority file lock; the complete Windows gate has not been rerun. Earlier Application Control 4551 failures are historical evidence, not the current desktop build result. |
| Linux | Native app, Secret Service, bundled owner, desktop pickers | Native compilation/build, real keyring, owner restart and integration tests run in Ubuntu 24.04 WSL. A general desktop distribution/installer and physical cross-device matrix remain pending. |
| macOS | Keychain adapter, native authority packaging and desktop picker paths | Earlier source built a native app/authority and passed 36 core tests. Bundle-signature verification and interactive Keychain checks remain pending. The latest sharing/service source passes 69 core tests, 15 app tests, the real-authority service integration and Clippy on the Mac. Interactive validation of this update remains pending. |
| Android | Keystore adapter, initialization script, join scheme, official icons, backup exclusion | Earlier debug APK installed and launched on Samsung SM-A176B (API 36) through Windows USB. The latest sharing/services update builds an ARM64 debug APK on the Mac; installation and service acceptance for this update remain pending. Android enrollment, persistence and file-workflow acceptance remain pending. Earlier Windows Android compilation was blocked by Application Control 4551; its policy was not changed. |
| iOS | Existing Tauri shell and device-only Keychain format retained | Build 11 from source a510a15 is signed, installed and launched on the physical iPhone (2026-10-28). Strict bundle signature verification passed; device inventory reports bundle version 11, and the app process remained running after launch. The latest service/picker workflows still need physical acceptance. Earlier build 6 folder navigation was confirmed by the user. |

## Build hosts

Desktop prerequisites include Rust, Node, the platform's Tauri prerequisites,
Python with `venv`, and the sibling Genesis Mesh 1.8.1 source. Native desktop
`npm run tauri -- build --debug --no-bundle --ci` generates official icons,
packages the real authority into an isolated build environment, builds the UI,
and builds the app. Installed users do not need the build Python or checkout.
Use `CONNECT_CORE_SOURCE` for a different core source location and
`CONNECT_NA_PYTHON` for an explicit build/development Python. Build fingerprints
and dependency reports are under `temp/authority-build/<native-target>/`.

On Linux, install WebKitGTK 4.1, the AppIndicator development package and a
working Secret Service provider. Headless NAS use needs an intentionally
configured, unlocked credential service; there is no plaintext fallback.
For an isolated real-keyring test, run `bash scripts/verify-linux-store.sh`.
It starts a private D-Bus session and disposable keyring rather than unlocking
the account's login keyring. Extra arguments replace the default Cargo test.

For Android, set `JAVA_HOME`, `ANDROID_HOME` and `NDK_HOME`, then run:

```sh
cd apps/connect
npm ci
npm run android:init -- --ci
npm run tauri -- android build --debug --apk --target aarch64 --ci
```

The initializer pins compile/target SDK 36 (minimum 24), disables application
backup because the Keystore key cannot move to another device, and applies the
official artwork. Install SDK 36, build tools 36.0.0, platform tools and NDK
27.2.12479018 on the build host. Use `--target x86_64` for a matching emulator.
After regenerating Android files, rerun
`npm run android:init -- --patch-existing`. Generated Android/Xcode projects stay
ignored. On macOS use the existing `npm run ios:init` workflow; preserve the
selected signing team and handle account/keychain/device prompts locally.

## Remaining product work

Full feature parity is not complete. Files/media copies, inbox send/receive,
download resume, multiple resources, service tunnels and resource-policy editing
are implemented. Mobile folder-tree hosting, broader service compatibility,
installers, and physical acceptance of the latest picker/service workflows remain
pending. The latest Windows desktop build runs, and iPhone build 11 is signed,
installed and running. Installation does not establish physical acceptance of
every new service, policy or picker workflow.
Every device should eventually offer both sides of that workflow. Mobile
foreground/background rules remain platform constraints; no always-on iPhone
service, transparent VPN, or authority-on-every-phone claim is made.

The consumer browser serves the selected folder and its subfolders, to depth 16,
with policy/disk-limited files up to the exact JSON integer ceiling, 32 entries per page and at most 512 scanned entries per
folder. Every path component rejects links/junctions. Nested downloads bind their
directory to the signed request and token. Legacy 64-KiB list/read
remains compatible. Re-share explicitly to issue a larger-file permission. No upload/write
permission is implied by pairing, enrollment or read access.


## Build record: 2026-10-28

Windows and iPhone build 11 use application source `a510a15`. Windows was built
with the committed frontend and freshly packaged authority. The first attempt
could not replace the running sidecar; closing Connect released the file and
the native build completed without changing security policy. The updated native
sharing dialog lists the existing iPhone and Android device names.

The iOS archive was compiled on the Mac, signed after the user unlocked the
keychain locally, verified with `codesign --verify --deep --strict`, installed
with `devicectl`, and launched successfully. Device inventory and a later process
query confirmed bundle version 11 was installed and running. This records build,
installation and launch; physical service and file-picker acceptance is separate.

Detailed build logs, installation/launch JSON, executable SHA-256 hashes and
source provenance are in ignored `temp/latest-platform-build.json` and the
associated `temp/latest-*` reports.
