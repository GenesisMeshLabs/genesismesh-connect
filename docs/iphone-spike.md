# Physical iPhone validation

Current update (2026-10-26): build 6 is signed, installed and launched on the
physical iPhone. It includes subfolder navigation and breadcrumbs, path-bound
nested downloads, and the simpler Files/Devices/Settings interface. Code
signature, device-bound provisioning, join scheme and all 18 official icon sizes
verify. The user approved signing locally; no password was captured or keychain
access rules changed. Physical nested-folder/view/save acceptance is tracked
separately; build 5 retained the existing network as confirmed by the user.

Build 4 was signed, installed and launched successfully. The user reported
Windows/iPhone pairing and small-file browsing work. This is physical baseline
evidence, not acceptance of the newer download/view/export code. The existing
bundle ID, signing team, device-only Keychain format and official Genesis Mesh
icon are retained. The Xcode Rust phase keeps sandboxing enabled.

Earlier transport validation (2026-10-25): Mac SSH works again, the paired iPhone is available, and the
current unsigned iPhoneOS archive builds successfully. All 36 default Mac tests
pass. The user has now selected a Personal Team and created a usable Apple
Development identity. The signed app is now installed on the physical iPhone;
its code signature and device-bound development profile verify. After the user
approved developer trust, devicectl confirmed launch and the running process.
The user's phone photo also confirms the transport screen and running endpoint.
The first phone-to-Windows probe timed out. A subsequent Windows-initiated
round trip to the physical iPhone succeeded: the 13-byte `Connect hello` reply
matched, elapsed time was 373 ms, and Iroh reported `direct (selected)` with
public relays disabled. The user also reported a successful phone-initiated
probe, and the Windows incoming counter increased to one. Endpoint restart
and lock/reopen checks remain pending. Protected file-read acceptance is
separate.
Public relay mode also connected from the Windows app (13 bytes in 47 ms),
but Iroh selected a direct path. A fresh client supplied only the relay URL
also upgraded to direct. On 2026-10-26 the operator reported public relay success
in both directions; per-direction path/latency evidence was not supplied. The
separate forced-relay diagnostic remains unexecuted.

## Prepare the Mac

1. Install and open full Xcode; finish its first-run setup and select the correct developer directory with `xcode-select` if needed.
2. Sign into your Apple Account in Xcode. A free Personal Team is sufficient for basic testing, with seven-day provisioning; paid membership can be used instead.
3. Install Rust 1.98 or newer, Node.js 24 and the prerequisites in the official Tauri guide, including CocoaPods. Add `aarch64-apple-ios`; add simulator targets only if needed.
4. Connect and trust the iPhone, enable Developer Mode on the device if required, and confirm that Xcode lists it as a usable run destination.
5. Copy this source repository to the Mac, excluding `target`, `node_modules`, `dist`, `.git` and `local`. Preserve both lockfiles. No remote Git repository is required. The ignored `temp` notes are optional and contain no required implementation source.

Verify tool versions and build from the copied repository:

```sh
rustc --version
node --version
xcodebuild -version
rustup target add aarch64-apple-ios
cd apps/connect
npm ci
npm run ios:init
npm run tauri ios dev -- --open
```

In Xcode, choose the signing team and physical iPhone, then build/run using the generated project's Tauri workflow. If the CLI requests a team, use your actual team identifier or `APPLE_DEVELOPMENT_TEAM`; no account identifiers are committed. Record any signing or deployment failure instead of treating project generation as a completed device build.

The initialization helper explicitly enables Xcode build-script sandboxing and
declares the generated `.tauri/cli-options-server.json` and `project.pbxproj` as
Rust build-phase inputs. This avoids file-read denials without disabling the
sandbox. To apply these adjustments to an existing generated project, preserving
its selected team and merged Info.plist, run:

```sh
node scripts/ios-init.mjs --patch-existing
```

Run that from `apps/connect`. The helper also keeps static archives out of copied
resources when XcodeGen runs after a previous build. The Tauri CLI must remain
running while its Xcode build script runs; an Xcode-only build without the CLI
can still fail because the options file is absent.

For the first build of a new Swift plugin with Xcode 27, compile the Rust/mobile
library from the ordinary Mac shell **before** the Xcode archive phase. SwiftPM's
own manifest sandbox cannot start inside Xcode's script sandbox. Keep both
protections enabled; preparing the package outside that nested phase avoids it:

```sh
# From the repository root on the Mac:
export DEVELOPER_DIR="$(xcode-select -p)"
SDKROOT="$(xcrun --sdk iphoneos --show-sdk-path)" \
  IPHONEOS_DEPLOYMENT_TARGET=15.0 \
  cargo build -p genesismesh-connect --target aarch64-apple-ios \
  --lib --features tauri/custom-protocol --locked
cd apps/connect
npm run tauri -- ios build --debug --archive-only --ci
```

If that first pass regenerated watched permission metadata, repeat the same
Cargo build once before starting the archive. Generated metadata must be settled
outside the Xcode script sandbox. Keep `DEVELOPER_DIR` the same as Xcode so native
dependencies are not rebuilt solely because the environment changed.

The vendored view plugin also explicitly exports its C entry point for the
Swift 6/Xcode 27 static linker. See its
[patch notes](../vendor/tauri-plugin-view/CONNECT-PATCH.md). No signing key or
security setting is changed by these build steps.

If SSH code signing returns `errSecInternalComponent`, try the same Tauri build
from Terminal in the Mac's logged-in desktop session. Handle any keychain
unlock/private-key access prompt locally. Do not put a password in a command,
export the private key, or change its access rules merely to make remote builds
work. The script sandbox and keychain signing access are separate boundaries.

The source supplies `Info.ios.plist` with a local-network usage explanation. Check the generated app includes it and allow local-network access on the phone when prompted. No VPN extension or entitlement is part of this spike.

The pending iOS compatibility work pins the reviewed netdev PR 195 revision and
libc 0.2.189. The init helper retains the selected signing team and merged
Info.plist while adding the SDK resolver library. A separate local path patch
for n0-dns-resolver 0.1.0 avoids selecting macOS-only DynamicStore APIs on iOS:
it reads the primary system resolver configuration using public SDK libresolv
calls. See [patch provenance and limits](../vendor/n0-dns-resolver/CONNECT-PATCH.md).
This resolves the previously observed linker failure and produces an unsigned
archive with the iOS platform load command. Device DNS/network-change behavior
remains a separate test; signed installation and launch have now passed. No
credentials are generated or security settings changed by this workaround.

Development can need the Mac's frontend server reachable from the phone. Keep `tauri ios dev` running for its development workflow, use the actual Mac network interface if prompted and follow Tauri's device guidance. No router forwarding is needed for a same-LAN test. A later installed build must also be tested without that development server.

## Test Windows and iPhone

1. Open Connect on Windows and iPhone, both on the home LAN. Select **Transport test** and start local mode on each.
2. Copy the current endpoint tickets between them. On Windows, use Select ticket, then copy. Tickets include network coordinates; use a deliberate local transfer method.
3. Send `Connect hello` from the phone to Windows, then Windows to phone. Record peer IDs, byte count, elapsed time and observed path. Check the receiving counter increases.
4. Stop/restart the phone endpoint and repeat with its new ticket. Confirm old tickets no longer succeed.
5. Lock/reopen the phone and observe whether the endpoint survives. If suspended/terminated, restart and exchange fresh tickets; do not claim background persistence.
6. Optionally use public relay mode on both, then test the phone on cellular. Record the actual topology/path and failures separately from LAN results.

For a LAN failure, first verify phone local-network permission, network isolation and the actual Windows firewall prompt/rule. Do not disable the firewall globally. Record any needed inbound UDP rule for the specific executable as deployment configuration.

To verify the relay itself, the headless diagnostic below disables direct IP
transports on its client and refuses success unless all observed paths are
relays with a selected path present. Merely choosing public relay mode or
removing IP candidates from a ticket still permits Iroh to discover a direct
path. Run from the repository root with a current foreground phone endpoint:

```sh
cargo run --locked -p connect-core --example relay_probe -- '<current public relay ticket JSON>'
```

This tests the echo protocol from a separate client; it does not establish
Genesis Mesh authentication, protected reads, cellular behavior, or that the
native Windows UI selected a relay. The example compiles and passes Clippy;
independently observed relay-only execution is pending after Windows Application Control
blocked that new diagnostic executable and the Mac SSH connection timed out.

Exit: an actual Windows/physical-iPhone round trip and reproducible build/install steps. Neither Windows-only tests nor simulator success closes this spike. All exchanges remain transport diagnostics until Spike B certificate authentication passes.

## References

- [Tauri platform prerequisites](https://v2.tauri.app/start/prerequisites/)
- [Tauri iOS signing](https://v2.tauri.app/distribute/sign/ios/)
- [Apple Personal Team limits](https://developer.apple.com/help/account/basics/about-your-developer-account)
