# Physical iPhone transport spike

Status: Mac availability confirmed by the operator; Mac access, build, signing and device installation have not yet been verified. Run these steps on the Mac when it is available. Windows cannot perform the iOS build.

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
npm run tauri ios init
npm run tauri ios dev -- --open
```

In Xcode, choose the signing team and physical iPhone, then build/run using the generated project's Tauri workflow. If the CLI requests a team, use your actual team identifier or `APPLE_DEVELOPMENT_TEAM`; no account identifiers are committed. Record any signing or deployment failure instead of treating project generation as a completed device build.

The source supplies `Info.ios.plist` with a local-network usage explanation. Check the generated app includes it and allow local-network access on the phone when prompted. No VPN extension or entitlement is part of this spike.

Development can need the Mac's frontend server reachable from the phone. Keep `tauri ios dev` running for its development workflow, use the actual Mac network interface if prompted and follow Tauri's device guidance. No router forwarding is needed for a same-LAN test. A later installed build must also be tested without that development server.

## Test Windows and iPhone

1. Open Connect on Windows and iPhone, both on the home LAN. Start local mode on each.
2. Copy the current endpoint tickets between them. On Windows, use Select ticket, then copy. Tickets include network coordinates; use a deliberate local transfer method.
3. Send `Connect hello` from the phone to Windows, then Windows to phone. Record peer IDs, byte count, elapsed time and observed path. Check the receiving counter increases.
4. Stop/restart the phone endpoint and repeat with its new ticket. Confirm old tickets no longer succeed.
5. Lock/reopen the phone and observe whether the endpoint survives. If suspended/terminated, restart and exchange fresh tickets; do not claim background persistence.
6. Optionally use public relay mode on both, then test the phone on cellular. Record the actual topology/path and failures separately from LAN results.

For a LAN failure, first verify phone local-network permission, network isolation and the actual Windows firewall prompt/rule. Do not disable the firewall globally. Record any needed inbound UDP rule for the specific executable as deployment configuration.

Exit: an actual Windows/physical-iPhone round trip and reproducible build/install steps. Neither Windows-only tests nor simulator success closes this spike. All exchanges remain transport diagnostics until Spike B certificate authentication passes.

## References

- [Tauri platform prerequisites](https://v2.tauri.app/start/prerequisites/)
- [Tauri iOS signing](https://v2.tauri.app/distribute/sign/ios/)
- [Apple Personal Team limits](https://developer.apple.com/help/account/basics/about-your-developer-account)
