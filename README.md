# Genesis Mesh Connect

A separate device application built around Genesis Mesh trust, Iroh connectivity and a Tauri shell.

Current implementation: **guided network setup, multiple approved devices and authorized file browsing**. The shared core now has native identity stores for Windows, macOS, Linux, Android and iOS, desktop authority packaging, and remote collection governance. Windows and Linux native builds are checked; Mac/iOS device acceptance and Android runtime validation remain pending. Full send/receive and mobile document workflows are still in progress. See the [platform status and remaining work](docs/cross-platform.md) and [everyday workflow](docs/everyday-workflow.md).

## Structure

The normal navigation is **Files**, **Devices** and **Settings**. Technical
enrollment, trust details, activity and connection diagnostics remain under
Settings → Advanced tools. Existing technical profiles are preserved.

- `crates/connect-core`: portable Rust library; transport module and headless diagnostic example.
- `apps/connect`: small TypeScript/Tauri application, calling the same Rust library.
- `apps/connect/authority`: native desktop owner adapter and standalone runtime build.
- `docs/everyday-workflow.md`: ordinary setup, pairing, file browsing and bounds.
- `docs/cross-platform.md`: platform adapters, native build steps, evidence and remaining parity work.
- `docs/iphone-spike.md`: Mac build/install and physical-device test steps.
- `docs/session-spike.md`: session trust, refusal cases and the independent local test.
- `docs/authority-spike.md`: real native-authority enrollment/renewal, persisted trust and integration test.
- `docs/windows-device.md`: Windows enrollment, protected storage and session controls.
- `docs/authority-bridge.md`: fixed-operation Iroh control channel, renewal after suspension and limits.
- `docs/remote-enrollment.md`: joining through another desktop, host proof and invite checks.
- `docs/protected-read.md`: edge host enrollment, live read policy, confined storage and receipts.
- `docs/trust-contract-proposal.md`: proposed Connect/radio ownership and semantic contract; not an agreed shared implementation.
- `docs/two-device-acceptance.md`: software evidence, physical-device matrix and current Mac/iPhone blockers.
- `scripts/verify.ps1`: required Windows checks, including real authority tests and a native build.
- `vendor/n0-dns-resolver`: temporary, licensed iOS resolver patch; see its CONNECT-PATCH.md.
- `temp/`: ignored planning and local verification results.

## Windows development

Requirements: Rust 1.98 or newer, Visual C++ build tools, WebView2 and Node.js 24. Tested tool versions are recorded in the local spike results. Dependencies resolve through the repository's Cargo/npm lockfiles.

From the repository root:

Run the complete Windows gate with the native core Python environment available:

```powershell
.\scripts\verify.ps1
# Or provide a different environment containing Genesis Mesh:
.\scripts\verify.ps1 -AuthorityPython 'C:\path\to\python.exe'
```

The gate requires real-authority tests and stops on the first failure. It writes
`temp/verification/latest.json`. Mac archive/signing and physical-device tests
remain separate. It checks the core library independently to catch dependency
features supplied indirectly by the shell, and runs the two iOS DNS parser tests.
For individual Rust checks:

```powershell
cargo test -p connect-core --locked
cargo run -p connect-core --example probe --locked -- self-test
```

Build and run the native app using its bundled frontend:

```powershell
cd apps/connect
npm ci
npm run tauri build -- --debug --no-bundle
```

The Windows executable is `target/debug/genesismesh-connect.exe` at the repository root. Keep its bundled `genesismesh-authority.exe` alongside it. Building the owner runtime needs the sibling Genesis Mesh 1.8.1 source and build Python (or explicit `CONNECT_CORE_SOURCE` and `CONNECT_NA_PYTHON`); installed end users need neither. Packaging uses an isolated build environment, with dependency reports under `temp/authority-build/<native-target>/`. For frontend hot reload, use `npm run tauri dev` instead; the explicit debug-only `CONNECT_NA_PYTHON` option can run the owner adapter from source. Opening Vite in an ordinary browser does not provide native Rust commands.

Use the [everyday workflow](docs/everyday-workflow.md) for normal setup, or the [Device guide](docs/windows-device.md) for technical controls. For the original connectivity spike, open **Settings → Advanced tools → Connection check**, start both endpoints in local mode and exchange tickets. That separate diagnostic does not publish endpoint addresses. Guided sessions follow the network computer's connection setting: public relays (n0 relays and address lookup, the default) or private, local network only (no relay or address publication); see [choose how devices connect](docs/everyday-workflow.md#choose-how-devices-connect). Either way Genesis Mesh authenticates the node and authorizes access.

For headless use:

```powershell
cargo run -p connect-core --example probe --locked -- listen
# In another terminal, use the ticket string from the listener's status:
cargo run -p connect-core --example probe --locked -- send '<ticket JSON>'
```

Optional public-relay bootstrap check:

```powershell
cargo run -p connect-core --example probe --locked -- self-test --public-relay
```

That check uses two endpoints on the same host and passes only the server's relay address to the client. The report shows the paths observed at reply time; it is not a physical-iPhone or cellular test and does not prove traffic remained relayed for an entire transfer.

## Spike limits

Original diagnostic/advanced transport keys remain ephemeral. Guided consumer transport keys persist separately from the node key in the platform vault, allowing saved connections to reopen. Tickets contain public endpoint keys and routing addresses, never private keys; they establish reachability, not Genesis Mesh permission.

The diagnostic protocols accept one message of at most 1,024 bytes per connection. Separate authenticated protocols handle pairing, fixed authority operations, directory pages and collection reads. The preview supports up to 32 saved devices, one selected folder tree (up to 16 levels) and disk-backed downloads up to 1 GiB. Folder navigation and breadcrumbs require the latest client and host; legacy flat protocols remain compatible. There is no shell or general-purpose HTTP proxy. The desktop host follows app lifetime; a persistent service comes later. Phone suspension can interrupt it; guided profiles reopen their saved connection and each operation refreshes trust. Downloads have progress/cancel and native view/save actions. Durable resume, mobile hosting, uploads and recovery remain pending; physical feature acceptance is recorded separately.

Spike B pins the released `v1.8.1` SDK and runs without Mac or iPhone setup:

```powershell
cargo run -p connect-core --example session --locked -- self-test
```

This uses an in-memory synthetic authority and real same-host QUIC connections.
It does not enroll your devices or change the transport UI's authentication status.
