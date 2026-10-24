# Genesis Mesh Connect

A separate device application built around Genesis Mesh trust, Iroh connectivity and a Tauri shell.

Current state: **Spike A, transport diagnostics**. The application sends bounded echo messages between explicit endpoint tickets. Genesis Mesh certificate authentication, enrollment, authority forwarding and file access are not implemented. A successful probe proves Iroh connectivity only.

## Structure

- `crates/connect-core`: portable Rust library; transport module and headless diagnostic example.
- `apps/connect`: small TypeScript/Tauri application, calling the same Rust library.
- `docs/iphone-spike.md`: Mac build/install and physical-device test steps.
- `temp/`: ignored planning and local verification results.

## Windows development

Requirements: Rust 1.98 or newer, Visual C++ build tools, WebView2 and Node.js 24. Tested tool versions are recorded in the local spike results. Dependencies resolve through the repository's Cargo/npm lockfiles.

From the repository root:

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

The Windows executable is `target/debug/genesismesh-connect.exe` at the repository root. For frontend hot reload, use `npm run tauri dev` instead. Opening Vite in an ordinary browser does not provide the native Rust commands.

Start an endpoint in the app, copy its ticket to a second device and paste that device's ticket into the first. Send a diagnostic message. Start both in local mode for a home-LAN test. Public relay mode explicitly uses Iroh's public relay servers; this spike does not publish endpoint addresses through a public address directory.

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

Endpoint keys exist only in Rust memory and change after restart. Tickets contain public keys and network addresses, never private keys. Exchange them deliberately; they are reachability information, not Genesis Mesh permission.

Each connection accepts a single diagnostic stream of at most 1,024 bytes, with timeouts and bounded concurrency. The service exposes no files, shell or authority APIs. The desktop host currently follows app lifetime; a persistent service comes later. Phone suspension can interrupt it; reconnect using the current ticket after reopening.

The SDK is intentionally absent from this transport-only spike. Spike B targets the released `v1.8.1` SDK tag once available and adds certified, mutually authenticated session proofs. No changes to the core or SDK repositories are needed for Spike A.
