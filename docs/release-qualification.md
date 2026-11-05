# Dependency qualification

Connect consumes released Genesis Mesh components independently of the core
release train. The SDK pin is in `crates/connect-core/Cargo.toml`; the authority
pin is in `apps/connect/authority/core-requirements.txt`. Packaging reads that
file and refuses a different source/installed core version. Renovate can update
both exact pins. The sibling core's Python environment is never upgraded as a
side effect of qualification.

## Qualification record: 5 November 2026

Candidate: released core and Rust SDK **1.9.1**, SDK commit
`b67c248717d5d99aca6f4dad320692f3f6c07c69`. Core was installed from its published
wheel in isolated Windows and Linux environments owned by this checkout.

| Gate | Result |
| --- | --- |
| Windows owner adapter against real released core, including protected-key, recovery, policy and revocation cases | 13 tests passed, including 2 release-pin tests |
| Frontend state tests | 22 passed |
| TypeScript and Vite production build | Passed |
| Workspace formatting | Passed |
| Fresh Linux core library/integration tests | 78 passed; credential-store and packaged-owner cases remain separately gated |
| Linux real-authority integration with private disposable Secret Service | All 14 passed, including enrollment, pairing/restart, transfers, services, denial and revocation |
| Full Windows verification script | Blocked at Rust dependency build script by Windows Application Control, error 4551; later gates not run |
| macOS/iOS/Android packaging, signing and physical-device acceptance | Not run in this qualification |

The first Linux live run lacked a credential service: 11 passed and 3 pairing
cases failed before saving their identities. Repeating through
`scripts/verify-linux-store.sh` provided a private disposable D-Bus/keyring and
passed all 14. No existing keyring was unlocked or replaced. Linux used Rust
1.99; it reports a pre-existing `fetch_update` deprecation, so this is not a
claim that the workspace Clippy gate passed with warnings denied.

The existing Windows target cache first produced inconsistent dependency
metadata. A fresh qualification target exposed the Application Control block.
No blocked executable was run through another path and no security setting was
changed. These Linux results do not substitute for the blocked Windows gate.

This is source/compatibility evidence, **not** an installed-app release or a
complete cross-platform qualification. The running desktop and user network
were not replaced. Logs and the full Windows gate report are ignored under
`temp/qualification/` and `temp/verification/`.

For a dependency update, rerun `scripts/verify.ps1` with an isolated matching
authority Python environment, plus native platform and device gates described
in `cross-platform.md`. Do not promote an unsupported platform based only on
unit tests or successful compilation elsewhere.
