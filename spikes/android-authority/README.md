# Embedded Android engine check

An isolated developer APK packages the unchanged pinned Python core and its
verified Android dependency closure. It tests imports, core signatures and
refusals, native FFI, authenticated encryption, model validation, SQLite and
temporary loopback HTTP. On a custody-ready phone, its separate owner check also
creates a private qualification network through the real core and checks owner
close/reopen, signed member liveness and purpose-separated Android Keystore
custody. Later runs reopen that same qualification profile. No production
Create Network action is exposed.

The Android source-wheel workflow builds it only after the full artifact-bound
closure passes. Gradle receives an offline wheel directory and generated full
hash requirements. The normal Connect app and qualification client keep their
separate package identifiers and data.

Install a downloaded CI artifact using `scripts/install-android-test.ps1` with
`-AppKind EngineCheck` and its existing APK/device/Python parameters. The installer
checks package identity, signature and native alignment before updating in place.
Open **GM Engine Check** on the phone. Its private diagnostic report is available
to the development host with:

```powershell
adb -s <serial> exec-out run-as org.genesismesh.connect.authoritycheck cat files/authority-runtime-report.json
```

Confirm the report's source commit, unique run ID, core version, actual device
API and all checks. Activity restarts use serialized process-wide execution;
stale completions cannot publish reports or update a newer screen. Python's
build-time API marker is recorded separately from the actual device API.
A passing runtime report qualifies those runtime operations only. The owner
check has its own results. Physical owner creation/persistence, device restart,
recovery, second-device enrollment/revocation, transport integration and
foreground/background lifecycle remain separate acceptance gates. This owner
profile requires an unlocked phone with a secure screen lock configured; configure
credentials only locally, never in a chat or developer command.

The owner profile requires API35+, with atomic no-replace publication. It first
tests this in a fresh temporary directory using public bytes, without hard links
or OS permission changes. A lock-only pre-initialization directory is reused only
when both fixed custody aliases are absent; initialized/unknown state is preserved.
