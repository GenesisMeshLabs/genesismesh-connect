# Embedded Android engine check

An isolated developer APK packages the unchanged pinned Python core and its
verified Android dependency closure. It tests imports, core signatures and
refusals, native FFI, authenticated encryption, model validation, SQLite and
temporary loopback HTTP. It creates no network or owner identity.

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
A passing report qualifies these runtime operations only. Authority
creation, protected owner custody, persisted identity, enrollment, revocation,
transport integration and foreground/background lifecycle are separate gates.
