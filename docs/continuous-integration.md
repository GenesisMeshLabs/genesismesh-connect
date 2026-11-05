# Continuous qualification

Every main push and pull request runs the existing contract/provenance workflow
and `Connect qualification`. The latter can also be started manually. It checks:

- Frontend state tests, TypeScript and Vite.
- Core and generated-schema tests on Linux and Windows at the declared minimum Rust.
- Released pinned Python authority tests; disposable Linux native-key lifecycle;
  real core/QUIC, access and owner-control checks; standalone authority/recovery;
  Linux desktop and headless-host compilation.
- An arm64 Android debug APK built with the existing initialization/branding/
  permission patches, followed by signature verification, 16 KiB ELF/RELRO/ZIP
  alignment refusal checks and SHA-256 inventory.

Download the Android APK from the run's **Artifacts** section. It is a development
build with a development signing identity, not a store release. Updating a device
requires compatible package/signing identity; do not automatically uninstall a
user's app or erase its data after a signature mismatch.

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
