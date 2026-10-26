# Working on Genesis Mesh Connect

## Genesis Mesh versions

Connect is not part of the coordinated release train: it consumes Genesis Mesh
releases. A new release arrives as one Renovate pull request, "Update Genesis
Mesh" (`renovate.json`, the shared preset in
`GenesisMeshLabs/devtools/renovate/genesis-mesh.json`). Keep every pin in a form
that pull request can move, so nobody edits versions by hand:

- **One source per pin.** Name each Genesis Mesh release once, in a file
  Renovate reads, and have code and scripts read it from there:
  - the Rust SDK: `genesis-mesh-sdk = { git = "https://github.com/GenesisMeshLabs/sdk-rust", tag = "vX.Y.Z", ... }`
    in `crates/connect-core/Cargo.toml` (cargo refreshes `Cargo.lock` on the
    next build);
  - the core for the owner runtime: `genesis-mesh==X.Y.Z` in a requirements
    file (for example `apps/connect/authority/core-requirements.txt`). The
    build and packaging scripts read the version from it instead of comparing
    with a literal such as `"1.8.1"`;
  - a pinned commit, where code needs one, written with its release so the tag
    and the commit move together: `"<40-hex sha>"  # GenesisMeshLabs/<repo> vX.Y.Z`,
    or `RELEASE = "vX.Y.Z"  # GenesisMeshLabs/<repo>` with the commit on the
    next line.
- **Documentation does not repeat the current version.** Write "the pinned
  Genesis Mesh release (`crates/connect-core/Cargo.toml`)" rather than "SDK
  1.8.1". A statement of what a test or a build was verified with ("validated
  with 1.8.1 on ...") is a record and keeps its version.
- **On the Renovate pull request**, run `scripts/verify.ps1` (and the platform
  builds it lists), then fix what the new release needs on that branch before
  merging.
