# Vendored source

`vendor/n0-dns-resolver` contains n0-dns-resolver 0.1.0 from the n0 team,
licensed under MIT OR Apache-2.0. Both license files are retained in that folder.
The upstream project is https://github.com/n0-computer/n0-dns-resolver.

Local iOS changes and source revision are documented in
`vendor/n0-dns-resolver/CONNECT-PATCH.md`. Other dependencies and licenses remain
identified by the Cargo/npm manifests and lockfiles.

The native desktop authority sidecars package Genesis Mesh 1.8.1 and a CPython runtime
with its installed dependencies. Its PyInstaller build retains dependency
license files under the packaged `licenses` data directory. PyInstaller is
GPL-2.0-or-later with its bootloader exception; that exception permits bundling
applications under their own licenses. Build input versions are in
`apps/connect/authority/build-requirements.txt`; the complete resolved environment
is recorded locally in `temp/authority-build/<native-target>/package.json`.

The QR encoder `qrcode` 1.5.4 is MIT licensed. The pinned Tauri deep-link/single
instance plugins, native folder picker and iOS Keychain wrapper retain their
upstream licenses through Cargo/npm metadata. Explicit keyring-core,
zbus-secret-service-keyring-store and android-native-keyring-store adapters
provide the Linux and Android identity stores; Apple uses security-framework.
Their versions and upstream licenses are recorded in Cargo metadata/lockfiles.
None of these supply the Genesis
Mesh brand artwork.

The mobile document viewer uses `tauri-plugin-view` 0.0.5 (MIT,
https://github.com/ecmel/tauri-plugin-view). Desktop file opening uses the official
Tauri opener plugin. Native commands expose only completed, verified downloads;
the web UI has no general path-opening permission. Android FileProvider is
restricted to Connect's private download-cache subdirectory.
