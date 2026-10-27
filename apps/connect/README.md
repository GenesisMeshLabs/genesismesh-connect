# Genesis Mesh Connect app

Genesis Mesh device workspace over the portable connect-core Rust library.

See the [repository README](../../README.md) for Windows commands and [iPhone spike guide](../../docs/iphone-spike.md) for Mac build/install steps.

Normal navigation is Files, Devices and Settings. The desktop owner flow creates
or attaches a real local authority, approves an expiring device invitation and
shares a folder through a native picker. The companion browses authorized file
pages and opens a version-checked file. Keys, routes and permission IDs stay in
native code. See [everyday workflow](../../docs/everyday-workflow.md).

The iPhone private record uses device-only, non-syncing Keychain storage. That
implementation compiles for iOS. Build 4 pairing and small-file browsing were
reported working by the user. Latest code supports up to 32 saved devices, one
shared folder tree (up to 16 levels) and disk-backed downloads up to 1 GiB; mobile installation and
physical viewing/export acceptance are tracked separately. Keep both apps open.
Existing size permissions stay unchanged until you explicitly re-share the folder.

Settings → Advanced tools retains technical enrollment, trust checkpoints,
activity and the separate unauthenticated connection check. Existing advanced
profiles are preserved. Those screens use the older [technical workflows](../../docs/app-workflows.md).

## Brand assets

`public/brand/logo.svg` is an unchanged copy of the official Genesis Mesh logo from `genesismesh-content/shared/images/brand/logo.svg`. Use this artwork for Connect; do not substitute starter or AI-created logos.

Run `npm run icons` after updating that SVG. The script preserves the complete artwork, centers it on a white square with padding, and uses the pinned Tauri CLI to export the Windows, macOS, iOS and Android icon sizes plus the favicon. Temporary conversion input stays under the repository's ignored `temp/branding` directory.

`npm run build` regenerates icons first. `npm run ios:init` also regenerates
icons after Xcode project generation, so the separate generated AppIcon catalog
receives the official logo. Use `npm run ios:init -- --patch-existing` for a
generated project that still has starter artwork, then rebuild and reinstall on
the iPhone. Changing Windows source assets cannot update an already installed
iPhone binary.

Run `npm test` for onboarding states, file filtering and saved-reference scope,
validation and persistence checks. Native desktop builds package a standalone authority
helper; mobile builds skip that step. End users do not
need the build Python environment or source checkout.

See [cross-platform status](../../docs/cross-platform.md) for Linux/macOS ownership,
native credential stores, Android initialization, validation limits, and the
remaining work before every device can send, receive and share through the same UI.
