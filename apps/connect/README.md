# Genesis Mesh Connect app

Thin TypeScript/Tauri diagnostic shell over the portable connect-core Rust library.

See the [repository README](../../README.md) for Windows commands and [iPhone spike guide](../../docs/iphone-spike.md) for Mac build/install steps.

This is a transport experiment. Genesis Mesh certificate authentication and protected services are not implemented yet.

## Brand assets

`public/brand/logo.svg` is an unchanged copy of the official Genesis Mesh logo from `genesismesh-content/shared/images/brand/logo.svg`. Use this artwork for Connect; do not substitute starter or AI-created logos.

Run `npm run icons` after updating that SVG. The script preserves the complete artwork, centers it on a white square with padding, and uses the pinned Tauri CLI to export the Windows, macOS, iOS and Android icon sizes plus the favicon. Temporary conversion input stays under the repository's ignored `temp/branding` directory.
