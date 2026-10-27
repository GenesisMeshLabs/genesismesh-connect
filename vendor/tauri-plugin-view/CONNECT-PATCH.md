# Connect mobile document actions

Based on crates.io tauri-plugin-view 0.0.5, MIT licensed (LICENSE retained).
The Rust, Android and Swift sources are otherwise upstream code.

Connect adds an optional `share` request field. On iOS this presents the native
activity sheet, including Save to Files. On Android it presents a chooser with
ACTION_SEND and EXTRA_STREAM, including a read-only URI grant. The upstream
preview fallback also now attaches EXTRA_STREAM. This fixes the distinction
between opening a document and saving/sharing a completed download.
The Swift C entry point is explicitly public so Swift 6/Xcode 27 retains it in
the static library for the Rust plugin binding.

Connect calls this from native commands using an opaque verified-download ID.
There is no frontend view permission or arbitrary path argument. Android's
FileProvider scope is configured separately in android-init.mjs, restricted to
the private connect-downloads cache. Upstream's broad README path example is
not used. Native build/device verification is recorded separately in temp/.

Upstream local.properties, wrapper binaries, JS tooling and tests were omitted
from this Rust/mobile dependency snapshot. Tauri uses the app's Gradle wrapper.
