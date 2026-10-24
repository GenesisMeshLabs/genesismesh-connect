fn main() {
    // Recompile the Windows executable resource when the app icon changes.
    println!("cargo:rerun-if-changed=icons/icon.ico");
    tauri_build::build()
}
