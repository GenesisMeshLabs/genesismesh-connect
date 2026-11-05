fn main() {
    // NDK r27 defaults to 4 KiB. Android 15+ devices may use 16 KiB pages;
    // apply both ELF/RELRO alignment flags to the final shared library only.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        println!("cargo:rustc-link-arg-cdylib=-Wl,-z,max-page-size=16384");
        println!("cargo:rustc-link-arg-cdylib=-Wl,-z,common-page-size=16384");
    }
    // Recompile the Windows executable resource when the app icon changes.
    println!("cargo:rerun-if-changed=icons/icon.ico");
    tauri_build::build()
}
