"""Native sidecar target selection. Never package a host binary as another OS."""
import os
import platform
import sys


def target():
    arch = {"AMD64": "x86_64", "x86_64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}.get(platform.machine())
    suffix = {"win32": "pc-windows-msvc", "darwin": "apple-darwin", "linux": "unknown-linux-gnu"}.get(sys.platform)
    if not arch or not suffix:
        raise RuntimeError("Package the authority on a supported native desktop build host")
    native = f"{arch}-{suffix}"
    configured = os.environ.get("TAURI_ENV_TARGET_TRIPLE", native)
    if configured != native:
        raise RuntimeError("The authority must be packaged on the target OS and architecture")
    return native


def extension():
    return ".exe" if sys.platform == "win32" else ""
