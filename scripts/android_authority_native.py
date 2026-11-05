"""Build bundled libsodium for the verified PyNaCl Android source wheel.

Runs only inside cibuildwheel's Android cross environment. No host libraries,
reduced primitives, source substitutions or native execution tests are used.
"""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys


def prepare_sodium(project, runner=subprocess.run):
    if os.environ.get("CIBW_HOST_TRIPLET") != "aarch64-linux-android" or os.environ.get("ANDROID_API_LEVEL") != "24":
        raise ValueError("Bundled sodium must be built in the Android arm64/API24 cross environment")
    library = Path(os.environ["PYO3_CROSS_LIB_DIR"]).resolve()
    prefix = library.parent
    python = library / "libpython3.13.so"
    with python.open("rb") as stream:
        header = stream.read(20)
    if len(header) < 20 or header[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", header, 18)[0] != 183:
        raise ValueError("Refusing a host or incompatible Python SDK library")
    if not (prefix / "include/python3.13/Python.h").is_file():
        raise ValueError("Android SDK headers are unavailable")
    if not Path(os.environ.get("CC", "")).name.startswith("aarch64-linux-android24-clang"):
        raise ValueError("The compiler does not match Android arm64/API24")
    project = project.resolve()
    source = (project / "src/libsodium").resolve()
    if not source.is_relative_to(project) or not (source / "configure").is_file():
        raise ValueError("The verified package has no bundled sodium source")
    build = project / ".connect-native-sodium"
    build.mkdir(exist_ok=False)
    configure = ["/bin/sh", str(source / "configure"), "--host=aarch64-linux-android",
                 "--disable-shared", "--enable-static", "--disable-debug",
                 "--disable-dependency-tracking", "--with-pic", f"--prefix={prefix}"]
    runner(configure, cwd=build, check=True, timeout=600)
    runner(["make", "-j2"], cwd=build, check=True, timeout=600)
    runner(["make", "install"], cwd=build, check=True, timeout=120)
    if not (library / "libsodium.a").is_file() or not (prefix / "include/sodium.h").is_file():
        raise ValueError("Bundled sodium installation is incomplete")
    (project / "connect-native-report.json").write_text(json.dumps({
        "library": "libsodium from the hash-verified PyNaCl sdist", "target": "Android arm64 API24",
        "linkage": "static", "minimal_build": False, "native_execution": "unverified",
    }, indent=2) + "\n")


if __name__ == "__main__":
    prepare_sodium(Path(sys.argv[1]))
