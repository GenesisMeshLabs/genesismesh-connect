"""Build target libsodium and libffi for Android authority dependency wheels.

Runs only inside cibuildwheel's Android cross environment. No host libraries,
reduced primitives, source substitutions or native execution tests are used.
"""
import json
import argparse
import hashlib
import os
from pathlib import Path
import struct
import subprocess


def sdk_prefix():
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
    return prefix


def prepare_sodium(project, runner=subprocess.run):
    prefix = sdk_prefix()
    library = prefix / "lib"
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


def prepare_ffi(project, runner=subprocess.run):
    prefix = sdk_prefix()
    from android_authority_sources import fetch, unpack
    lock = json.loads(Path(__file__).with_name("android-authority-native.lock.json").read_text())
    if lock["schema"] != 1:
        raise ValueError("Unsupported native source lock")
    source = lock["libffi"]
    data = fetch(source["url"], 100_000_000, ("github.com", "release-assets.githubusercontent.com"))
    if hashlib.sha256(data).hexdigest() != source["sha256"]:
        raise ValueError("libffi source hash mismatch")
    work = project.resolve() / ".connect-native-ffi"
    work.mkdir(exist_ok=False)
    archive = work / "upstream.tar.gz"
    archive.write_bytes(data)
    root = unpack(archive, work / "source")
    build = work / "build"
    build.mkdir()
    runner(["/bin/sh", str(root / "configure"), "--host=aarch64-linux-android", "--disable-shared",
            "--enable-static", "--with-pic", "--disable-multi-os-directory", f"--prefix={prefix}", f"--libdir={prefix / 'lib'}"],
           cwd=build, check=True, timeout=600)
    runner(["make", "-j2"], cwd=build, check=True, timeout=600)
    runner(["make", "install"], cwd=build, check=True, timeout=120)
    if not (prefix / "lib/libffi.a").is_file():
        raise ValueError("Target libffi installation is incomplete")
    (project / "connect-native-report.json").write_text(json.dumps({
        "library": "libffi", **source, "target": "Android arm64 API24", "linkage": "static", "native_execution": "unverified",
    }, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", type=Path)
    parser.add_argument("--kind", choices=("sodium", "ffi"), default="sodium")
    args = parser.parse_args()
    (prepare_sodium if args.kind == "sodium" else prepare_ffi)(args.project)
