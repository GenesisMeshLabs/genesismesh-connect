"""Require the shared Python dependency needed by Android's embedded loader.

Run after the wheel ABI/ELF checks. Uses readelf; never executes the extension.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile


def verify(wheel):
    with zipfile.ZipFile(wheel) as archive:
        modules = [e for e in archive.infolist()
                   if e.filename == "cryptography/hazmat/bindings/_rust.abi3.so"]
        if len(modules) != 1 or not 0 < modules[0].file_size <= 64_000_000:
            raise ValueError("Expected one bounded cryptography Rust extension")
        with tempfile.TemporaryDirectory(prefix="gm-android-link-") as folder:
            module = Path(folder) / "module.so"
            module.write_bytes(archive.read(modules[0]))
            result = subprocess.run(["readelf", "-d", str(module)], check=True,
                                    capture_output=True, timeout=20,
                                    env={**os.environ, "LC_ALL": "C"})
    if not re.search(rb"\(NEEDED\)[^\n]*Shared library: \[libpython3\.13\.so\]", result.stdout):
        raise ValueError("Android cryptography lacks its explicit shared Python dependency")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    verify(parser.parse_args().wheel)
    print("Embedded Android shared Python linkage passed")
