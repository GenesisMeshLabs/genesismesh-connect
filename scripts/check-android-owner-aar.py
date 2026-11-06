"""Inspect the build-only owner library. This never installs or runs its code."""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import struct
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MODULES = {"android_connect_owner.pyc", "android_storage.pyc", "connect_owner.pyc", "core-requirements.txt",
           "core_release.pyc", "local_server.pyc", "member_renewal.pyc", "owner.pyc", "owner_adapter.pyc",
           "protection.pyc", "state_storage.pyc"}


def check(path):
    spec = importlib.util.spec_from_file_location("elf_check", Path(__file__).with_name("check-android-apk.py"))
    elf = importlib.util.module_from_spec(spec); spec.loader.exec_module(elf)
    pin = (ROOT / "apps/connect/authority/core-requirements.txt").read_bytes()
    version = re.search(rb"(?m)^genesis-mesh==([0-9.]+)\s*$", pin).group(1).decode()
    libraries = []
    def native(archive, prefix=""):
        for entry in archive.infolist():
            if not entry.filename.endswith(".so"): continue
            if not 0 < entry.file_size <= 64 * 1024 * 1024: raise ValueError("Invalid native library size")
            with archive.open(entry) as stream:
                header = stream.read(64); stream.seek(0)
                if len(header) < 64 or struct.unpack_from("<H", header, 18)[0] != 183:
                    raise ValueError("Owner library requires Android arm64 native objects")
                elf.check_elf(stream, entry.file_size)
            libraries.append(prefix + entry.filename)
    with zipfile.ZipFile(path) as aar:
        manifest = ET.fromstring(aar.read("AndroidManifest.xml"))
        if (manifest.attrib.get("package") != "org.genesismesh.connect.ownerqualification"
                or manifest.find("application") is not None
                or manifest.find("uses-sdk").attrib.get("{http://schemas.android.com/apk/res/android}minSdkVersion") != "35"):
            raise ValueError("Expected the isolated build-only library manifest")
        with zipfile.ZipFile(io.BytesIO(aar.read("classes.jar"))) as classes:
            for name in ("OwnerQualificationPlugin", "OwnerSessionGuard", "OwnerKeyVault", "RootKeyAuthorization", "RootKeyPolicy"):
                if f"org/genesismesh/connect/authority/{name}.class" not in classes.namelist():
                    raise ValueError("A required native bridge class was not compiled")
        with zipfile.ZipFile(io.BytesIO(aar.read("assets/chaquopy/app.imy"))) as app:
            if set(app.namelist()) != MODULES: raise ValueError("Unexpected or missing application Python sources")
            if app.read("core-requirements.txt") != pin: raise ValueError("Packaged core pin differs from the checkout")
        metadata = False
        native(aar)
        for entry in aar.infolist():
            if not entry.filename.endswith(".imy"): continue
            with zipfile.ZipFile(io.BytesIO(aar.read(entry))) as embedded:
                native(embedded, entry.filename + ":")
                wanted = f"genesis_mesh-{version}.dist-info/METADATA"
                if wanted in embedded.namelist(): metadata = True
        if not metadata or not libraries: raise ValueError("Missing pinned core metadata or native runtime")
    return {"artifact_kind": "build_only_android_library", "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "python_modules": sorted(MODULES), "native_16k_libraries": len(libraries),
            "core_version": version, "full_app_qualified": False, "physical_root_auth_accepted": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("aar", type=Path)
    print(json.dumps(check(parser.parse_args().aar), indent=2))
