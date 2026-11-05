"""Prepare hash-locked upstream authority dependencies and check Android wheels.

Build products remain unaccepted for device use until real runtime tests pass.
"""
import argparse
from email.parser import BytesParser
import hashlib
import importlib.metadata as metadata
import importlib.util
import json
from pathlib import Path
import struct
import tarfile
import tomllib
import urllib.parse
import urllib.request
import zipfile

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name, parse_wheel_filename

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "scripts/android-authority-sources.lock.json"
PACKAGES = ("pydantic-core", "cryptography", "PyNaCl")


def pin():
    lines = [s.split("#", 1)[0].strip() for s in (ROOT / "apps/connect/authority/core-requirements.txt").read_text().splitlines()]
    entries = [s for s in lines if s]
    if len(entries) != 1:
        raise ValueError("Expected one authority release pin")
    requirement = Requirement(entries[0])
    exact(requirement)
    if requirement.name != "genesis-mesh":
        raise ValueError("Unexpected authority package")
    return requirement


def exact(requirement):
    specs = list(requirement.specifier)
    if len(specs) != 1 or specs[0].operator != "==" or "*" in specs[0].version or requirement.url or requirement.marker:
        raise ValueError("An exact, unconditional dependency is required")
    return specs[0].version


def dependency(parent, name):
    matches = [Requirement(r) for r in metadata.requires(parent) or [] if canonicalize_name(Requirement(r).name) == canonicalize_name(name)]
    if len(matches) != 1:
        raise ValueError("Dependency is missing or ambiguous")
    version = exact(matches[0])
    if metadata.version(name) != version:
        raise ValueError("Installed dependency differs from the authority requirement")
    return version


def versions():
    requirement = pin()
    if metadata.version(requirement.name) != exact(requirement):
        raise ValueError("Install the pinned authority before preparing its dependencies")
    dependency("genesis-mesh", "pydantic")
    return {"pydantic-core": dependency("pydantic", "pydantic-core"),
            "cryptography": dependency("genesis-mesh", "cryptography"),
            "PyNaCl": dependency("genesis-mesh", "PyNaCl")}


def fetch(url, limit):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in {"pypi.org", "files.pythonhosted.org"} or parsed.username or parsed.password:
        raise ValueError("Only official HTTPS Python package sources are permitted")
    with urllib.request.urlopen(url, timeout=60) as response:
        if urllib.parse.urlsplit(response.url).hostname != parsed.hostname:
            raise ValueError("Unexpected source redirect")
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Package source exceeds the bounded download size")
    return data


def refresh_lock():
    sources = {}
    for name, version in versions().items():
        info = json.loads(fetch(f"https://pypi.org/pypi/{name}/{version}/json", 2_000_000))
        files = [f for f in info["urls"] if f["packagetype"] == "sdist"]
        if len(files) != 1:
            raise ValueError("Expected a single upstream source archive")
        sources[name] = {"version": version, "url": files[0]["url"], "sha256": files[0]["digests"]["sha256"]}
    LOCK.write_text(json.dumps({"schema": 1, "authority_pin_sha256": hashlib.sha256(str(pin()).encode()).hexdigest(),
                                "packages": sources}, indent=2) + "\n", encoding="utf-8")


def verified_source(name):
    lock = json.loads(LOCK.read_text())
    expected = versions()
    if lock["schema"] != 1 or lock["authority_pin_sha256"] != hashlib.sha256(str(pin()).encode()).hexdigest():
        raise ValueError("Authority release changed; refresh and review source qualification")
    source = lock["packages"][name]
    if source["version"] != expected[name]:
        raise ValueError("Source lock differs from the pinned authority dependency")
    data = fetch(source["url"], 100_000_000)
    if hashlib.sha256(data).hexdigest() != source["sha256"]:
        raise ValueError("Source archive hash mismatch; nothing may be built")
    return source, data


def unpack(archive, output):
    output.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive) as source:
        members = source.getmembers()
        if len(members) > 50_000 or sum(m.size for m in members) > 500_000_000:
            raise ValueError("Source archive exceeds extraction limits")
        source.extractall(output, filter="data")
    roots = list(output.iterdir())
    if len(roots) != 1 or not roots[0].is_dir():
        raise ValueError("Expected a single source directory")
    return roots[0]


def prepare(name, output):
    for parent in output.resolve().parents:
        manifest = parent / "Cargo.toml"
        if manifest.is_file() and "workspace" in tomllib.loads(manifest.read_text()):
            raise ValueError("Prepare sources outside the enclosing Cargo workspace")
    source, data = verified_source(name)
    output.mkdir(parents=True, exist_ok=False)
    archive = output / "upstream.tar.gz"
    archive.write_bytes(data)
    project = unpack(archive, output / "extracted")
    destination = output / "project"
    if not project.resolve().is_relative_to(output.resolve()) or not destination.resolve().is_relative_to(output.resolve()):
        raise ValueError("Source move escapes the build workspace")
    project.rename(destination)
    (output / "source-report.json").write_text(json.dumps({"package": name, **source, "device_runtime": "unverified"}, indent=2) + "\n")


def check_wheel(path):
    name, version, _, tags = parse_wheel_filename(path.name)
    sources = json.loads(LOCK.read_text())["packages"]
    expected = next((v for k, v in sources.items() if canonicalize_name(k) == name), None)
    if not expected or str(version) != expected["version"] or not all(t.platform == "android_24_arm64_v8a" for t in tags):
        raise ValueError("Wheel name, version or Android target differs from the source qualification")
    spec = importlib.util.spec_from_file_location("alignment", ROOT / "scripts/check-android-apk.py")
    alignment = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(alignment)
    libraries = []
    with zipfile.ZipFile(path) as wheel:
        manifests = [e for e in wheel.infolist() if e.filename.endswith(".dist-info/METADATA")]
        if len(manifests) != 1 or manifests[0].file_size > 1_000_000:
            raise ValueError("Missing or oversized wheel metadata")
        manifest = BytesParser().parsebytes(wheel.read(manifests[0]))
        if canonicalize_name(manifest.get("Name", "")) != name or manifest.get("Version") != str(version):
            raise ValueError("Wheel contents disagree with its name/version")
        for entry in wheel.infolist():
            if ".so" not in Path(entry.filename).name:
                continue
            with wheel.open(entry) as library:
                header = library.read(20)
                if len(header) < 20 or struct.unpack_from("<H", header, 18)[0] != 183:
                    raise ValueError("Native library is not Android arm64")
                library.seek(0)
                alignment.check_elf(library, entry.file_size)
                libraries.append(entry.filename)
    if not libraries:
        raise ValueError("Expected native libraries in the wheel")
    report = {"wheel": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
              "libraries": libraries, "elf_16k_alignment": "passed", "device_runtime": "unverified"}
    path.with_suffix(".qualification.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("lock")
    prep = commands.add_parser("prepare")
    prep.add_argument("--package", choices=PACKAGES, required=True)
    prep.add_argument("--output", type=Path, required=True)
    check = commands.add_parser("check")
    check.add_argument("wheel", type=Path)
    args = parser.parse_args()
    if args.command == "lock": refresh_lock()
    elif args.command == "prepare": prepare(args.package, args.output)
    else: check_wheel(args.wheel)
