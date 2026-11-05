"""Collect qualified source wheels and verify dependencies with Android markers."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name, parse_wheel_filename

import android_authority_sources as sources


def lock_digest(path):
    value = json.loads(path.read_text())
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def collect(root, output):
    wheels = sorted(root.rglob("*.whl"))
    names = [parse_wheel_filename(w.name)[0] for w in wheels]
    if len(names) != len(set(names)) or set(names) != set(map(canonicalize_name, sources.PACKAGES)):
        raise ValueError("The native wheel bundle must contain exactly one of every required package")
    lock = json.loads(sources.LOCK.read_text())
    if lock["authority_pin_sha256"] != hashlib.sha256(str(sources.pin()).encode()).hexdigest():
        raise ValueError("Authority pin changed; source lock is stale")
    entries = {}
    native_lock = json.loads(sources.LOCK.with_name("android-authority-native.lock.json").read_text())
    if lock.get("schema") != 1 or native_lock.get("schema") != 1:
        raise ValueError("Unsupported source qualification schema")
    for wheel in wheels:
        inspected = sources.check_wheel(wheel)
        name = parse_wheel_filename(wheel.name)[0]
        expected = next(v for k, v in lock["packages"].items() if canonicalize_name(k) == name)
        report = json.loads((wheel.parent.parent / "source-report.json").read_text())
        if any(report.get(k) != expected[k] for k in ("version", "url", "sha256")) or report.get("patches", []) != expected.get("patches", []):
            raise ValueError("Wheel source provenance differs from the reviewed source lock")
        if name in ("cffi", "pynacl"):
            native = json.loads((wheel.parent.parent / "project/connect-native-report.json").read_text())
            if native.get("target") != "Android arm64 API24" or native.get("linkage") != "static":
                raise ValueError("Native library target or linkage differs from the build profile")
            if name == "cffi" and any(native.get(k) != native_lock["libffi"][k] for k in ("version", "url", "sha256")):
                raise ValueError("libffi provenance differs from the native source lock")
            if name == "pynacl" and native.get("minimal_build") is not False:
                raise ValueError("A reduced sodium build cannot qualify")
        entries[name] = {k: inspected[k] for k in ("wheel", "version", "sha256")}
    output.mkdir(parents=True, exist_ok=False)
    for wheel in wheels:
        shutil.copy2(wheel, output / wheel.name)
    manifest = {"schema": 1, "authority_pin_sha256": lock["authority_pin_sha256"],
                "source_lock_sha256": lock_digest(sources.LOCK),
                "native_lock_sha256": lock_digest(sources.LOCK.with_name("android-authority-native.lock.json")),
                "wheels": entries}
    (output / "native-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


def validate_graph(root):
    reports = [sources.inspect_wheel(w) for w in sorted(root.glob("*.whl"))]
    if not reports or len(reports) > 128:
        raise ValueError("Missing or oversized dependency closure")
    packages = {r["name"]: r for r in reports}
    if len(packages) != len(reports):
        raise ValueError("Duplicate package versions in dependency closure")
    environment = sources.android_environment()
    for report in reports:
        if not SpecifierSet(report["requires_python"]).contains(environment["python_full_version"]):
            raise ValueError(f"Incompatible Python requirement: {report['name']}")
    pending = [sources.pin()]
    seen = set()
    while pending:
        requirement = pending.pop()
        key = (canonicalize_name(requirement.name), frozenset(requirement.extras))
        if len(seen) >= 1024 or requirement.url:
            raise ValueError("Unsupported or oversized dependency graph")
        report = packages.get(key[0])
        if not report or not requirement.specifier.contains(report["version"]):
            raise ValueError(f"Missing or incompatible Android dependency: {requirement}")
        # Every incoming constraint is checked. Only expansion is deduplicated.
        if key in seen:
            continue
        seen.add(key)
        for raw in report["requires_dist"]:
            child = Requirement(raw)
            if not child.marker or any(child.marker.evaluate({**environment, "extra": extra}) for extra in key[1] | {""}):
                pending.append(child)
    reached = {k[0] for k in seen}
    return {"schema": 1, "gate": "android_marker_dependency_graph", "status": "graph_valid", "native_artifacts_bound": False,
              "target_marker_environment": environment, "hosting_accepted": False, "device_runtime": "unverified",
              "packages": [r for r in reports if r["name"] in reached], "unused_packages": sorted(set(packages) - reached)}


def verify(root, native_manifest):
    if native_manifest.stat().st_size > 1_000_000:
        raise ValueError("Native artifact manifest is oversized")
    manifest = json.loads(native_manifest.read_text())
    expected_names = set(map(canonicalize_name, sources.PACKAGES))
    if (manifest.get("schema") != 1 or set(manifest.get("wheels", {})) != expected_names
        or manifest.get("authority_pin_sha256") != hashlib.sha256(str(sources.pin()).encode()).hexdigest()
        or manifest.get("source_lock_sha256") != lock_digest(sources.LOCK)
        or manifest.get("native_lock_sha256") != lock_digest(sources.LOCK.with_name("android-authority-native.lock.json"))):
        raise ValueError("Native artifact manifest is missing, incomplete or stale")
    result = validate_graph(root)
    reports = {r["name"]: r for r in result["packages"]}
    for name, expected in manifest["wheels"].items():
        report = reports.get(name)
        if not report or any(report[k] != expected[k] for k in ("wheel", "version", "sha256")):
            raise ValueError(f"Resolved native artifact differs from the reviewed bundle: {name}")
        sources.check_wheel(root / report["wheel"])
    result.update(gate="android_marker_dependency_closure", status="available", native_artifacts_bound=True,
                  native_manifest_sha256=hashlib.sha256(native_manifest.read_bytes()).hexdigest())
    (root.parent / "android-marker-report.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def freeze(root, native_manifest, output):
    result = verify(root, native_manifest)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        for report in sorted(result["packages"], key=lambda r: r["name"]):
            stream.write(f"{report['name']}=={report['version']} --hash=sha256:{report['sha256']}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    bundle = commands.add_parser("collect")
    bundle.add_argument("--input", type=Path, required=True)
    bundle.add_argument("--output", type=Path, required=True)
    closure = commands.add_parser("verify")
    closure.add_argument("wheels", type=Path)
    closure.add_argument("--native-manifest", type=Path, required=True)
    frozen = commands.add_parser("freeze")
    frozen.add_argument("wheels", type=Path)
    frozen.add_argument("--native-manifest", type=Path, required=True)
    frozen.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "collect": collect(args.input, args.output)
    elif args.command == "freeze": freeze(args.wheels, args.native_manifest, args.output)
    else: print(f"Android target closure: {len(verify(args.wheels, args.native_manifest)['packages'])} reachable packages; runtime unverified")
