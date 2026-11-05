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


def collect(root, output):
    wheels = sorted(root.rglob("*.whl"))
    names = [parse_wheel_filename(w.name)[0] for w in wheels]
    if len(names) != len(set(names)) or set(names) != set(map(canonicalize_name, sources.PACKAGES)):
        raise ValueError("The native wheel bundle must contain exactly one of every required package")
    lock = json.loads(sources.LOCK.read_text())
    if lock["authority_pin_sha256"] != hashlib.sha256(str(sources.pin()).encode()).hexdigest():
        raise ValueError("Authority pin changed; source lock is stale")
    for wheel in wheels:
        sources.check_wheel(wheel)
        name = parse_wheel_filename(wheel.name)[0]
        expected = next(v for k, v in lock["packages"].items() if canonicalize_name(k) == name)
        report = json.loads((wheel.parent.parent / "source-report.json").read_text())
        if any(report.get(k) != expected[k] for k in ("version", "url", "sha256")) or report.get("patches", []) != expected.get("patches", []):
            raise ValueError("Wheel source provenance differs from the reviewed source lock")
    output.mkdir(parents=True, exist_ok=False)
    for wheel in wheels:
        shutil.copy2(wheel, output / wheel.name)


def verify(root):
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
        if key in seen:
            continue
        if len(seen) >= 1024 or requirement.url:
            raise ValueError("Unsupported or oversized dependency graph")
        report = packages.get(key[0])
        if not report or not requirement.specifier.contains(report["version"]):
            raise ValueError(f"Missing or incompatible Android dependency: {requirement}")
        seen.add(key)
        for raw in report["requires_dist"]:
            child = Requirement(raw)
            if not child.marker or any(child.marker.evaluate({**environment, "extra": extra}) for extra in key[1] | {""}):
                pending.append(child)
    reached = {k[0] for k in seen}
    result = {"schema": 1, "gate": "android_marker_dependency_closure", "status": "available",
              "target_marker_environment": environment, "hosting_accepted": False, "device_runtime": "unverified",
              "packages": [r for r in reports if r["name"] in reached], "unused_packages": sorted(set(packages) - reached)}
    (root.parent / "android-marker-report.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    bundle = commands.add_parser("collect")
    bundle.add_argument("--input", type=Path, required=True)
    bundle.add_argument("--output", type=Path, required=True)
    closure = commands.add_parser("verify")
    closure.add_argument("wheels", type=Path)
    args = parser.parse_args()
    if args.command == "collect": collect(args.input, args.output)
    else: print(f"Android target closure: {len(verify(args.wheels)['packages'])} reachable packages; runtime unverified")
