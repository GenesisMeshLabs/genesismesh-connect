"""Resolve the unchanged authority pin for Android; never install or execute it.

Success proves wheel availability only, not embedded runtime or device hosting.
Use --wheelhouse for independently built/qualified missing native dependencies.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "apps/connect/authority/core-requirements.txt"


def core_pin(path=REQUIREMENTS):
    entries = [line.split("#", 1)[0].strip() for line in path.read_text(encoding="utf-8").splitlines()]
    entries = [line for line in entries if line]
    if len(entries) != 1 or not re.fullmatch(r"genesis-mesh==[0-9][a-zA-Z0-9.!+_-]*", entries[0]):
        raise ValueError("Expected exactly the single exact authority pin; no overrides are permitted")
    return entries[0]


def command(pin, destination, wheelhouse=None):
    args = [sys.executable, "-m", "pip", "--isolated", "--disable-pip-version-check", "download",
            "--only-binary=:all:", "--implementation", "cp", "--python-version", "3.13",
            "--abi", "cp313", "--abi", "abi3", "--abi", "none",
            "--index-url", "https://pypi.org/simple",
            "--extra-index-url", "https://chaquo.com/pypi-13.1/",
            "--dest", str(destination)]
    for api in range(24, 20, -1):
        args += ["--platform", f"android_{api}_arm64_v8a"]
    if wheelhouse is not None:
        args += ["--find-links", str(wheelhouse.resolve(strict=True))]
    return args + [pin]


def probe(output, wheelhouse=None, runner=subprocess.run):
    pin = core_pin()
    # Refuse stale output: a previous partial download must never look complete.
    output.mkdir(parents=True, exist_ok=False)
    wheels = output / "wheels"
    wheels.mkdir()
    report = {"schema": 1, "pin": pin, "target": "Android arm64 API24 CPython3.13",
              "gate": "binary_dependency_resolution", "status": "unconfirmed",
              "hosting_accepted": False, "wheels": []}
    with (output / "resolver.log").open("w", encoding="utf-8") as log:
        try:
            result = runner(command(pin, wheels, wheelhouse), stdout=log, stderr=subprocess.STDOUT,
                            check=False, timeout=900,
                            env={**os.environ, "PIP_CONFIG_FILE": os.devnull})
            report["resolver_exit_code"] = result.returncode
            report["status"] = "available" if result.returncode == 0 else "unavailable"
        except (subprocess.TimeoutExpired, OSError) as error:
            # Do not persist exception text, which may contain environment data.
            report["failure"] = type(error).__name__
    for wheel in sorted(wheels.glob("*.whl")):
        report["wheels"].append({"name": wheel.name, "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest()})
    if report["status"] == "available" and not report["wheels"]:
        report["status"] = "unconfirmed"
        report["failure"] = "NoWheelsProduced"
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New artifact directory; must not already exist")
    parser.add_argument("--wheelhouse", type=Path, help="Optional locally built Android wheels; pins remain unchanged")
    args = parser.parse_args()
    report = probe(args.output, args.wheelhouse)
    print(f"Android authority dependency resolution: {report['status']}; hosting is NOT accepted")
    return 0 if report["status"] == "available" else 1


if __name__ == "__main__":
    raise SystemExit(main())
