"""Read the reviewed authority release pin without importing or starting core."""
import re
from pathlib import Path


def required_core_version(path=None):
    path = Path(path) if path is not None else Path(__file__).with_name("core-requirements.txt")
    requirements = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.lstrip().startswith("#")]
    if len(requirements) != 1:
        raise ValueError("Pin exactly one Genesis Mesh authority release.")
    match = re.fullmatch(r"genesis-mesh==([0-9]+\.[0-9]+\.[0-9]+)", requirements[0])
    if match is None:
        raise ValueError("The authority requirement must pin an exact Genesis Mesh release.")
    return match.group(1)


def require_installed_core_version(installed=None):
    if installed is None:
        from importlib.metadata import version
        installed = version("genesis-mesh")
    expected = required_core_version()
    if installed != expected:
        raise ValueError(f"Authority Python has Genesis Mesh {installed}; this checkout requires {expected}. "
                         "Choose an isolated matching environment with -AuthorityPython.")
    return installed


if __name__ == "__main__":
    print(f"Authority Python matches pinned Genesis Mesh {require_installed_core_version()}.")
