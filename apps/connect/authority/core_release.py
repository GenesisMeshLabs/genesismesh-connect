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
