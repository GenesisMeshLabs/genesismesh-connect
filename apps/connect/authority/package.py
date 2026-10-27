"""Native desktop packaging in a Connect-owned isolated build environment."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tomllib
import venv
from pathlib import Path
from build_platform import target as native_target, extension

source=Path(__file__).resolve().parent
root=source.parents[2]
core=Path(os.environ.get("CONNECT_CORE_SOURCE",str(root.parent/"genesismesh"))).resolve()
project=tomllib.loads((core/"pyproject.toml").read_text())
if project["project"]["version"]!="1.8.1": raise SystemExit("Package the supported Genesis Mesh 1.8.1 source.")
scratch=root/"temp"/"authority-build"/native_target()
scratch.mkdir(parents=True,exist_ok=True)
build_env=scratch/"environment"
python=build_env/"Scripts"/"python.exe" if os.name == "nt" else build_env/"bin"/"python"
if not python.is_file(): venv.EnvBuilder(with_pip=True).create(build_env)
digest=hashlib.sha256()
digest.update((source.parent/"src-tauri"/"icons"/"icon.ico").read_bytes())
allowed={".py",".sql",".json",".html",".css",".js",".png",".svg",".ico",".txt",".typed",".toml",".md"}
files=[]
for parent in (source,core/"genesis_mesh"):
    for path in sorted(parent.rglob("*")):
        if not path.is_file() or any(p in ("tests","__pycache__") for p in path.relative_to(parent).parts) or path.name.startswith("test_") or path.suffix not in allowed: continue
        digest.update(str(path.relative_to(parent)).encode()); digest.update(path.read_bytes())
        if parent==core/"genesis_mesh": files.append(path)
for name in ("pyproject.toml","README.md","LICENSE"):
    digest.update((core/name).read_bytes())
fingerprint=digest.hexdigest()
binary=source.parent/"src-tauri"/"binaries"/("genesismesh-authority-"+native_target()+extension())
stamp=scratch/"package.json"
if binary.is_file() and stamp.is_file() and json.loads(stamp.read_text()).get("source")==fingerprint:
    print("Bundled authority runtime is current."); raise SystemExit(0)
snapshot=scratch/("core-"+fingerprint[:16])
snapshot.mkdir(exist_ok=True)
for path in files:
    target=snapshot/"genesis_mesh"/path.relative_to(core/"genesis_mesh")
    target.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(path,target)
for name in ("pyproject.toml","README.md","LICENSE"): shutil.copyfile(core/name,snapshot/name)
env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1"}
env.pop("PYTHONPATH",None)
def run(*args): subprocess.run([str(python),*args],check=True,env=env)
run("-m","pip","install","--no-compile","--disable-pip-version-check","-r",str(source/"build-requirements.txt"),str(snapshot))
run(str(source/"build.py"))
versions=subprocess.check_output([str(python),"-m","pip","freeze"],text=True,env=env)
stamp.write_text(json.dumps({"source":fingerprint,"core_version":"1.8.1","dependencies":versions.splitlines()},indent=2)+"\n")
