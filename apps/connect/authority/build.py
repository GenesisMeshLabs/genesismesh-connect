"""Build-time packaging only. End users run the bundled executable, not Python."""
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from build_platform import target as native_target, extension

source=Path(__file__).resolve().parent
app=source.parent
target="genesismesh-authority-"+native_target()
scratch=app.parents[1]/"temp"/"authority-build"/native_target()
output=app/"src-tauri"/"binaries"
binary=output/(target+extension())
stamp=scratch/"source.json"
version=importlib.metadata.version("genesis-mesh")
if version!="1.8.1":
    raise SystemExit("Build the owner runtime with genesis-mesh==1.8.1")
core=Path(next(iter(importlib.util.find_spec("genesis_mesh").submodule_search_locations)))
digest=hashlib.sha256()
digest.update((app/"src-tauri"/"icons"/"icon.ico").read_bytes())
for root in (source,core):
    for path in sorted(root.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts or path.suffix in (".pyc",".pyo") or path.name.startswith("test_"): continue
        digest.update(str(path.relative_to(root)).encode()); digest.update(path.read_bytes())
key={"source":digest.hexdigest(),"core_version":version,"python":sys.version,"pyinstaller":"6.22.2"}
if binary.is_file() and stamp.is_file() and json.loads(stamp.read_text())==key:
    print("Bundled authority runtime is current.")
    raise SystemExit(0)
scratch.mkdir(parents=True,exist_ok=True); output.mkdir(parents=True,exist_ok=True)
spec=scratch/"authority.spec"
spec.write_text('''from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata
from importlib.metadata import distributions
from pathlib import Path
import re,sys
licenses=[]
for distribution in distributions():
    name=distribution.metadata['Name']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+',name): raise RuntimeError('Invalid license package name')
    for file in distribution.files or []:
        if file.name.lower().startswith(('license','copying','notice')):
            path=Path(distribution.locate_file(file))
            if path.is_file(): licenses.append((str(path),'licenses/'+name))
python_license=Path(sys.base_prefix)/'LICENSE.txt'
if python_license.is_file(): licenses.append((str(python_license),'licenses/CPython'))
a=Analysis([%r],pathex=[%r],binaries=[],datas=collect_data_files('genesis_mesh')+copy_metadata('genesis-mesh')+licenses,hiddenimports=collect_submodules('genesis_mesh',filter=lambda name:'.tests' not in name),excludes=['pytest','IPython','matplotlib','tkinter'],noarchive=False)
pyz=PYZ(a.pure)
exe=EXE(pyz,a.scripts,a.binaries,a.datas,[],name=%r,icon=%r,debug=False,bootloader_ignore_signals=False,strip=False,upx=False,console=True)
'''%(str(source/"main.py"),str(source),target,str(app/"src-tauri"/"icons"/"icon.ico")),encoding="utf-8")
subprocess.run([sys.executable,"-m","PyInstaller","--noconfirm","--distpath",str(output),"--workpath",str(scratch/"work"),str(spec)],check=True)
stamp.write_text(json.dumps(key,indent=2)+"\n")
print("Packaged Genesis Mesh authority:",binary.name)
