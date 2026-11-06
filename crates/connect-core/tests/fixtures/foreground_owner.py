"""Disposable real-core native transport fixture. Never packaged or used by an app."""
import base64
from contextlib import redirect_stdout
import json
import os
from pathlib import Path
import sys

repository = Path(__file__).resolve().parents[4]
sys.path[:0] = [str(repository / "apps/connect/authority"), str(repository / "apps/connect/authority/embedded")]
from test_embedded_owner import TestVault
from connect_owner import ConnectOwner

directory = Path(sys.argv[1])
directory.mkdir(mode=0o700, exist_ok=True)
class FixtureVault(TestVault):
    def __init__(self):
        super().__init__()
        self.path = directory / "fixture-keys.json"
        if self.path.exists():
            self.keys = {k: base64.b64decode(v, validate=True) for k, v in json.loads(self.path.read_bytes()).items()}
    def has_custody(self): return bool(self.keys)
    def create(self):
        super().create()
        descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump({k: base64.b64encode(v).decode() for k, v in self.keys.items()}, stream)
            stream.flush(); os.fsync(stream.fileno())

with redirect_stdout(sys.stderr): owner = ConnectOwner(directory, FixtureVault())
try:
    for line in sys.stdin:
        request = json.loads(line)
        if request == {"fixture_close": True}: break
        with (directory / "fixture-calls.jsonl").open("a") as stream:
            stream.write(json.dumps(request.get("op")) + "\n")  # No keys or invite tokens in trace.
        try:
            with redirect_stdout(sys.stderr): result = {"ok": owner.request(line)}
        except Exception as error:
            result = {"error": type(error).__name__}
        print(json.dumps(result), flush=True)
finally:
    with redirect_stdout(sys.stderr): owner.close()
