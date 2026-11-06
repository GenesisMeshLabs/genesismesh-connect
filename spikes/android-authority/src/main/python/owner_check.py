"""Fixed disposable phone-local owner qualification; never a public Create UI."""
import hashlib
import json
from pathlib import Path

from owner_adapter import EmbeddedOwner


class AndroidVault:
    def __init__(self, native): self.native = native
    def ready(self): self.native.ready()
    def create(self): self.native.create()
    def seal_owner(self, instance, data): return bytes(self.native.seal_owner(instance, data))
    def seal_member(self, instance, data): return bytes(self.native.seal_member(instance, data))
    def _open(self, method, instance, data):
        plaintext = method(instance, data)
        try: return bytes(plaintext)
        finally:
            for index in range(len(plaintext)): plaintext[index] = 0
    def open_owner(self, instance, data): return self._open(self.native.open_owner, instance, data)
    def open_member(self, instance, data): return self._open(self.native.open_member, instance, data)


def run(expected_version, directory, native):
    report = {"status": "running", "production_create_enabled": False, "checks": []}
    first = second = None
    stage = "Protected owner custody"
    try:
        readiness = str(native.readiness())
        if readiness != "ready":
            report.update(status="blocked", stage=stage, readiness=readiness)
            return json.dumps(report)
        vault = AndroidVault(native)
        vault.ready()
        first = EmbeddedOwner(directory, vault, expected_version)
        stage = "Phone-local authority"
        if Path(directory).exists():
            identity = first.open()
            report["initial_operation"] = "reopen"
        else:
            identity = first.create("Phone-local qualification")
            report["initial_operation"] = "create"
        if not first.check_member(): raise RuntimeError("Local member check failed")
        report["checks"].append({"name": "Real local authority and membership", "passed": True})
        stage = "Purpose-separated owner custody"
        try:
            vault.open_member(identity["instance"], first.storage.read("owner.sealed"))
        except Exception:
            pass
        else:
            raise RuntimeError("Owner record accepted in member custody domain")
        report["checks"].append({"name": stage, "passed": True})
        stage = "Close and reopen identity"
        first.close()
        second = EmbeddedOwner(directory, vault, expected_version)
        if second.open() != identity or not second.check_member(): raise RuntimeError("Identity changed after reopen")
        report["checks"].append({"name": stage, "passed": True})
        # Only public identity fingerprints/certificate ID appear in the developer report.
        report["identity"] = {key: hashlib.sha256(value.encode()).hexdigest()
            for key, value in identity.items() if key.endswith("public_key")}
        report["identity"]["certificate_id"] = identity["certificate_id"]
        report["status"] = "passed"
    except Exception as error:
        report.update(status="failed", stage=stage, exception_type=type(error).__name__)
    finally:
        if first is not None: first.close()
        if second is not None: second.close()
    return json.dumps(report)
