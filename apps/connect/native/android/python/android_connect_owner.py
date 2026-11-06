"""Native-selected bootstrap; never registered as a frontend Python dispatcher."""
import json
from pathlib import Path

from android_storage import AndroidPublisher
from connect_owner import ConnectOwner, exchange as owner_exchange
from core_release import required_core_version


class AndroidReadVault:
    """Only daily custody reads; no create/seal/root-decrypt primitive."""
    def __init__(self, native):
        self.native = native

    def ready(self): self.native.ready()
    def require_root_custody(self): self.native.require_root_custody()
    def _open(self, method, instance, data):
        plaintext = method(instance, data)
        try: return bytes(plaintext)
        finally:
            for index in range(len(plaintext)): plaintext[index] = 0
    def open_owner(self, instance, data): return self._open(self.native.open_owner, instance, data)
    def open_member(self, instance, data): return self._open(self.native.open_member, instance, data)


class AndroidVault(AndroidReadVault):
    def __init__(self, native, directory):
        super().__init__(native)
        self.publish_new = AndroidPublisher(Path(directory) / "authority")

    def create(self): self.native.create()
    def has_custody(self): return bool(self.native.hasCustody())
    def seal_root(self, instance, data): return bytes(self.native.seal_root(instance, data))
    def seal_owner(self, instance, data): return bytes(self.native.seal_owner(instance, data))
    def seal_member(self, instance, data): return bytes(self.native.seal_member(instance, data))


def begin(native_directory, native_vault):
    # Only the native bridge constructs these values from its application context.
    return ConnectOwner(native_directory, AndroidVault(native_vault, native_directory))


def handshake(owner):
    owner.vault.ready()
    return json.dumps({"ok": {"schema": 1, "core_version": required_core_version(),
                            "native_only": True, "production_create_enabled": False}})


def exchange(owner, request):
    return owner_exchange(owner, request)


def inspect_membership(native_directory, native_vault):
    """Fresh inspection, not an operation on a poisoned/mutating ConnectOwner."""
    from membership_inspection import inspect
    result = inspect(Path(native_directory) / "authority", AndroidReadVault(native_vault), required_core_version())
    return json.dumps({"ok": result})
