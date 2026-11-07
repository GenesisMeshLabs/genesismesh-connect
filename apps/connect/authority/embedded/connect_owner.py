"""Connect's fixed application operations over the embedded authority.

Native code chooses the private directory and vault. No paths, private keys,
Python names or HTTP routes are accepted through this boundary. Desktop policy
and invitation implementations are reused rather than reimplemented for mobile.
"""
import json
import os
from pathlib import Path
import shutil
import stat
import threading
import tempfile
import uuid

from genesis_mesh.crypto import sign_data, verify_signature

from core_release import required_core_version
from owner import Owner, Refused as OperationRefused
from owner_adapter import EmbeddedOwner, OPERATOR_ID, NA_ID, public
from state_storage import Refused

MAX_REQUEST = 16 * 1024
MAX_REPLY = 512 * 1024
REGISTRY_DOMAIN = b"GenesisMesh.Connect.EmbeddedOwner.Registry.v1\0"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise Refused("Duplicate network operation field.")
        result[key] = value
    return result


def decode_request(text):
    if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_REQUEST:
        raise Refused("Network operation is too large.")
    try:
        value = json.loads(text, object_pairs_hook=unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, RecursionError):
        raise Refused("Invalid network operation.") from None
    if not isinstance(value, dict): raise Refused("Invalid network operation.")
    return value


class ConnectOperations(Owner):
    """Existing app semantics with embedded custody and one fixed public registry."""
    def __init__(self, embedded, directory):
        self.embedded = embedded
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, exist_ok=True)
        if self.directory.is_symlink() or not self.directory.is_dir():
            raise Refused("Shared-item storage needs attention.")
        self.genesis = embedded.genesis
        self.operator, self.na_key = embedded.keys["operator"], embedded.keys["na"]
        self.origin, self.session = embedded.origin, embedded.session
        self.service, self.server = embedded.service, embedded.server
        self.config = {"operator": {"key_id": OPERATOR_ID}, "na": {"key_id": NA_ID}}
        path = self.directory / "spaces.json"
        if not embedded.state.get("connect_registry_initialized", False):
            # An interrupted initialization remains for explicit recovery.
            # Neither a lost registry nor a partial first write becomes [].
            content = self._registry_bytes([])
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content); stream.flush(); os.fsync(stream.fileno())
            self._sync()
            embedded.state["connect_registry_initialized"] = True
            embedded._commit_certificate(embedded.certificate, require_current=False)
        self._spaces()  # Refuse missing, changed or foreign initialized registry.

    def admin(self, path, body):
        self.embedded.vault.ready()
        return super().admin(path, body)

    def read(self, path, params=None):
        self.embedded.vault.ready()
        return super().read(path, params)

    def capabilities(self):
        self.embedded.vault.ready()
        result = super().capabilities()
        result["transport"] = "local_android_embedded"
        return result

    def pairing_ready(self):
        result = super().pairing_ready()
        result["transport"] = "local_android_embedded"
        return result

    def _spaces(self):
        path = self.directory / "spaces.json"
        if path.is_symlink(): raise Refused("Shared-item storage links are not permitted.")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 256 * 1024:
                raise Refused("Shared-item storage needs attention.")
            data = json.loads(stream.read(256 * 1024 + 1), object_pairs_hook=unique_object)
        if (set(data) != {"version", "root", "spaces", "signature"} or data["version"] != 1
                or data["root"] != self.genesis.root_public_key or not isinstance(data["spaces"], list)
                or not verify_signature(REGISTRY_DOMAIN + self._registry_payload(data["spaces"]), data["signature"], public(self.operator))):
            raise Refused("Shared-item storage does not match this network.")
        return data["spaces"]

    def _registry_payload(self, spaces):
        return json.dumps({"version": 1, "root": self.genesis.root_public_key, "spaces": spaces}, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

    def _registry_bytes(self, spaces):
        payload = self._registry_payload(spaces)
        return json.dumps({**json.loads(payload), "signature": sign_data(REGISTRY_DOMAIN + payload, self.operator)}, allow_nan=False).encode()

    def _sync(self):
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)

    def _save_spaces(self, spaces):
        self.embedded.vault.ready()
        self._spaces()  # Never replace a missing or changed initialized registry.
        content = self._registry_bytes(spaces)
        if len(content) > 256 * 1024: raise Refused("The shared-item list is full.")
        descriptor, pending = tempfile.mkstemp(prefix=".registry-", dir=self.directory)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content); stream.flush(); os.fsync(stream.fileno())
            os.replace(pending, self.directory / "spaces.json")
            self._sync()
        finally: Path(pending).unlink(missing_ok=True)


# Exact field sets; callables are internal constants, never caller-selected names.
OPERATIONS = {
    "capabilities": (set(), lambda o, r: o.capabilities()),
    "pairing_ready": (set(), lambda o, r: o.pairing_ready()),
    "resource_capabilities": ({"host", "collection"}, lambda o, r: o.resource_capabilities(r["host"], r["collection"])),
    "invite": ({"node", "host"}, lambda o, r: o.invite(r["node"], r["host"])),
    "space_list": (set(), lambda o, r: o.space_list()),
    "space_renew": (set(), lambda o, r: o.space_renew()),
    "space_remove": ({"host", "collection"}, lambda o, r: o.space_remove(r["host"], r["collection"])),
    "access_get": ({"host", "collection"}, lambda o, r: o.access_get(r["host"], r["collection"])),
    "access_update": ({"host", "collection", "settings"}, lambda o, r: o.access_update(r["host"], r["collection"], r["settings"])),
    "remove_device": ({"node"}, lambda o, r: o.remove_device(r["node"])),
}


def dispatch(operations, request):
    op = request.get("op")
    if not isinstance(op, str): raise Refused("Unsupported network operation.")
    if op == "space_share":
        if not {"op", "host", "collection", "name", "recipients"} <= set(request) <= {"op", "host", "collection", "name", "recipients", "subject", "kind"}:
            raise Refused("Unsupported network operation fields.")
        return operations.space_share(request["host"], request["collection"], request["name"], request["recipients"], request.get("subject"), kind=request.get("kind", "folder"))
    if op == "space_adopt" and set(request) == {"op", "host", "collection", "name", "recipients", "subject"}:
        return operations.space_share(request["host"], request["collection"], request["name"], request["recipients"], request["subject"], adopt=True)
    if op == "share" and {"op", "host", "peer", "collection"} <= set(request) <= {"op", "host", "peer", "collection", "subject"}:
        return operations.share(request["host"], request["peer"], request["collection"], request.get("subject", "connect-host"))
    definition = OPERATIONS.get(op)
    if definition is None or set(request) != definition[0] | {"op"}:
        raise Refused("Unsupported network operation fields.")
    if op == "invite" and type(request["host"]) is not bool:
        raise Refused("Choose a valid device invitation.")
    return definition[1](operations, request)


class ConnectOwner:
    """One serialized native-only owner session. Creation is always explicit."""
    def __init__(self, directory, vault):
        self.directory, self.vault = Path(directory), vault
        self.directory.mkdir(mode=0o700, exist_ok=True)
        if self.directory.is_symlink(): raise Refused("Authority storage links are not permitted.")
        self.embedded = EmbeddedOwner(self.directory / "authority", vault, required_core_version())
        self.operations = None
        self.mutex = threading.RLock()
        self.uncertain = False

    def configured(self):
        path = self.embedded.storage.directory
        # Missing initialized state never becomes permission to create.
        return self.vault.has_custody() or path.is_symlink() or (path.exists() and any(p.name != ".authority-lock" for p in path.iterdir()))

    def info(self):
        identity = self.embedded.identity
        if identity is None: raise Refused("Open the network first.")
        return {"url": self.embedded.origin, "pin": {"root_public_key": identity["root_public_key"], "network_name": identity["network_name"]}, "managed": True}

    def request(self, text):
        with self.mutex:
            request = decode_request(text)
            self.vault.ready()
            if self.uncertain: raise Refused("Restart Connect to review the unfinished operation. Your network was preserved.")
            op = request.get("op")
            if op == "status" and set(request) == {"op"}:
                return {"configured": self.configured(), "running": self.operations is not None,
                        "foreground_only": True, "production_create_enabled": False}
            if op == "recovery_export" and set(request) == {"op"}:
                try:
                    return self._export_recovery()
                except Exception as failure:
                    # Exporting writes nothing the network uses: a declined or
                    # failed export leaves the session as it was.
                    raise Unchanged("The recovery file was not created. Nothing changed.") from failure
            if op == "recovery_import" and set(request) == {"op", "staging", "keys"}:
                try:
                    return self._import_recovery(request["staging"], request["keys"])
                except Exception:
                    self.uncertain = True
                    raise
            if op in ("create", "open"):
                expected = {"op", "name"} if op == "create" else {"op"}
                if set(request) != expected: raise Refused("Unsupported network setup fields.")
                if self.operations is not None:
                    if op == "open":
                        self.embedded.open_for_use()
                        return self.info()
                    raise Refused("A network is already open. Its identity was preserved.")
                if op == "create" and self.configured():
                    raise Refused("Existing authority custody must be reopened, never replaced.")
                try:
                    if op == "create": self.embedded.create(request["name"])
                    else: self.embedded.open_for_use()
                    self.operations = ConnectOperations(self.embedded, self.directory / "application")
                    return self.info()
                except Exception:
                    self.uncertain = True
                    raise
            if self.operations is None: raise Refused("Open the network first.")
            try:
                result = dispatch(self.operations, request)
                if len(json.dumps(result, allow_nan=False).encode()) > MAX_REPLY:
                    raise Refused("The network reply is too large.")
                return result
            except Exception:
                # An operation may already have reached core; no automatic retry.
                self.uncertain = True
                raise

    def _export_recovery(self):
        """Stage this network for a recovery file: the authority's records and the
        signed Spaces registry, in private storage. Changes nothing here."""
        if self.operations is None: raise Refused("Open the network first.")
        # Staging left by an export that did not finish goes first.
        for stale in self.directory.glob(".recovery-*"):
            shutil.rmtree(stale, ignore_errors=True)
        staging = self.directory / f".recovery-{uuid.uuid4().hex}"
        try:
            keys = self.embedded.export_recovery(str(staging))
            application = staging / "application"
            application.mkdir(mode=0o700)
            shutil.copyfile(self.directory / "application" / "spaces.json", application / "spaces.json")
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        return {"staging": str(staging.resolve()), "root": "embedded", "config": "state.json", "keys": keys}

    def _import_recovery(self, staging, keys):
        """Install a network from decrypted recovery files that native code
        staged in this app's private storage. Never replaces a network."""
        if self.operations is not None or self.configured():
            raise Refused("This device already has a network. It has been preserved.")
        if not isinstance(staging, str) or len(staging) > 4096:
            raise Refused("The recovery file was not staged for this device.")
        staging = Path(staging)
        if not staging.is_absolute() or staging.is_symlink() or not staging.is_dir():
            raise Refused("The recovery file was not staged for this device.")
        registry = staging / "application" / "spaces.json"
        if registry.is_symlink() or not registry.is_file():
            raise Refused("The recovery file is incomplete.")
        self.embedded.import_recovery(str(staging), keys)
        application = self.directory / "application"
        application.mkdir(mode=0o700)
        shutil.copyfile(registry, application / "spaces.json")
        # The registry is checked against the network's own operator key here.
        self.operations = ConnectOperations(self.embedded, application)
        return self.info()

    def close(self):
        with self.mutex:
            self.embedded.close()
            self.operations = None


class Unchanged(Refused):
    """A refusal after which the network is exactly as it was."""


def exchange(owner, text):
    """Sanitized result only; no exception, key, invite or path reflection."""
    try: return json.dumps({"ok": owner.request(text)}, allow_nan=False)
    except Unchanged as refusal:
        return json.dumps({"unchanged": str(refusal)[:200]})
    except (Refused, OperationRefused):
        return json.dumps({"error": "The local network operation was refused. Existing state was preserved."})
    except Exception:
        return json.dumps({"error": "The local network operation did not finish. Restart Connect to review the saved network."})
