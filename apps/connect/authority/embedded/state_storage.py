"""Private fixed-name state, no-follow reads and one live authority writer."""
import json
import os
from pathlib import Path
import stat
import tempfile
import hashlib
import re


class Refused(RuntimeError):
    pass

STATE_FILES = frozenset({"state.json", "initializing.json", "root.sealed", "owner.sealed", "member.sealed", "authority.db", "member-renewal.json"})

class StateStorage:
    def __init__(self, directory, *, publish_new=None):
        self.directory = Path(directory).absolute()
        self.lock = None
        self.readonly = False
        self.publish_new = os.link if publish_new is None else publish_new

    def acquire(self, *, create=False):
        self._acquire(create=create, readonly=False)

    def acquire_readonly(self):
        """Lock an existing profile without creating a lock, directory or state."""
        self._acquire(create=False, readonly=True)

    def _acquire(self, *, create, readonly):
        if self.lock is not None:
            raise Refused("The authority is already open.")
        if create:
            self.directory.mkdir(mode=0o700, exist_ok=True)
        if not self.directory.is_dir() or self.directory.is_symlink():
            raise Refused("Existing authority storage needs attention.")
        path = self.directory / ".authority-lock"
        if path.is_symlink():
            raise Refused("Authority storage links are not permitted.")
        flags = os.O_RDONLY if readonly else os.O_RDWR | os.O_CREAT
        descriptor = os.open(path, flags | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise Refused("Invalid authority lock.")
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.lock = descriptor
            self.readonly = readonly
        except Exception:
            os.close(descriptor)
            raise Refused("Another authority is using this storage.") from None

    def release(self):
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None

    def path(self, name):
        # Only adapter constants may name files; never accept a frontend path.
        if name not in STATE_FILES:
            raise Refused("Unsupported authority state file.")
        return self.directory / name

    def sync(self):
        if self.readonly: raise Refused("Inspection cannot sync authority state.")
        if os.name != "nt":
            descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(descriptor)
            finally: os.close(descriptor)

    def write_new(self, name, content):
        self._write(name, content, replace=False)

    def replace_state(self, content, expected):
        if self.read("state.json") != expected:
            raise Refused("Authority state changed before commit.")
        self._write("state.json", content, replace=True)

    def _write(self, name, content, *, replace):
        if self.readonly or self.lock is None or not isinstance(content, bytes) or not 0 < len(content) <= 65536:
            raise Refused("Invalid authority state write.")
        descriptor, pending = tempfile.mkstemp(prefix=".state-", dir=self.directory)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            if replace: os.replace(pending, self.path(name))
            else: self.publish_new(pending, self.path(name))  # Creation never replaces prior state.
            self.sync()
        finally:
            Path(pending).unlink(missing_ok=True)

    def read(self, name, limit=65536):
        return self._read(self.path(name), limit)

    def read_staged(self, name):
        if not isinstance(name, str) or not re.fullmatch(r"\.state-[a-z0-9_]{8}", name):
            raise Refused("Unknown authority staging file.")
        return self._read(self.directory / name, 65536)

    def _read(self, path, limit):
        if path.is_symlink():
            raise Refused("Authority storage links are not permitted.")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit
                    or getattr(metadata, "st_file_attributes", 0) & 1024):
                raise Refused("Invalid or oversized authority state.")
            content = stream.read(limit + 1)
        if not content or len(content) > limit:
            raise Refused("Missing or oversized authority state.")
        return content

    def check_files(self, *, allow_renewal=False):
        allowed = {".authority-lock", "state.json", "root.sealed", "owner.sealed", "member.sealed",
                   "authority.db", "authority.db-wal", "authority.db-shm", "authority.db-journal"}
        if allow_renewal: allowed.add("member-renewal.json")
        staged = []
        for path in self.directory.iterdir():
            if path.is_symlink() or not path.is_file(): raise Refused("Authority storage links or non-files are not permitted.")
            if path.name in allowed: continue
            if not re.fullmatch(r"\.state-[a-z0-9_]{8}", path.name) or len(staged) >= 8:
                raise Refused("Authority setup was interrupted or storage needs attention. Existing identity was preserved.")
            self.read_staged(path.name)  # Read-only bounded inventory, not permission to adopt or discard.
            staged.append(path.name)
        return staged

    def check_evidence(self, recorded, staged, *, allow_unrecorded=False):
        if not isinstance(recorded, dict) or len(recorded) > 8:
            raise Refused("Invalid authority recovery evidence index.")
        for name, digest in recorded.items():
            if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
                raise Refused("Invalid authority recovery evidence digest.")
            if name not in staged or hashlib.sha256(self.read_staged(name)).hexdigest() != digest:
                raise Refused("Authenticated authority recovery evidence is missing or changed.")
        unrecorded = sorted(set(staged) - set(recorded))
        if unrecorded and not allow_unrecorded:
            raise Refused("Interrupted authority staging needs authenticated recovery.")
        return unrecorded


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
