"""Private fixed-name state, no-follow reads and one live authority writer."""
import json
import os
from pathlib import Path
import stat
import tempfile


class Refused(RuntimeError):
    pass


class StateStorage:
    def __init__(self, directory):
        self.directory = Path(directory).absolute()
        self.lock = None

    def acquire(self, *, create=False):
        if self.lock is not None:
            raise Refused("The authority is already open.")
        if create:
            self.directory.mkdir(mode=0o700, exist_ok=True)
        if not self.directory.is_dir() or self.directory.is_symlink():
            raise Refused("Existing authority storage needs attention.")
        path = self.directory / ".authority-lock"
        if path.is_symlink():
            raise Refused("Authority storage links are not permitted.")
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
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
        except Exception:
            os.close(descriptor)
            raise Refused("Another authority is using this storage.") from None

    def release(self):
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None

    def path(self, name):
        # Only adapter constants may name files; never accept a frontend path.
        if name not in {"state.json", "initializing.json", "owner.sealed", "member.sealed", "authority.db", "member-renewal.json"}:
            raise Refused("Unsupported authority state file.")
        return self.directory / name

    def sync(self):
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
        if self.lock is None or not isinstance(content, bytes) or not 0 < len(content) <= 65536:
            raise Refused("Invalid authority state write.")
        descriptor, pending = tempfile.mkstemp(prefix=".state-", dir=self.directory)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            if replace: os.replace(pending, self.path(name))
            else: os.link(pending, self.path(name))  # Creation never replaces prior state.
            self.sync()
        finally:
            Path(pending).unlink(missing_ok=True)

    def read(self, name, limit=65536):
        path = self.path(name)
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
        allowed = {".authority-lock", "state.json", "owner.sealed", "member.sealed",
                   "authority.db", "authority.db-wal", "authority.db-shm", "authority.db-journal"}
        if allow_renewal: allowed.add("member-renewal.json")
        if any(p.name not in allowed or p.is_symlink() or not p.is_file() for p in self.directory.iterdir()):
            raise Refused("Authority setup was interrupted or storage needs attention. Existing identity was preserved.")


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
