"""Android-private no-replace publication. No OS policy or permission changes."""
import errno
import os
from pathlib import Path
import re
import stat

from state_storage import Refused, STATE_FILES


class AndroidPublisher:
    def __init__(self, directory):
        from cffi import FFI
        self.directory = Path(directory).absolute()
        self.ffi = FFI()
        self.ffi.cdef("int renameat2(int, const char *, int, const char *, unsigned int);")
        self.library = self.ffi.dlopen("libc.so")
        try:
            self.rename = self.library.renameat2
        except AttributeError:
            raise Refused("Atomic private storage is unavailable on this Android runtime.") from None

    def __call__(self, source, target):
        source, target = Path(source), Path(target)
        if (not source.is_absolute() or not target.is_absolute()
                or source.parent != self.directory or target.parent != self.directory
                or not re.fullmatch(r"\.state-[a-z0-9_]{8}", source.name)
                or target.name not in STATE_FILES or self.directory.is_symlink()
                or not stat.S_ISREG(source.lstat().st_mode)):
            raise Refused("Atomic state publication requires fixed private staging paths.")
        # Bionic API30: AT_FDCWD and RENAME_NOREPLACE, not ordinary rename/replace.
        # Any unsupported runtime/filesystem error is fatal; never fall back to
        # a check-then-rename, overwrite or a blocked hard-link operation.
        result = self.rename(-100, os.fsencode(source), -100, os.fsencode(target), 1)
        if result != 0:
            raise OSError(self.ffi.errno or errno.EIO, "Atomic no-replace state publication failed")


def check_publication(directory):
    """Probe only a fresh public-data temporary directory, never owner state."""
    from state_storage import StateStorage
    folder = Path(directory).absolute()
    storage = StateStorage(folder, publish_new=AndroidPublisher(folder))
    storage.acquire(create=True)
    try:
        storage.write_new("initializing.json", b'{"probe":"original"}')
        try:
            storage.write_new("initializing.json", b'{"probe":"replacement"}')
        except FileExistsError:
            pass
        else:
            raise Refused("Atomic state publication did not refuse an existing target.")
        if storage.read("initializing.json") != b'{"probe":"original"}':
            raise Refused("Atomic state publication changed an existing target.")
    finally:
        storage.release()
