"""Account-bound owner key storage. No machine-wide DPAPI or UI prompts."""
import ctypes
import os
import base64
import json
import sys
from ctypes import wintypes

MAGIC = b"GenesisMesh.Connect.Owner.DPAPI.v1\0"
MAX_SECRET = 16 * 1024


def native(operation, data=None):
    if os.environ.get("CONNECT_NATIVE_SECRETS") != "1" or sys.platform not in ("darwin", "linux"):
        raise RuntimeError("A supported native credential store is required")
    request = {"op": operation}
    if data is not None:
        if not data or len(data) > MAX_SECRET:
            raise ValueError("Invalid owner secret size")
        request["data"] = base64.b64encode(data).decode("ascii")
    print(json.dumps({"native_storage": request}), flush=True)
    line = sys.stdin.buffer.readline(32769)
    if not line or len(line) > 32768:
        raise RuntimeError("The native credential store did not respond")
    response = json.loads(line)
    if "error" in response:
        raise RuntimeError("Unlock the system credential store to use the network owner keys")
    if operation == "ready":
        if response != {"ok": {"ready": True}}:
            raise RuntimeError("Invalid credential store response")
        return None
    result = base64.b64decode(response["ok"]["data"], validate=True)
    if not result or len(result) > MAX_SECRET:
        raise RuntimeError("Invalid credential store response")
    return result


def ready():
    if os.name != "nt":
        native("ready")


def transform(data: bytes, encrypt: bool) -> bytes:
    if os.name != "nt":
        raise RuntimeError("Managed authority storage requires Windows")
    if not data or len(data) > MAX_SECRET:
        raise ValueError("Invalid owner secret size")

    class Blob(ctypes.Structure):
        _fields_ = [("length", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]

    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    source = ctypes.create_string_buffer(data)
    domain = ctypes.create_string_buffer(MAGIC)
    original = Blob(len(data), ctypes.cast(source, ctypes.POINTER(ctypes.c_ubyte)))
    entropy = Blob(len(MAGIC), ctypes.cast(domain, ctypes.POINTER(ctypes.c_ubyte)))
    output = Blob()
    function = crypt.CryptProtectData if encrypt else crypt.CryptUnprotectData
    function.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    function.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    try:
        if not function(ctypes.byref(original), None, ctypes.byref(entropy), None, None, 1, ctypes.byref(output)):
            raise RuntimeError("Windows could not unlock the network owner keys")
        if not output.data or output.length > MAX_SECRET:
            raise RuntimeError("Invalid protected owner key")
        return ctypes.string_at(output.data, output.length)
    finally:
        ctypes.memset(source, 0, len(source))
        if output.data:
            ctypes.memset(output.data, 0, output.length)
            kernel.LocalFree(output.data)


def protect(data: bytes) -> bytes:
    if os.name != "nt":
        return native("seal", data)
    return MAGIC + transform(data, True)


def unprotect(data: bytes) -> bytes:
    if os.name != "nt":
        return native("open", data)
    if not data.startswith(MAGIC):
        raise ValueError("Owner key is not account-protected")
    return transform(data[len(MAGIC):], False)
