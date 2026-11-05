"""Fixed real-core runtime checks. No console, owner keys or network creation."""
import importlib.metadata
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading


def run(expected_version):
    report = {"status": "running", "checks": [], "authority_hosting_accepted": False}
    stage = "Android runtime"
    try:
        assert hasattr(sys, "getandroidapilevel") and sys.getandroidapilevel() >= 24
        report.update(python_version=sys.version.split()[0], platform=sys.platform,
                      python_android_api=sys.getandroidapilevel())
        stage = "Core loading"
        version = importlib.metadata.version("genesis-mesh")
        assert version == expected_version
        from genesis_mesh.crypto import generate_keypair, sign_data, verify_signature
        from genesis_mesh.models.genesis import GenesisBlock
        from genesis_mesh.na_service.server import NetworkAuthorityService
        assert callable(NetworkAuthorityService)
        report["core_version"] = version
        report["checks"].append({"name": stage, "passed": True})

        stage = "Core signatures"
        key = generate_keypair()
        message = b"Genesis Mesh Android engine check"
        signature = sign_data(message, key.private_key)
        assert verify_signature(message, signature, key.public_key)
        assert not verify_signature(message + b"changed", signature, key.public_key)
        assert not verify_signature(message, signature, generate_keypair().public_key)
        report["checks"].append({"name": stage, "passed": True})

        stage = "Native calls"
        import cffi
        ffi = cffi.FFI()
        ffi.cdef("int abs(int);")
        assert ffi.dlopen("libc.so").abs(-23) == 23
        report["checks"].append({"name": stage, "passed": True})

        stage = "Encryption"
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.exceptions import InvalidTag
        cipher = AESGCM(AESGCM.generate_key(bit_length=256))
        nonce = os.urandom(12)
        encrypted = cipher.encrypt(nonce, message, b"engine-check")
        assert cipher.decrypt(nonce, encrypted, b"engine-check") == message
        try:
            cipher.decrypt(nonce, encrypted[:-1] + bytes([encrypted[-1] ^ 1]), b"engine-check")
        except InvalidTag:
            pass
        else:
            raise AssertionError("Tampered ciphertext accepted")
        report["checks"].append({"name": stage, "passed": True})

        stage = "Model validation"
        from pydantic import ValidationError
        from pydantic_core import SchemaValidator
        assert SchemaValidator({"type": "int", "strict": True}).validate_python(42) == 42
        try:
            GenesisBlock.model_validate({})
        except ValidationError:
            pass
        else:
            raise AssertionError("Invalid core model accepted")
        report["checks"].append({"name": stage, "passed": True})

        stage = "Local storage"
        with tempfile.TemporaryDirectory(prefix="gm-engine-check-") as folder:
            path = Path(folder) / "check.db"
            with sqlite3.connect(path) as database:
                database.execute("create table runtime (value integer)")
                database.execute("insert into runtime values (42)")
            with sqlite3.connect(path) as database:
                assert database.execute("select value from runtime").fetchone() == (42,)
        report["checks"].append({"name": stage, "passed": True})

        stage = "Local HTTP"
        from flask import Flask
        from werkzeug.serving import make_server
        import requests
        app = Flask("gm-engine-check")
        app.add_url_rule("/runtime", view_func=lambda: {"ok": True})
        server = make_server("127.0.0.1", 0, app)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            assert requests.get(f"http://127.0.0.1:{server.server_port}/runtime", timeout=3).json() == {"ok": True}
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)
        report["checks"].append({"name": stage, "passed": True})
        report["status"] = "passed"
    except Exception as error:
        report.update(status="failed", stage=stage, exception_type=type(error).__name__)
        missing = getattr(error, "name", None)
        if isinstance(missing, str) and all(c.isalnum() or c in "_." for c in missing):
            report["missing_module"] = missing
    return json.dumps(report)
