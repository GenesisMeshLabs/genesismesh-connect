"""Isolated native Genesis Mesh service for Connect's live integration test.

Runs the actual authority routes. Operator keys stay in this process; only
public pins and one-use invites cross the local test control pipe. No changes
are made to an existing authority, its state, or the sibling repository.
"""
import json
import logging
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import request
from werkzeug.serving import make_server, WSGIRequestHandler
from genesis_mesh.crypto import generate_keypair, sign_model
from genesis_mesh.crypto.admin_auth import sign_admin_request
from genesis_mesh.models.genesis import GenesisBlock, NetworkAuthority, PolicyManifestRef
from genesis_mesh.na_service.server import NetworkAuthorityService


class QuietHandler(WSGIRequestHandler):
    def log_request(self, code="-", size="-"):
        pass


def main():
    logging.disable(logging.CRITICAL)
    root, authority, operator = (generate_keypair() for _ in range(3))
    now = datetime.now(timezone.utc)
    genesis = GenesisBlock(
        network_name="CONNECT-LIVE-TEST", network_version="v1",
        root_public_key=root.public_key_b64,
        network_authority=NetworkAuthority(public_key=authority.public_key_b64,
            valid_from=now, valid_to=now + timedelta(days=1)),
        policy_manifest=PolicyManifestRef(hash="sha256:connect-integration", url=None),
    )
    genesis.signatures.append(sign_model(genesis, root.private_key, "root"))
    service = NetworkAuthorityService(
        genesis_block=genesis, na_private_key=authority.private_key, key_id="connect-test-na",
        operator_public_keys={"fixture-operator": operator.public_key_b64},
        operator_key_tiers={"fixture-operator": "privileged"},
        boundary_policy_enforcement="required", evidence_store="on", evidence_out_of_band="on", db_path=":memory:",
    )
    paused_reads = {"marker": None, "release": threading.Event()}

    @service.app.before_request
    def pause_read_decision():
        # Test-only rendezvous: stop before authorization, never inside core.
        marker = paused_reads["marker"]
        if request.path == "/node/boundary/evaluate" and marker is not None:
            Path(marker).write_text("waiting", encoding="utf-8")
            if not paused_reads["release"].wait(timeout=5):
                return {"error": "fixture_pause_timeout"}, 503

    server = make_server("127.0.0.1", 0, service.app, request_handler=QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def reply(data):
        print(json.dumps(data), flush=True)

    def admin(path, body):
        headers = sign_admin_request(operator.private_key, "fixture-operator", method="POST",
            path=path, audience=authority.public_key_b64, body=body)
        with service.app.test_client() as client:
            response = client.post(path, json=body, headers=headers)
            if response.status_code not in (200, 201):
                raise RuntimeError(f"Fixture admin operation refused: {response.status_code}")
            return response.get_json()

    reply({"url": f"http://127.0.0.1:{server.server_port}", "pin": {
        "root_public_key": root.public_key_b64, "network_name": genesis.network_name}})
    try:
        for line in sys.stdin:
            command = json.loads(line)
            if command["op"] == "invite":
                result = admin("/admin/invite", {"roles": ["role:client"],
                    "max_validity_hours": 24, "token_expiry_hours": 1,
                    "recipient_public_key": command["node_public_key"]})
                reply({"invite": result["token_id"]})
            elif command["op"] == "edge_invite":
                result = admin("/admin/invite", {"roles": ["role:client"], "max_validity_hours":24,
                    "recipient_public_key":command["node_public_key"], "node_sovereign_id":"connect-host",
                    "executor_resource_prefix":"connect:host/"})
                reply({"invite":result["token_id"]})
            elif command["op"] in ("read_policy", "deny_reads", "allow_reads", "list_policy", "deny_list"):
                capabilities = ["connect.collection.read", "connect.collection.list"] if command["op"] in ("list_policy", "deny_list") else ["connect.collection.read"]
                gates = [{"gate_id":"collection", "gate_type":"allowlist.v1", "order":0,
                    "config":{"path":"request_parameters.collection_id", "values":[command.get("collection", "denied")] }},
                    {"gate_id":"peer", "gate_type":"allowlist.v1", "order":1,
                    "config":{"path":"request_parameters.peer_node", "values":[command["peer_node"]]}},
                    {"gate_id":"size", "gate_type":"max_value.v1", "order":2,
                    "config":{"path":"request_parameters.size", "max":command.get("max_size",65536)}}]
                result = admin("/admin/boundary-policies", {"policy_id":"connect-read", "valid_from":now.isoformat(),
                    "valid_until":(now+timedelta(days=1)).isoformat(),
                    "selector":{"capabilities":capabilities}, "gates":gates})
                admin("/admin/boundary-policies/connect-read/activate", {"version":result["version"]})
                if command["op"] in ("read_policy", "list_policy"):
                    attestation = admin("/admin/attestations", {"subject_id":"connect-host", "subject_public_key":command["host_node"],
                        "roles":["role:client"], "claims":{"capabilities":capabilities}})
                    reply({"attestation_id":attestation["attestation_id"], "policy_id":"connect-read"})
                else:
                    reply({"denied":True})
            elif command["op"] == "revoke_attestation":
                admin(f"/admin/attestations/{command['attestation_id']}/revoke", {"reason":"test"})
                reply({"revoked":True})
            elif command["op"] == "pause_reads":
                paused_reads["release"].clear()
                paused_reads["marker"] = command["marker"]
                reply({"paused": True})
            elif command["op"] == "resume_reads":
                paused_reads["marker"] = None
                paused_reads["release"].set()
                reply({"resumed": True})
            elif command["op"] == "revoke":
                admin("/admin/revoke", {"cert_id": command["cert_id"], "reason": "key_compromise"})
                reply({"revoked": True})
            elif command["op"] == "stop":
                reply({"stopped": True})
                break
            else:
                raise ValueError("Unsupported fixture command")
    finally:
        paused_reads["release"].set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
