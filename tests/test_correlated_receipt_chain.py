import base64, hashlib, json, sqlite3
import attestpipe.bus as bus
import evidence.index as idxmod
import evidence.warehouse as whmod
import plane_service.server as api
import plane_service.executor as executor_module
import plane_service.crypto_sign as crypto_sign
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from evidence.index import EvidenceIndex
from evidence.warehouse import EvidenceWarehouse
from plane_service.crypto_sign import verify_sig

class Bus:
    def __init__(self, index): self.index = index
    def publish(self, event): return self.index.ingest(event)

def test_correlated_capability_receipt_and_durable_chain(tmp_path, monkeypatch):
    index = EvidenceIndex(tmp_path / "index.json")
    warehouse = EvidenceWarehouse(tmp_path / "chain.sqlite")
    monkeypatch.setattr(idxmod, "get_index", lambda: index)
    monkeypatch.setattr(whmod, "get_warehouse", lambda: warehouse)
    monkeypatch.setattr(bus, "BUS", Bus(index))
    corr = "integration-run-0001"
    right = {"type": "read", "resource": "demo", "method": "GET"}
    issued = api.handle_issue({"correlation_id": corr, "rights": [right], "ttl_seconds": 60})
    assert issued["status"] == "ok" and issued["correlation_id"] == corr
    cap = issued["capability"]
    result = api.handle_execute({"correlation_id": corr, "capability": cap,
        "signature": issued["signature"], "required": right, "caller": cap["audience"]})
    assert result["status"] == "authorized"
    assert result["result"] == "not_executed"
    receipt = result["receipt"]
    assert receipt["correlation_id"] == corr
    assert receipt["outcome"] == "authorized_not_executed"
    signature = receipt.pop("signature")
    assert verify_sig(receipt, signature)
    receipt["signature"] = signature
    assert warehouse.verify_chain()["ok"]
    assert warehouse.verify_chain()["length"] == 2
    replay = api.handle_execute({"correlation_id": corr, "capability": cap,
        "signature": issued["signature"], "required": right, "caller": cap["audience"]})
    assert replay["idempotent_replay"] is True
    assert replay["receipt"] == receipt
    assert warehouse.verify_chain()["length"] == 2
    conflict = api.handle_execute({"correlation_id": corr, "capability": cap,
        "signature": issued["signature"],
        "required": {"type": "read", "resource": "demo", "method": "POST"},
        "caller": cap["audience"]})
    assert conflict["error"] == "correlation_id_replay_conflict"

def test_allowlisted_artifact_dispatch_has_signed_side_effect(tmp_path, monkeypatch):
    # Deterministic test signer; verification below uses a separately pinned
    # public-key constant rather than the service's verify_sig helper.
    fixture_private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    monkeypatch.setattr(crypto_sign, "_KEY", fixture_private)
    monkeypatch.setattr(crypto_sign, "_PUB", fixture_private.public_key())
    pinned_public_key_b64 = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="
    pinned_public_key = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(pinned_public_key_b64)
    )
    index = EvidenceIndex(tmp_path / "index.json")
    warehouse = EvidenceWarehouse(tmp_path / "chain.sqlite")
    monkeypatch.setattr(idxmod, "get_index", lambda: index)
    monkeypatch.setattr(whmod, "get_warehouse", lambda: warehouse)
    monkeypatch.setattr(bus, "BUS", Bus(index))
    monkeypatch.setattr(executor_module, "ROOT", tmp_path)
    monkeypatch.setattr(executor_module, "ARTIFACT_DIR", tmp_path / "dispatcher")

    corr = "artifact-write-e2e-001"
    right = {"type": "Execute", "resource": "artifact.write_demo", "method": "POST"}
    issued = api.handle_issue({
        "correlation_id": corr,
        "rights": [right],
        "ttl_seconds": 60,
    })
    assert issued["status"] == "ok"
    cap = issued["capability"]
    request = {
        "correlation_id": corr,
        "capability": cap,
        "signature": issued["signature"],
        "required": right,
        "input": {"content": "AVRONE verified artifact payload"},
        "caller": cap["audience"],
    }
    result = api.handle_execute(request)
    assert result["status"] == "executed"
    assert result["execution_status"] == "SUCCEEDED"
    assert result["idempotent_replay"] is False

    receipt = result["receipt"]
    assert receipt["outcome"] == "succeeded"
    assert receipt["action"] == "Execute:artifact.write_demo:POST"
    signature = receipt.pop("signature")
    pinned_public_key.verify(base64.b64decode(signature), crypto_sign.canonical(receipt))
    receipt["signature"] = signature

    artifact_path = tmp_path / "dispatcher" / f"{corr}.json"
    artifact = json.loads(artifact_path.read_text())
    assert artifact["schema"] == "avrone.execution-artifact/v1"
    assert artifact["payload"] == "AVRONE verified artifact payload"
    assert artifact["receipt"] == receipt
    assert receipt["result_digest"] == "sha256:" + hashlib.sha256(
        artifact["payload"].encode("utf-8")
    ).hexdigest()

    rows = index.query(correlation_id=corr, message_type="AuthorizationReceipt")
    assert len(rows) == 1
    assert rows[0]["receipt"] == receipt
    assert rows[0]["result"] == result["result"]
    assert warehouse.verify_chain()["ok"] is True
    assert warehouse.verify_chain()["length"] == 2

    # Independently recompute the persisted SQLite chain without calling
    # EvidenceWarehouse.verify_chain(), and bind its receipt event to the
    # independently verified artifact receipt above.
    with sqlite3.connect(str(warehouse.db_path)) as connection:
        persisted = connection.execute(
            "SELECT payload, prev_digest, digest FROM evidence ORDER BY id"
        ).fetchall()
    previous = "0" * 64
    independently_verified_events = []
    for payload_json, stored_previous, stored_digest in persisted:
        event = json.loads(payload_json)
        canonical_event = json.dumps(
            event, sort_keys=True, separators=(",", ":"), default=str
        ).encode("utf-8")
        expected_digest = hashlib.sha256(
            previous.encode("utf-8") + canonical_event
        ).hexdigest()
        assert stored_previous == previous
        assert stored_digest == expected_digest
        independently_verified_events.append(event)
        previous = expected_digest

    receipt_events = [
        event for event in independently_verified_events
        if event.get("correlation_id") == corr
        and event.get("message_type") == "AuthorizationReceipt"
    ]
    assert len(receipt_events) == 1
    assert receipt_events[0]["receipt"] == receipt

    replay = api.handle_execute(request)
    assert replay["status"] == "executed"
    assert replay["idempotent_replay"] is True
    assert replay["receipt"] == receipt
    assert warehouse.verify_chain()["length"] == 2

    conflicting = dict(request)
    conflicting["input"] = {"content": "different bytes"}
    rejected = api.handle_execute(conflicting)
    assert rejected["status"] == "error"
    assert rejected["error"] == "correlation_id_replay_conflict"
    assert warehouse.verify_chain()["length"] == 2
