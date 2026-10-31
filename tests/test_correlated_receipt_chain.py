import hashlib, json
import attestpipe.bus as bus
import evidence.index as idxmod
import evidence.warehouse as whmod
import plane_service.server as api
import plane_service.executor as executor_module
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
    assert verify_sig(receipt, signature)
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
