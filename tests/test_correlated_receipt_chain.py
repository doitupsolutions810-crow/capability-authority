import hashlib, json
import attestpipe.bus as bus
import evidence.index as idxmod
import evidence.warehouse as whmod
import plane_service.server as api
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
