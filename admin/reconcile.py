"""Treat provider timeout as unknown. Reconcile by provider_request_id, never invent success."""

def classify(outcome):
    if outcome.get("status") in ("ok", "applied", "applied-lab"):
        return "succeeded"
    if outcome.get("status") in ("denied", "error"):
        return "failed"
    if outcome.get("status") == "timeout":
        return "unknown"
    return "unknown"

def next_action(state):
    if state == "unknown":
        return "lookup_provider_request_id"
    if state == "failed":
        return "do_not_retry_new_id"
    return "record_and_stop"
