def isolation_plan(provider_request_id, namespace, deployment, mode):
    net = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": f"isolate-{deployment}", "namespace": namespace},
        "spec": {"podSelector": {"matchLabels": {"app": deployment}}, "policyTypes": ["Ingress", "Egress"], "ingress": [], "egress": []},
    }
    dep = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": deployment, "namespace": namespace}}
    objects = [net, dep] if mode != "access_only" else [dep]
    return {"provider_request_id": provider_request_id, "mode": mode, "namespace": namespace, "objects": objects}
