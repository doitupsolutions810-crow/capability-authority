"""Minimal operator dashboard: health + intent POST to plane."""
from flask import Flask, jsonify, request
import json, os, urllib.request

app = Flask(__name__)
PLANE = os.environ.get("PLANE_URL", "http://127.0.0.1:8090")

@app.get("/health")
def health():
    try:
        with urllib.request.urlopen(PLANE + "/health", timeout=2) as r:
            plane = json.loads(r.read().decode())
    except Exception as e:
        plane = {"status": "down", "error": str(e)}
    return jsonify({"dashboard": "ok", "plane": plane})

@app.post("/api/intent")
def intent():
    body = request.get_json(force=True, silent=True) or {}
    data = json.dumps(body).encode()
    req = urllib.request.Request(PLANE + "/v1/capabilities/issue", data=data, headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return jsonify(json.loads(r.read().decode()))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("DASHBOARD_PORT", "8088")))
