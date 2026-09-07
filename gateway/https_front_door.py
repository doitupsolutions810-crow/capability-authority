#!/usr/bin/env python3
"""TLS terminator. Path allowlist only — frozen OpenAPI."""
from __future__ import annotations
import json, os, ssl, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

UPSTREAM = os.environ.get("PLANE_UPSTREAM", "http://127.0.0.1:8090")
ALLOWED = {
    "/health",
    "/v1/capabilities/issue",
    "/v1/capabilities/attenuate",
    "/v1/capabilities/verify",
    "/v1/execute",
    "/v1/evidence",
    "/v1/identity",
}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("[front-door]", self.command, self.path)
    def do_GET(self):
        self._proxy()
    def do_POST(self):
        self._proxy()
    def _proxy(self):
        path = urlparse(self.path).path
        if path not in ALLOWED:
            return self._json(404, {"status": "error", "error": "path not allowed"})
        n = int(self.headers.get("Content-Length") or 0)
        data = self.rfile.read(n) if n else None
        req = urllib.request.Request(UPSTREAM + self.path, data=data, method=self.command)
        if data is not None:
            req.add_header("Content-Type", self.headers.get("Content-Type", "application/json"))
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                body = r.read()
                self.send_response(r.status)
                self.send_header("Content-Type", r.headers.get("Content-Type", "application/json"))
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        except Exception as e:
            self._json(502, {"status": "error", "error": str(e)})
    def _json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

def main():
    host = os.environ.get("FRONT_DOOR_HOST", "127.0.0.1")
    port = int(os.environ.get("FRONT_DOOR_PORT", "8443"))
    httpd = HTTPServer((host, port), Handler)
    cert = os.environ.get("FRONT_DOOR_CERT")
    key = os.environ.get("FRONT_DOOR_KEY")
    if os.environ.get("FRONT_DOOR_TLS", "0") == "1" and cert and key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        print(f"front-door https://{host}:{port} -> {UPSTREAM}")
    else:
        print(f"front-door http://{host}:{port} -> {UPSTREAM} (TLS off)")
    httpd.serve_forever()

if __name__ == "__main__":
    main()
