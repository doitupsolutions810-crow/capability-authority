import json
import threading
from http.server import HTTPServer

import httpx
import pytest

from plane_service.server import Handler


@pytest.fixture
def authority_http():
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_rejects_post_body_over_64k_before_json_parse(authority_http):
    response = httpx.post(authority_http + "/v1/capabilities/delegate", content=b"x" * 65537, headers={"content-type": "application/json"})
    assert response.status_code == 413
    assert "64 KiB" in response.json()["error"]


def test_rejects_malformed_json_and_non_object_body(authority_http):
    malformed = httpx.post(authority_http + "/v1/capabilities/delegate", content=b"{bad", headers={"content-type": "application/json"})
    array = httpx.post(authority_http + "/v1/capabilities/delegate", content=b"[]", headers={"content-type": "application/json"})
    assert malformed.status_code == 400
    assert array.status_code == 400
    assert "JSON object" in array.json()["error"]


def test_unknown_post_route_returns_404_without_parsing_body(authority_http):
    response = httpx.post(authority_http + "/not-a-route", content=b"not json")
    assert response.status_code == 404
