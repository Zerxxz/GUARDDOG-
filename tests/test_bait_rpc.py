"""T12 unit tests — bait RPC routing logic (offline, no server)."""

import pytest
from fastapi.testclient import TestClient

from sentinel import bait_rpc, db


@pytest.fixture()
def client(monkeypatch):
    # don't hit the real node in unit tests
    async def fake_passthrough(payload, req_id):
        return bait_rpc._ok(req_id, "0xdeadbeef")

    async def fake_send_raw(raw, req_id):
        return bait_rpc._ok(req_id, "0xbroadcast")

    monkeypatch.setattr(bait_rpc, "_passthrough", fake_passthrough)
    monkeypatch.setattr(bait_rpc, "_send_raw", fake_send_raw)
    db.init_db()
    return TestClient(bait_rpc.app)


def test_bait_request_is_logged(client):
    r = client.post("/", json={"jsonrpc": "2.0", "id": 7, "method": "eth_gasPrice", "params": []})
    assert r.status_code == 200
    rows = db.list_bait_requests(limit=5)
    assert rows, "expected at least one bait request row"
    assert any(row["method"] == "eth_gasPrice" for row in rows)


def test_sendraw_is_routed_and_logged(client):
    r = client.post("/", json={
        "jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction",
        "params": ["0x02f86c..."]})
    body = r.json()
    assert body["result"] == "0xbroadcast"
    rows = db.list_bait_requests(limit=5)
    assert rows[0]["method"] == "eth_sendRawTransaction"


def test_unknown_method_gets_plausible_response(client):
    r = client.post("/", json={"jsonrpc": "2.0", "id": 2, "method": "eth_syncing", "params": []})
    assert r.json() == {"jsonrpc": "2.0", "id": 2, "result": False}


def test_passthrough_method_uses_upstream_shape(client):
    r = client.post("/rpc", json={"jsonrpc": "2.0", "id": 3, "method": "eth_chainId", "params": []})
    # fake passthrough returns "0xdeadbeef" as the result
    assert r.json()["result"] == "0xdeadbeef"
