"""T12 — Fake RPC bait endpoint.

A FastAPI service that looks like a permissive Base Sepolia node. Rogue agents
(hooked on the bait RPC via X announce / config poison) point their Web3 at
us; we log EVERY call and serve responses that encourage the drain MO:

  - eth_sendRawTransaction → actually broadcast to the REAL testnet node
    (the tx must land for the trap listener to catch the contact) while
    logging the raw payload
  - eth_estimateGas / eth_call / eth_getTransactionCount → honest passthrough
    (a lying node breaks the drainer's tx and the loop dies)
  - everything else → plausible static responses

Every request is recorded to SQLite (bait_requests table) with method, params
digest, caller IP and user-agent — that's the second capture surface.
"""

from __future__ import annotations

import json
import os
import time

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

import httpx

from . import db as event_db

BAIT_CHAIN_ID = int(os.getenv("BAIT_CHAIN_ID", "84532"))  # Base Sepolia
REAL_RPC = os.getenv("BASE_SEPOLIA_RPC", "https://sepolia.base.org")

app = FastAPI(title="Base Sepolia Node", version="1.0.0", docs_url=None, redoc_url=None)

PASSTHROUGH = {
    "eth_chainId", "net_version", "eth_blockNumber", "eth_getBalance",
    "eth_getTransactionCount", "eth_getTransactionReceipt", "eth_getTransactionByHash",
    "eth_call", "eth_estimateGas", "eth_gasPrice", "eth_getBlockByNumber",
    "eth_getLogs", "eth_getCode",
}


@app.post("/")
@app.post("/rpc")
async def rpc(request: Request, response: Response):
    body = await request.body()
    try:
        payload = json.loads(body or b"{}")
    except json.JSONDecodeError:
        return JSONResponse({"jsonrpc": "2.0", "error": {"code": -32700, "message": "parse error"}}, status_code=400)

    method = payload.get("method", "?")
    params = payload.get("params", [])
    req_id = payload.get("id", 1)

    _log_bait(request, method, params)

    if method == "eth_sendRawTransaction":
        raw = params[0] if params else ""
        return await _send_raw(raw, req_id)

    if method in PASSTHROUGH:
        return await _passthrough(payload, req_id)

    # everything else: plausible generic success shapes that keep bots going
    if method == "eth_accounts":
        return _ok(req_id, [])
    if method == "eth_maxPriorityFeePerGas":
        return _ok(req_id, "0x3b9aca00")
    if method == "eth_syncing":
        return _ok(req_id, False)
    return _ok(req_id, None)


def _ok(req_id, result) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _log_bait(request: Request, method: str, params) -> None:
    """Record the contact — second capture surface beside on-chain traps."""
    try:
        event_db.record_bait_request(
            ts=time.time(),
            caller_ip=request.client.host if request.client else "?",
            user_agent=request.headers.get("user-agent", "")[:200],
            method=method,
            params_digest=json.dumps(params, default=str)[:1000],
        )
    except Exception:
        pass  # bait must never 500 because of logging


async def _passthrough(payload: dict, req_id) -> JSONResponse:
    async with httpx.AsyncClient(timeout=20) as client:
        try:
            r = await client.post(REAL_RPC, json=payload)
            return JSONResponse(r.json(), status_code=r.status_code)
        except Exception:
            return JSONResponse(
                {"jsonrpc": "2.0", "id": req_id,
                 "error": {"code": -32000, "message": "upstream unavailable"}}, status_code=502)


async def _send_raw(raw_tx: str, req_id) -> JSONResponse:
    """Broadcast the drainer's tx to the REAL testnet and let the trap listen."""
    if not raw_tx:
        return JSONResponse(_err(req_id, -32602, "missing raw tx"), status_code=400)
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            r = await client.post(REAL_RPC, json={
                "jsonrpc": "2.0", "id": req_id, "method": "eth_sendRawTransaction",
                "params": [raw_tx],
            })
            data = r.json()
            # keep the bait's JSON-RPC shape; the tx actually lands on-chain
            return JSONResponse(data, status_code=r.status_code)
        except Exception:
            return JSONResponse(_err(req_id, -32000, "broadcast failed"), status_code=502)


def _err(req_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}
