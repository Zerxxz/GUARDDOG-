"""Sentinel read API (T10 companion): verdicts + blocklist over FastAPI.

GET /verdicts          — recent verdicts (proxies the registry `latest`)
GET /is_blocked?chain=&addr= — live blocklist check with a 30s cache
GET /stats             — registry stats
GET /health            — liveness
"""

from __future__ import annotations

import os
import time

from fastapi import FastAPI, HTTPException, Query

REGISTRY = os.getenv("SENTINEL_REGISTRY_CONTRACT", "guarddog-sentinel.testnet")
NEAR_RPC = os.getenv("NEAR_RPC", "https://rpc.testnet.near.org")

app = FastAPI(title="GUARDDOG Sentinel API", version="0.1.0")
_cache: dict[str, tuple[float, object]] = {}


def _view(method: str, args: dict, ttl: float = 30.0):
    key = f"{method}:{sorted(args.items())}"
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    import base64
    import json
    import urllib.request

    args_b64 = base64.b64encode(json.dumps(args).encode()).decode()
    req = urllib.request.Request(
        NEAR_RPC,
        data=json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "query",
            "params": {"request_type": "call_function", "account_id": REGISTRY,
                       "method_name": method, "args_base64": args_b64,
                       "finality": "final"},
        }).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        resp = json.loads(urllib.request.urlopen(req, timeout=15).read())
        r = resp["result"]
        if "error" in r:
            raise RuntimeError(r["error"][:200])
        val = json.loads(bytes(r["result"]).decode() or "null")
        _cache[key] = (time.time(), val)
        return val
    except RuntimeError:
        raise
    except Exception as e:
        raise HTTPException(502, f"registry read failed: {str(e)[:200]}")


@app.get("/health")
def health():
    return {"ok": True, "registry": REGISTRY}


@app.get("/stats")
def stats():
    return _view("stats", {})


@app.get("/verdicts")
def verdicts(limit: int = Query(default=10, ge=1, le=100)):
    return _view("latest", {"limit": limit})


@app.get("/is_blocked")
def is_blocked(chain: str = Query(...), addr: str = Query(...)):
    return {"chain": chain, "addr": addr, "blocked": _view(
        "is_blocked", {"chain": chain, "addr": addr})}
