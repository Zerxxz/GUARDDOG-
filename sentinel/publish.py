"""Publish verdicts to the NEAR Sentinel Registry (T5).

Two paths, matching the contract's access-control design (registry/src/lib.rs):

1. **owner fallback** (default for the demo): direct owner transaction —
   signer == predecessor == owner — calling ``publish_verdict(verdict, null)``.
2. **MPC-anchored** (production): request a Chain Signatures signature from
   the MPC contract for sha256(canonical payload) with derivation path
   ``guarddog-v1``, then publish ``publish_verdict(verdict, proof)``. The
   registry re-derives the key for (predecessor, path) and recovers the
   signer from (big_r, s, recovery_id).

All NEAR interactions go through near-cli-rs (near-api-py is dead upstream).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time

NEAR_CLI = os.environ.get("NEAR_CLI", os.path.expanduser("~/.local/bin/near"))
KEYFILE = os.getenv("NEAR_KEYFILE", os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "keys", "near.json"))
NETWORK = "testnet"
MPC_CONTRACT = os.getenv("MPC_CONTRACT", "v1.signer-prod.testnet")
DERIVATION_PATH = "guarddog-v1"

REGISTRY = os.getenv("SENTINEL_REGISTRY_CONTRACT", "guarddog-sentinel.testnet")


def _private_key() -> str:
    with open(KEYFILE) as f:
        return json.load(f)["private_key"]


def account_id() -> str:
    with open(KEYFILE) as f:
        return json.load(f)["account_id"]


def expected_payload(verdict: dict) -> str:
    """sha256 of the canonical payload — must match the contract byte-for-byte:
    id 0 chain 0 attacker 0 selector 0 pattern_hash 0 confidence evidence_tx timestamp_be."""
    b = b""
    for field in ("id", "chain", "attacker", "selector", "pattern_hash"):
        b += verdict[field].encode() + b"\x00"
    b += bytes([int(verdict["confidence"])])
    b += verdict["evidence_tx"].encode()
    b += int(verdict["timestamp"]).to_bytes(8, "big")
    return hashlib.sha256(b).hexdigest()


def _near(args: list[str], timeout: int = 90) -> str:
    proc = subprocess.run([NEAR_CLI, *args], capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"near cli failed: {proc.stderr.strip()[:400]}")
    return proc.stdout


def publish_owner(verdict: dict) -> dict:
    """Owner-fallback publish: direct owner transaction, signature=null."""
    args = json.dumps({"verdict": verdict, "signature": None}, separators=(",", ":"))
    out = _near([
        "contract", "call-function", "as-transaction", REGISTRY, "publish_verdict",
        "json-args", args, "prepaid-gas", "50 Tgas", "attached-deposit", "0 NEAR",
        "sign-as", account_id(), "network-config", NETWORK,
        "sign-with-plaintext-private-key", _private_key(), "save-to-file",
        "/tmp/guarddog-signed-tx.json",
    ])
    with open("/tmp/guarddog-signed-tx.json") as f:
        b64 = json.load(f)["signed_transaction_as_base64"]
    return _broadcast(b64)


def publish_mpc(verdict: dict, sign_timeout_s: int = 240) -> dict:
    """MPC-anchored publish: request a Chain Signatures signature over the
    payload hash, then submit it with the verdict.

    The near-cli-rs `sign-with-mpc` path drives the whole MPC flow from the
    CLI; the signature lands in the transaction outcome logs of the `sign`
    call on the MPC contract. We parse big_r / s / recovery_id from there.
    """
    payload_hash = expected_payload(verdict)
    raise NotImplementedError(
        "MPC sign-and-relay pipeline lands in the next iteration; owner fallback "
        f"is the active demo path (payload_hash={payload_hash})"
    )


def _broadcast(signed_tx_b64: str) -> dict:
    """Send a signed tx via RPC broadcast_tx_commit and summarize the outcome."""
    import base64
    import urllib.request

    req = urllib.request.Request(
        "https://rpc.testnet.near.org",
        data=json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "broadcast_tx_commit",
            "params": {"signed_tx_base64": signed_tx_b64},
        }).encode(),
        headers={"Content-Type": "application/json"},
    )
    resp = json.loads(urllib.request.urlopen(req, timeout=90).read())
    if "error" in resp:
        raise RuntimeError(resp["error"].get("message", "?")[:300])
    result = resp["result"]
    tx_hash = result.get("transaction", {}).get("hash")
    out: dict = {"tx_hash": tx_hash}
    for st in result.get("receipts_outcome", []):
        status = st.get("outcome", {}).get("status", {})
        if "Failure" in status:
            raise RuntimeError(f"tx {tx_hash} failed: {json.dumps(status)[:400]}")
        if "SuccessValue" in status and status["SuccessValue"]:
            out["result"] = json.loads(base64.b64decode(status["SuccessValue"]))
    return out


def view(method: str, args: dict | None = None) -> object:
    """Query a view method on the registry via RPC (no tx)."""
    import base64
    import urllib.request

    args_b64 = base64.b64encode(json.dumps(args or {}).encode()).decode()
    req = urllib.request.Request(
        "https://rpc.testnet.near.org",
        data=json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "query",
            "params": {"request_type": "call_function", "account_id": REGISTRY,
                       "method_name": method, "args_base64": args_b64,
                       "finality": "final"},
        }).encode(),
        headers={"Content-Type": "application/json"},
    )
    resp = json.loads(urllib.request.urlopen(req, timeout=30).read())
    r = resp.get("result", {})
    if "error" in r:
        raise RuntimeError(r["error"][:200])
    return json.loads(bytes(r["result"]).decode() or "null")


def verdict_from_capture(capture: dict) -> dict:
    """Shape a contract-ready verdict out of a sentinel capture row."""
    return {
        "id": f"cap-{capture['id']}",
        "chain": capture["chain"],
        "attacker": capture["attacker_addr"],
        "selector": capture["selector"] or "",
        "pattern_hash": capture["pattern_hash"],
        "confidence": int(round(float(capture["confidence"]) * 100)),
        "evidence_tx": capture["tx_hash"],
        "timestamp": str(int(time.time() * 1e9)),
    }


def publish_capture(capture_id: int) -> dict:
    """Fetch a capture from the local DB, publish its verdict, record the tx."""
    from . import db

    caps = {c["id"]: c for c in db.list_captures(limit=100)}
    cap = caps.get(capture_id)
    if not cap:
        raise KeyError(f"capture #{capture_id} not found")
    verdict = verdict_from_capture(cap)
    res = publish_owner(verdict)
    with db.connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO verdicts (id, ts, capture_id, near_tx_hash) VALUES (?,?,?,?)",
            (verdict["id"], time.time(), cap["id"], res["tx_hash"]),
        )
    return {"verdict": verdict, "near": res}
