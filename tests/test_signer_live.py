"""Golden tests for Leash derivation — verified against the LIVE MPC contract.

The MPC network itself (v1.signer-prod.testnet) exposes `derived_public_key`
view; the EVM address of that key (keccak256(x||y)[-20:]) must equal what our
pure-python derivation produces. Requires network; marked integration.
"""

import base64
import json
import urllib.request

import pytest

from leash.signer import derived_address
from sentinel.mpc import MPC_CONTRACT

pytestmark = pytest.mark.integration


def _rpc(method, params):
    req = urllib.request.Request(
        "https://rpc.testnet.near.org",
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json"},
    )
    return json.loads(urllib.request.urlopen(req, timeout=30).read())


def _live_address(account: str, path: str) -> str:
    from base58 import b58decode
    from Crypto.Hash import keccak

    r = _rpc("query", {
        "request_type": "call_function", "account_id": MPC_CONTRACT,
        "method_name": "derived_public_key",
        "args_base64": base64.b64encode(
            json.dumps({"path": path, "predecessor": account}).encode()).decode(),
        "finality": "final",
    })
    raw = bytes(r["result"]["result"]).decode().strip('"')
    payload = b58decode(raw.split(":", 1)[1])[-64:]
    k = keccak.new(digest_bits=256)
    k.update(payload)
    return "0x" + k.digest()[-20:].hex()


def test_derivation_matches_live_mpc_network():
    for acct, path in [
        ("guarddog-sentinel.testnet", "leash-base-1"),
        ("example.near", "ethereum-1"),
        ("example.near", "ethereum-2"),
    ]:
        assert derived_address(acct, path) == _live_address(acct, path), (acct, path)
