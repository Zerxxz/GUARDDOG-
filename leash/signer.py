"""Leash signing path (T8): intent → guard check → MPC sign → broadcast.

Signing is delegated to Chain Signatures: the *guard never holds the EVM
key*. The key material for the derived address lives only inside the MPC
network; what we hold is the NEAR account key that authorizes `sign`
requests. Deny = tx is never signed, on any chain.

E2E testnet path (Base Sepolia):
  1. derive (account, path) → expected EVM address
  2. guard.check(chain, to, value) → deny = raise, nothing signed
  3. build the EVM tx, request MPC signature over its signer hash
  4. assemble the signed tx with (big_r, s, recovery_id) → broadcast
"""

from __future__ import annotations

import json
import os
import time

from eth_utils import keccak
from web3 import Web3

from .guard import Decision, Guard

# the derived address of (registry account, LEASH_PATH) on Base Sepolia
LEASH_PATH = os.getenv("LEASH_DERIVATION_PATH", "leash-base-1")
CHAIN = "base-sepolia"

NEAR_CLI = os.environ.get("NEAR_CLI", os.path.expanduser("~/.local/bin/near"))
KEYFILE = os.getenv("NEAR_KEYFILE", os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "keys", "near.json"))
MPC_CONTRACT = os.getenv("MPC_CONTRACT", "v1.signer-prod.testnet")
NEAR_RPC = os.getenv("NEAR_RPC", "https://rpc.testnet.near.org")
BASE_SEPOLIA_RPC = os.getenv("BASE_SEPOLIA_RPC", "https://sepolia.base.org")
SIGN_GAS = "300 Tgas"


class DenyError(Exception):
    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(f"LEASH DENY [{decision.rule}]: {decision.reason}")


# --------------------------------------------------------------- derivation --

def derived_address(near_account: str, path: str = LEASH_PATH, mpc_key: str | None = None) -> str:
    """EVM address the MPC network controls for (near_account, path).

    epsilon = sha3_256("near-mpc-recovery v0.1.0 epsilon derivation:{account},{path}")
    derived_pubkey = P_mpc + epsilon*G (secp256k1)
    address = last 20 bytes of keccak256(x||y)

    Golden-tested against the LIVE MPC network's own `derived_public_key`
    view (tests/test_signer_live.py).
    """
    from Crypto.Hash import keccak as _keccak
    from hashlib import sha3_256 as _sha3  # stdlib sha3 == NIST sha3-256

    from sentinel.mpc import MPC_PUBLIC_KEY

    mpc_key = mpc_key or MPC_PUBLIC_KEY

    prefix = "near-mpc-recovery v0.1.0 epsilon derivation:"
    eps = int.from_bytes(_sha3(f"{prefix}{near_account},{path}".encode()).digest(), "big")

    # mpc_key: "secp256k1:" + base58(x||y)
    from base58 import b58decode

    raw = b58decode(mpc_key.split(":", 1)[1])
    assert len(raw) == 64, "expected 64-byte x||y"

    P_X = int.from_bytes(raw[:32], "big")
    P_Y = int.from_bytes(raw[32:], "big")
    G = (
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    )
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

    def add(P1, P2):
        if P1 is None:
            return P2
        if P2 is None:
            return P1
        if P1[0] == P2[0] and (P1[1] + P2[1]) % p == 0:
            return None
        if P1 == P2:
            lam = (3 * P1[0] * P1[0]) * pow(2 * P1[1], p - 2, p) % p
        else:
            lam = (P2[1] - P1[1]) * pow(P2[0] - P1[0], p - 2, p) % p
        x = (lam * lam - P1[0] - P2[0]) % p
        y = (lam * (P1[0] - x) - P1[1]) % p
        return (x, y)

    def mul(k, Pt):
        R = None
        while k:
            if k & 1:
                R = add(R, Pt)
            Pt = add(Pt, Pt)
            k >>= 1
        return R

    Q = add((P_X, P_Y), mul(eps % N, G))
    assert Q is not None

    pub = bytes.fromhex(f"{Q[0]:064x}{Q[1]:064x}")
    k = _keccak.new(digest_bits=256)
    k.update(pub)
    return "0x" + k.digest()[-20:].hex()


# ------------------------------------------------------------ MPC signing ----

def _load_keyfile() -> dict:
    with open(KEYFILE) as f:
        return json.load(f)


def _near(args: list[str], timeout: int = 120) -> str:
    import subprocess

    proc = subprocess.run([NEAR_CLI, *args], capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"near cli failed: {proc.stderr.strip()[:400]}")
    return proc.stdout


def _broadcast_near(signed_tx_b64: str) -> dict:
    import base64
    import urllib.request

    req = urllib.request.Request(
        NEAR_RPC,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "broadcast_tx_commit",
                         "params": {"signed_tx_base64": signed_tx_b64}}).encode(),
        headers={"Content-Type": "application/json"},
    )
    resp = json.loads(urllib.request.urlopen(req, timeout=120).read())
    if "error" in resp:
        raise RuntimeError(resp["error"].get("message", "?")[:300])
    result = resp["result"]
    out = {"tx_hash": result.get("transaction", {}).get("hash")}
    for st in result.get("receipts_outcome", []):
        status = st.get("outcome", {}).get("status", {})
        if "Failure" in status:
            raise RuntimeError(f"near tx failed: {json.dumps(status)[:400]}")
    return out


def _find_signature_response(request_tx: str, payload32: bytes, path: str,
                             signer: str) -> dict | None:
    """Scan the request tx's receipts for the MPC `respond` outcome carrying
    big_r / s / recovery_id for our payload."""
    import urllib.request

    req = urllib.request.Request(
        NEAR_RPC,
        data=json.dumps({"jsonrpc": "2.0", "id": 1,
                         "method": "EXPERIMENTAL_tx_status",
                         "params": [request_tx, signer]}).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        resp = json.loads(urllib.request.urlopen(req, timeout=30).read())
    except Exception:
        return None
    want = payload32.hex()
    for st in resp.get("result", {}).get("receipts_outcome", []):
        for log in st.get("outcome", {}).get("logs", []):
            if "big_r" not in log:
                continue
            try:
                data = json.loads(log)
            except Exception:
                continue
            sig = data.get("signature") or data
            big_r = (sig.get("big_r") or {}).get("affine_point")
            s = (sig.get("s") or {}).get("scalar")
            rid = sig.get("recovery_id")
            if big_r and s and rid is not None:
                # the respond log echoes the signature for the exact request
                return {"big_r": big_r, "s": s, "recovery_id": int(rid),
                        "request_tx": request_tx}
    return None


def request_mpc_signature(payload32: bytes, path: str = LEASH_PATH,
                          timeout_s: int = 240) -> dict:
    """Request a Chain Signatures signature over `payload32` (32-byte hash).

    Submits `sign` on the MPC contract through near-cli-rs (deposit + the
    yield/resume gas budget). The MPC network usually resolves the request
    inside the same transaction (yield/resume); we re-query the FINAL tx
    outcome for the signature {"big_r","s","recovery_id"}. A log-poll
    fallback covers the async path if the value never lands.
    """
    import base64

    acct = _load_keyfile()["account_id"]
    sk = _load_keyfile()["private_key"]

    args = json.dumps({
        "request": {"key_version": 0, "path": path, "payload": list(payload32)}
    }, separators=(",", ":"))

    _near([
        "contract", "call-function", "as-transaction", MPC_CONTRACT, "sign",
        "json-args", args, "prepaid-gas", SIGN_GAS, "attached-deposit", "1 yoctonear",
        "sign-as", acct, "network-config", "testnet",
        "sign-with-plaintext-private-key", sk, "save-to-file",
        "/tmp/guarddog-mpc-signed.json",
    ])
    with open("/tmp/guarddog-mpc-signed.json") as f:
        b64 = json.load(f)["signed_transaction_as_base64"]
    res = _broadcast_near(b64)
    tx_hash = res["tx_hash"]

    def _final_signature():
        """Fetch the tx final outcome; return the MPC signature if present."""
        import urllib.request

        req = urllib.request.Request(
            NEAR_RPC,
            data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tx",
                             "params": [tx_hash, acct]}).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            r = json.loads(urllib.request.urlopen(req, timeout=30).read())
        except Exception:
            return None
        sv = None
        for st in r.get("result", {}).get("receipts_outcome", []):
            sv = st.get("outcome", {}).get("status", {}).get("SuccessValue") or sv
        if sv:
            try:
                sig = json.loads(base64.b64decode(sv))
                if sig.get("big_r") and sig.get("s") and sig.get("recovery_id") is not None:
                    sig["request_tx"] = tx_hash
                    return sig
            except Exception:
                return None
        return None

    # fast path: final query right away
    sig = _final_signature()
    if sig:
        return sig

    # fallback: poll for the async respond receipt
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        time.sleep(6)
        sig = _final_signature() or _find_signature_response(
            tx_hash, payload32, path, acct)
        if sig:
            return sig
    raise TimeoutError(f"no MPC signature within {timeout_s}s (request tx {tx_hash})")


# --------------------------------------------------------------- EVM layer ---

def build_unsigned_transfer(w3: Web3, from_addr: str, to: str, value_eth: float,
                            data: bytes = b"") -> dict:
    tx = {
        "chainId": w3.eth.chain_id,
        "nonce": w3.eth.get_transaction_count(from_addr),
        "gasPrice": w3.eth.gas_price,
        "to": Web3.to_checksum_address(to),
        "value": Web3.to_wei(value_eth, "ether"),
        "data": data,
    }
    tx["gas"] = w3.eth.estimate_gas({**tx, "from": from_addr})
    return tx


def signer_hash(tx: dict) -> bytes:
    """keccak256 of the RLP-encoded unsigned legacy tx (EIP-155)."""
    from eth_account._utils.legacy_transactions import Transaction

    t = Transaction(v=tx["chainId"], r=0, s=0,
                    nonce=tx["nonce"], gas_price=tx["gasPrice"], gas=tx["gas"],
                    to=bytes.fromhex(tx["to"][2:]), value=tx["value"], data=tx["data"])
    return bytes(t.hash_for_signature(tx["chainId"]))


def assemble_signed(tx: dict, mpc_sig: dict):
    """Build the signed legacy tx from the unsigned fields + MPC signature."""
    from eth_account._utils.legacy_transactions import Transaction

    r_hex = mpc_sig["big_r"]
    if r_hex.startswith("0x"):
        r_hex = r_hex[2:]
    r_int = int(r_hex, 16) % (2**256)
    s_int = int(mpc_sig["s"], 16)
    v = tx["chainId"] * 2 + 35 + int(mpc_sig["recovery_id"])
    return Transaction(v=v, r=r_int, s=s_int,
                       nonce=tx["nonce"], gas_price=tx["gasPrice"], gas=tx["gas"],
                       to=bytes.fromhex(tx["to"][2:]), value=tx["value"], data=tx["data"])


def sign_and_broadcast_intent(to: str, value_eth: float, guard: Guard | None = None,
                              data: bytes = b"") -> dict:
    """Full leash path for an EVM transfer intent on Base Sepolia."""
    guard = guard or Guard()
    decision = guard.check(CHAIN, to, value_eth)
    if not decision.allowed:
        raise DenyError(decision)

    acct_id = _load_keyfile()["account_id"]
    from_addr = derived_address(acct_id, LEASH_PATH)

    w3 = Web3(Web3.HTTPProvider(BASE_SEPOLIA_RPC, request_kwargs={"timeout": 30}))
    tx = build_unsigned_transfer(w3, from_addr, to, value_eth, data)
    payload = signer_hash(tx)
    mpc_sig = request_mpc_signature(payload)
    signed = assemble_signed(tx, mpc_sig)

    raw = signed.encode_for_rlp() if hasattr(signed, "encode_for_rlp") else None
    # eth_account Transaction encodes via rlp(); wrap for a signed raw tx
    from rlp import encode

    raw_tx = "0x" + encode(signed).hex()
    h = w3.eth.send_raw_transaction(bytes.fromhex(raw_tx[2:]))
    rc = w3.eth.wait_for_transaction_receipt(h, timeout=180)
    guard.record(to, value_eth)
    return {
        "from": from_addr, "to": to, "value_eth": value_eth,
        "evm_tx": h.hex(), "status": int(rc.status),
        "mpc_request_tx": mpc_sig.get("request_tx"),
        "recovery_id": mpc_sig["recovery_id"],
    }
