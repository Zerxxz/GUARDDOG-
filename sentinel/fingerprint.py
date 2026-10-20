"""Fingerprinting: turn a raw capture into a structured, scorable signal."""

from __future__ import annotations

import hashlib

import httpx

SELECTORS = {
    "0x095ea7b3": "approve(address,uint256)",
    "0xa9059cbb": "transfer(address,uint256)",
    "0x23b872dd": "transferFrom(address,address,uint256)",
    "0x2e1a7d4d": "withdraw(uint256)",
    "0xd0e30db0": "deposit()",
    "0x095ea7b300000000": "approve(address,uint256) [max-approval pattern]",
}


def selector_of(calldata: str) -> str | None:
    if not calldata or len(calldata) < 10:
        return None
    if calldata.startswith("0x"):
        calldata = calldata[2:]
    return "0x" + calldata[:8]


def decode_signature(selector: str) -> str | None:
    """Best-effort lookup via the openchain signature DB; None if offline/unknown."""
    if selector in SELECTORS:
        return SELECTORS[selector]
    try:
        r = httpx.get(
            "https://api.openchain.xyz/signature-database/v1/lookup",
            params={"function": selector},
            timeout=8,
        )
        data = r.json()
        hit = data.get("result", {}).get("function", {}).get(selector)
        if hit:
            return hit[0]["name"]
    except Exception:
        pass
    return None


def pattern_hash(selector: str | None, kind: str, counterparty: str) -> str:
    """Stable behavioral fingerprint: what was attempted, against whom."""
    basis = f"{kind}|{selector or 'raw-eth'}|{counterparty.lower()}"
    return hashlib.sha256(basis.encode()).hexdigest()[:16]


def score(kind: str, decoded: str | None) -> float:
    """Confidence that this interaction is a hostile drain attempt."""
    if kind == "approval" and decoded and decoded.startswith("approve"):
        return 0.95  # drainer MO: get the victim to approve a spender
    if kind == "token_out":
        return 0.90  # direct bait-token theft
    if kind == "eth_out":
        return 0.70  # ETH leaving a decoy — suspicious, lower certainty
    return 0.40
