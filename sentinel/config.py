"""Sentinel configuration — loads .env from the repo root."""

import os

from dotenv import load_dotenv

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(ROOT, ".env"))

BASE_SEPOLIA_RPC = os.getenv("BASE_SEPOLIA_RPC", "https://sepolia.base.org")
OPERATOR_KEYFILE = os.getenv("OPERATOR_KEYFILE", "")
DECOY_COUNT = int(os.getenv("DECOY_COUNT", "5"))
DECOY_FUND_ETH = float(os.getenv("DECOY_FUND_ETH", "0.01"))


def operator_account():
    """Load the operator EVM account from its keyfile (path in .env, never the key itself)."""
    import json

    from eth_account import Account

    if not OPERATOR_KEYFILE or not os.path.exists(OPERATOR_KEYFILE):
        raise FileNotFoundError(
            f"OPERATOR_KEYFILE not set or missing: {OPERATOR_KEYFILE!r} — set it in .env"
        )
    with open(OPERATOR_KEYFILE) as f:
        data = json.load(f)
    return Account.from_key(data["private_key"])
