"""Decoy wallet generation and persistence.

Decoys are bait wallets: believable balances, keys stored locally (testnet-only),
state tracked in decoys/state.json so the trap listener knows what to watch.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict, field

from eth_account import Account

STATE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "decoys")
STATE_FILE = os.path.join(STATE_DIR, "state.json")


@dataclass
class Decoy:
    address: str
    keyfile: str  # path to JSON keyfile (testnet bait key)
    label: str
    funded_eth: float = 0.0
    token: str = ""  # GullibleToken address decoy holds


def new_decoy(label: str) -> Decoy:
    """Generate one decoy wallet, write its key as a JSON keyfile with tight perms."""
    acct = Account.create()
    os.makedirs(STATE_DIR, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    kf = os.path.join(STATE_DIR, f"{label}.key.json")
    # testnet bait key; plaintext json but dir locked 0700 and gitignored
    with open(kf, "w") as f:
        json.dump({"address": acct.address, "private_key": acct.key.hex()}, f)
    os.chmod(kf, 0o600)
    return Decoy(address=acct.address, keyfile=kf, label=label)


def save_state(decoys: list[Decoy], extra: dict | None = None) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    payload = {"decoys": [asdict(d) for d in decoys], **(extra or {})}
    with open(STATE_FILE, "w") as f:
        json.dump(payload, f, indent=2)
    os.chmod(STATE_FILE, 0o600)


def load_state() -> dict:
    with open(STATE_FILE) as f:
        return json.load(f)


def generate_batch(n: int, prefix: str = "decoy") -> list[Decoy]:
    return [new_decoy(f"{prefix}-{i:02d}") for i in range(n)]
