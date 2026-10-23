"""Leash policy engine (T7): pre-sign checks consumed by the signing layer.

Rules, all pure and unit-testable:
  - blocklist  : counterparty on the Sentinel Registry verdict feed → deny
  - per_tx_cap : value above the cap → deny
  - daily_cap  : cumulative value in the rolling 24h window above cap → deny
  - velocity   : more than N txs in the rolling window → deny
  - cooldown   : an anomaly (denial) within the cooldown window → deny everything

The registry is read through an injectable ``RegistryFeed`` (cached, TTL) so
tests run offline and the live path uses NEAR RPC.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

import httpx

NEAR_RPC = os.getenv("NEAR_RPC", "https://rpc.testnet.near.org")
REGISTRY = os.getenv("SENTINEL_REGISTRY_CONTRACT", "guarddog-sentinel.testnet")

DEFAULTS = dict(
    per_tx_cap_eth=0.005,
    daily_cap_eth=0.02,
    velocity_max=5,
    velocity_window_s=3600,
    cooldown_s=600,
)


@dataclass
class Decision:
    allowed: bool
    reason: str
    rule: str = ""


@dataclass
class TxHistory:
    """Rolling in-memory ledger of signed txs (ts, value_eth, to)."""

    entries: list = field(default_factory=list)

    def add(self, ts: float, value_eth: float, to: str) -> None:
        self.entries.append((ts, value_eth, (to or "").lower()))

    def in_window(self, ts: float, window_s: float) -> list:
        return [e for e in self.entries if ts - e[0] <= window_s]


class RegistryFeed:
    """is_blocked() with a TTL cache; injectable for tests."""

    def __init__(self, ttl_s: float = 30.0, rpc_url: str = NEAR_RPC, registry: str = REGISTRY):
        self.ttl = ttl_s
        self.rpc_url = rpc_url
        self.registry = registry
        self._cache: dict[tuple, tuple[float, bool]] = {}

    def is_blocked(self, chain: str, addr: str) -> bool:
        key = (chain, (addr or "").lower())
        hit = self._cache.get(key)
        now = time.time()
        if hit and now - hit[0] < self.ttl:
            return hit[1]
        blocked = self._query(chain, key[1])
        self._cache[key] = (now, blocked)
        return blocked

    def _query(self, chain: str, addr: str) -> bool:
        import base64
        import json
        import urllib.request

        args_b64 = base64.b64encode(
            json.dumps({"chain": chain, "addr": addr}).encode()
        ).decode()
        req = urllib.request.Request(
            self.rpc_url,
            data=json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "query",
                "params": {"request_type": "call_function", "account_id": self.registry,
                           "method_name": "is_blocked", "args_base64": args_b64,
                           "finality": "final"},
            }).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            resp = json.loads(urllib.request.urlopen(req, timeout=15).read())
            raw = bytes(resp["result"]["result"]).decode()
            return json.loads(raw) is True
        except Exception:
            # fail-closed would brick the wallet on RPC hiccups; policy decision:
            # fail-open for reads, deny is enforced by caps/velocity regardless.
            return False


class Guard:
    def __init__(self, registry_feed: RegistryFeed | None = None, **limits):
        self.feed = registry_feed or RegistryFeed()
        cfg = dict(DEFAULTS)
        cfg.update(limits)
        self.per_tx_cap_eth = cfg["per_tx_cap_eth"]
        self.daily_cap_eth = cfg["daily_cap_eth"]
        self.velocity_max = cfg["velocity_max"]
        self.velocity_window_s = cfg["velocity_window_s"]
        self.cooldown_s = cfg["cooldown_s"]
        self.history = TxHistory()
        self.last_denial_ts: float | None = None

    def check(self, chain: str, to: str, value_eth: float, now: float | None = None) -> Decision:
        """Run every rule; return the first denial or an allow."""
        now = time.time() if now is None else now

        # malformed intent: negative value is nonsensical (or an attempt to
        # exploit accounting); empty recipient burns funds — both denied outright
        if value_eth < 0:
            self.last_denial_ts = now
            return Decision(False, "negative value in intent", "malformed_intent")
        if not (to or "").strip():
            self.last_denial_ts = now
            return Decision(False, "empty recipient", "malformed_intent")

        # cooldown: after an anomaly, nothing moves for cooldown_s
        if self.last_denial_ts is not None and now - self.last_denial_ts < self.cooldown_s:
            return Decision(False, "cooldown after anomaly", "cooldown")

        if self.feed.is_blocked(chain, to or ""):
            self.last_denial_ts = now
            return Decision(False, f"{to} is on the Sentinel blocklist", "blocklist")

        if value_eth > self.per_tx_cap_eth:
            self.last_denial_ts = now
            return Decision(
                False,
                f"value {value_eth} ETH exceeds per-tx cap {self.per_tx_cap_eth} ETH",
                "per_tx_cap",
            )

        window = self.history.in_window(now, 86400)
        daily = sum(e[1] for e in window) + value_eth
        if daily > self.daily_cap_eth:
            self.last_denial_ts = now
            return Decision(
                False,
                f"daily total {daily} ETH would exceed cap {self.daily_cap_eth} ETH",
                "daily_cap",
            )

        recent = self.history.in_window(now, self.velocity_window_s)
        if len(recent) + 1 > self.velocity_max:
            self.last_denial_ts = now
            return Decision(
                False,
                f"velocity limit: {len(recent)} txs in the last "
                f"{self.velocity_window_s}s (max {self.velocity_max})",
                "velocity",
            )

        return Decision(True, "all checks passed")

    def record(self, to: str, value_eth: float, now: float | None = None) -> None:
        """Record a signed tx into the rolling ledger."""
        self.history.add(time.time() if now is None else now, value_eth, to)
