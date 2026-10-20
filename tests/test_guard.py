"""Unit tests for the Leash policy engine — pure, offline, deterministic."""

import pytest

from leash.guard import Decision, Guard, RegistryFeed, TxHistory


class FakeFeed(RegistryFeed):
    """Offline registry feed with a static blocklist."""

    def __init__(self, blocked: set[tuple[str, str]] | None = None):
        super().__init__(ttl_s=1)
        self.blocked = blocked or set()

    def is_blocked(self, chain: str, addr: str) -> bool:
        return (chain, (addr or "").lower()) in self.blocked


T0 = 1_700_000_000.0


def make_guard(**kw) -> Guard:
    return Guard(registry_feed=FakeFeed(), **kw)


def test_allow_normal_tx():
    g = make_guard()
    d = g.check("base-sepolia", "0xAAA", 0.001, now=T0)
    assert d.allowed and d.rule == ""


def test_blocklist_denies_and_sets_cooldown():
    g = make_guard()
    g.feed = FakeFeed(blocked={("base-sepolia", "0xdead")})
    d = g.check("base-sepolia", "0xDEAD", 0.001, now=T0)
    assert not d.allowed and d.rule == "blocklist"
    # cooldown now applies to everything
    d2 = g.check("base-sepolia", "0xAAA", 0.001, now=T0 + 1)
    assert not d2.allowed and d2.rule == "cooldown"
    # after the cooldown window it works again
    d3 = g.check("base-sepolia", "0xAAA", 0.001, now=T0 + 601)
    assert d3.allowed


def test_per_tx_cap():
    g = make_guard(per_tx_cap_eth=0.005)
    d = g.check("base-sepolia", "0xAAA", 0.006, now=T0)
    assert not d.allowed and d.rule == "per_tx_cap"
    # cooldown clears
    d2 = g.check("base-sepolia", "0xAAA", 0.005, now=T0 + g.cooldown_s + 1)
    assert d2.allowed


def test_daily_cap_accumulates():
    g = make_guard(daily_cap_eth=0.02, per_tx_cap_eth=0.005)
    for i in range(3):
        g.check("base-sepolia", "0xAAA", 0.005, now=T0 + i)
        g.record("0xAAA", 0.005, now=T0 + i)
    # 0.015 already spent + 0.0049 new = 0.0199... use two more txs instead:
    # 0.005 x3 recorded; next tx 0.0049 passes per-tx but 0.0199 < cap... push to 4 txs
    g.record("0xAAA", 0.0049, now=T0 + 10 + g.cooldown_s)
    d = g.check("base-sepolia", "0xAAA", 0.0005, now=T0 + 11 + g.cooldown_s)
    assert not d.allowed and d.rule == "daily_cap"


def test_velocity_limit():
    g = make_guard(velocity_max=3, velocity_window_s=60)
    for i in range(3):
        g.record("0xAAA", 0.0001, now=T0 + i)
    d = g.check("base-sepolia", "0xAAA", 0.0001, now=T0 + 5)
    assert not d.allowed and d.rule == "velocity"
    # window slides: cooldown cleared and first tx dropped out
    d2 = g.check("base-sepolia", "0xAAA", 0.0001, now=T0 + g.cooldown_s + 65)
    assert d2.allowed


def test_cooldown_expires():
    g = make_guard(cooldown_s=100)
    g.check("base-sepolia", "0xAAA", 99, now=T0)  # triggers per-tx denial
    d = g.check("base-sepolia", "0xAAA", 0.001, now=T0 + 99)
    assert not d.allowed and d.rule == "cooldown"
    d2 = g.check("base-sepolia", "0xAAA", 0.001, now=T0 + 101)
    assert d2.allowed


def test_history_window_prunes():
    h = TxHistory()
    h.add(0, 1, "0xa")
    h.add(10, 1, "0xa")
    assert len(h.in_window(10, 5)) == 1
    assert len(h.in_window(10, 100)) == 2


def test_decision_shape():
    d = Decision(True, "ok")
    assert d.rule == ""
