"""Regression tests for guard edge cases found in the deep audit (22 Oct 2026)."""

from leash.guard import Guard, RegistryFeed


class NoFeed(RegistryFeed):
    def is_blocked(self, chain, addr):
        return False


T0 = 1_700_000_000.0


def make_guard(**kw):
    return Guard(registry_feed=NoFeed(), cooldown_s=0, **kw)


def test_negative_value_denied():
    g = make_guard()
    d = g.check("base-sepolia", "0xAAA", -1.0, now=T0)
    assert not d.allowed and d.rule == "malformed_intent"


def test_empty_recipient_denied():
    g = make_guard()
    d = g.check("base-sepolia", "", 0.001, now=T0)
    assert not d.allowed and d.rule == "malformed_intent"


def test_zero_value_still_allowed():
    # zero-value txs (calls, approvals) are legitimate
    g = make_guard()
    d = g.check("base-sepolia", "0xAAA", 0.0, now=T0)
    assert d.allowed


def test_huge_value_hits_per_tx_cap():
    g = make_guard()
    d = g.check("base-sepolia", "0xAAA", 999999.0, now=T0)
    assert not d.allowed and d.rule == "per_tx_cap"
