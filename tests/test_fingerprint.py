"""Pure-function tests for fingerprinting (no network)."""

from sentinel.fingerprint import decode_signature, pattern_hash, score, selector_of


def test_selector_extraction():
    calldata = "0x095ea7b3" + "aa" * 64
    assert selector_of(calldata) == "0x095ea7b3"
    assert selector_of("0x") is None
    assert selector_of(None) is None


def test_known_selector_decode_offline():
    assert "approve" in decode_signature("0x095ea7b3")
    assert "transfer" in decode_signature("0xa9059cbb")


def test_pattern_hash_stable():
    a = pattern_hash("0x095ea7b3", "approval", "0xBAD")
    b = pattern_hash("0x095ea7b3", "approval", "0xbad")
    c = pattern_hash("0xa9059cbb", "approval", "0xbad")
    assert a == b  # case-insensitive counterparty
    assert a != c  # different selector → different pattern


def test_confidence_ordering():
    assert score("approval", "approve(address,uint256)") > score("token_out", None)
    assert score("token_out", None) > score("eth_out", None)
