"""T11 unit tests — local scorer + honest TEE fallback."""

import pytest

from sentinel.scoring import (
    NotImplementedOffline,
    private_inference_configured,
    score_with_local_rules,
    score_with_private_inference,
)


def test_local_scores_match_blueprint_weights():
    cap = {"kind": "approval", "decoded_sig": "approve(address,uint256)"}
    assert score_with_local_rules(cap) == 98  # 0.95 + 0.03 MO bump
    assert score_with_local_rules({"kind": "token_out"}) == 90
    assert score_with_local_rules({"kind": "eth_out"}) == 70
    assert score_with_local_rules({"kind": "?"}) == 40


def test_local_score_bounds():
    assert 0 <= score_with_local_rules({}) <= 100


def test_private_inference_offline_is_honest(monkeypatch):
    monkeypatch.delenv("NEARAI_API_KEY", raising=False)
    monkeypatch.delenv("NEARAI_INFERENCE_URL", raising=False)
    assert private_inference_configured() is False
    with pytest.raises(NotImplementedOffline):
        score_with_private_inference({"kind": "approval"})
