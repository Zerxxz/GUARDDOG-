"""T11 — TEE angle (NEAR AI Cloud private inference).

Honest scope per blueprint: this is the *polish* task. What is real here:

- `score_with_local_rules` — deterministic, offline scoring of a capture
  (works today, used as the baseline and as the fallback).
- `score_with_private_inference` — sends the capture to a NEAR AI Cloud
  private-inference endpoint when NEARAI_API_KEY/endpoint is configured.
  No keys in this repo → it raises NotImplementedOffline, and the publish
  path keeps using the local scorer. README labels TEE scoring as
  future work unless the endpoint is live.

The verdict contract stays the source of truth either way; scoring only
affects `confidence` before publish.
"""

from __future__ import annotations

import os


class NotImplementedOffline(Exception):
    """Private inference is not configured on this box."""


LOCAL_WEIGHTS = {
    "approval": 0.95,
    "token_out": 0.90,
    "eth_out": 0.70,
}


def score_with_local_rules(capture: dict) -> int:
    """Baseline scorer: behavioral weight + small modifiers, 0..=100."""
    kind = capture.get("kind", "")
    base = LOCAL_WEIGHTS.get(kind, 0.40)
    score = base
    # max-approval pattern is the classic drainer MO — bump it
    if kind == "approval" and (capture.get("decoded_sig") or "").startswith("approve"):
        score += 0.03
    return int(round(min(score, 1.0) * 100))


def private_inference_configured() -> bool:
    return bool(os.getenv("NEARAI_API_KEY")) and bool(os.getenv("NEARAI_INFERENCE_URL"))


def score_with_private_inference(capture: dict) -> int:
    """Score inside a TEE via NEAR AI Cloud. Requires env configuration.

    The capture payload is deliberately minimal (addresses + selector + kind)
    so that, when enabled, the model never sees decoy keys or balances.
    """
    if not private_inference_configured():
        raise NotImplementedOffline(
            "NEAR AI Cloud private inference not configured — "
            "using local rule-based scoring (see README: TEE = future work)"
        )
    import httpx

    r = httpx.post(
        os.environ["NEARAI_INFERENCE_URL"],
        headers={"Authorization": f"Bearer {os.environ['NEARAI_API_KEY']}"},
        json={
            "model": os.getenv("NEARAI_MODEL", "llama-3.1-8b-instruct"),
            "messages": [{
                "role": "user",
                "content": json.dumps({
                    "task": "threat_score_0_100",
                    "capture": {k: capture.get(k) for k in
                                ("kind", "selector", "decoded_sig", "chain")},
                }),
            }],
            "max_tokens": 8,
        },
        timeout=30,
    )
    r.raise_for_status()
    return int(str(r.json()["choices"][0]["message"]["content"]).strip()[:3])
