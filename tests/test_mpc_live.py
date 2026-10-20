"""Integration: the full MPC sign loop against the live testnet network.

Requests a real Chain Signatures signature for a fixed probe payload and
verifies the response shape. Network-dependent; kept separate from unit
tests. The probe payload is deterministic so the request is idempotent-ish
(the MPC contract rejects duplicate pending requests, which is fine — a
duplicate simply errors, the probe is about the happy path).
"""

import hashlib

import pytest

from leash.signer import LEASH_PATH, request_mpc_signature

pytestmark = pytest.mark.integration


def test_mpc_signature_loop_live():
    payload = hashlib.sha256(b"guarddog mpc loop probe").digest()
    sig = request_mpc_signature(payload, LEASH_PATH, timeout_s=120)
    big_r = sig["big_r"]["affine_point"] if isinstance(sig["big_r"], dict) else sig["big_r"]
    s = sig["s"]["scalar"] if isinstance(sig["s"], dict) else sig["s"]
    assert big_r.startswith("02") or big_r.startswith("03")
    assert len(big_r) == 66  # 33-byte compressed point
    assert len(s) == 64  # 32-byte scalar
    assert sig["recovery_id"] in (0, 1)
    assert sig["request_tx"]
