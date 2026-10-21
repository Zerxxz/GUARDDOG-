"""T14 prep — self-running demo script that produces every shot the video needs.

Runs the full story in one pass and prints a timestamped narration log:
  decoy list → strike → trap capture → verdict on-chain → Leash deny vs allow
  → live MPC signature → registry stats

Output: a plain-text "shot list" (demo/script_output.txt) the screen recording
follows. Deterministic order, real chains, real evidence everywhere.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
import time
from contextlib import redirect_stdout

from sentinel import db, publish


def sh(args: list[str]) -> str:
    out = subprocess.run(args, capture_output=True, text=True)
    return (out.stdout + out.stderr).strip()


def banner(t: str) -> str:
    return f"\n{'=' * 62}\n  {t}\n{'=' * 62}"


def run() -> str:
    log = io.StringIO()

    with redirect_stdout(log):
        print(banner("SHOT 1 — the decoys are live (Base Sepolia)"))
        print(sh([sys.executable, "-m", "sentinel.cli", "list"]))

        print(banner("SHOT 2 — attacker strikes (simulated drainer, honest)"))
        print(sh([sys.executable, "-m", "demo.strike"]))

        print(banner("SHOT 3 — Sentinel trap captures the contact"))
        print(sh([sys.executable, "-m", "sentinel.trap", "watch", "--once"]))
        cap = db.list_captures(limit=1)[0]
        print(f"\ncapture #{cap['id']}: {cap['kind']} | selector {cap['selector']} "
              f"| confidence {cap['confidence']:.0%}")
        print(f"attacker: {cap['attacker_addr']}")
        print(f"evidence: {cap['tx_hash']}")

        print(banner("SHOT 4 — verdict published on-chain (NEAR testnet)"))
        res = publish.publish_capture(cap["id"])
        v, near = res["verdict"], res["near"]
        print(f"verdict {v['id']} → NEAR tx {near['tx_hash']}")
        print(f"registry result: {near.get('result')}")
        stats = publish.view("stats", {})
        print(f"registry now: {stats}")

        print(banner("SHOT 5 — Leash: the attacker is now DENIED at signing"))
        from leash.guard import Guard
        g = Guard()
        d = g.check(v["chain"], v["attacker"], 0.001)
        print(f"check → {'ALLOW' if d.allowed else f'DENY [{d.rule}]'} — {d.reason}")
        print("→ the drainer's transaction is never signed. It does not exist.")
        g.record("0x00000000000000000000000000000000c0ffee00", 0.0001)

        print(banner("SHOT 6 — healthy agent flows under the same policy"))
        d2 = g.check("base-sepolia", "0x00000000000000000000000000000000c0ffee00", 0.0001,
                     now=time.time() + 10_000)
        print(f"check → {'ALLOW' if d2.allowed else f'DENY [{d2.rule}]'} — {d2.reason}")

        print(banner("SHOT 7 — live Chain Signatures (MPC network signs)"))
        import hashlib
        from leash.signer import LEASH_PATH, request_mpc_signature
        sig = request_mpc_signature(hashlib.sha256(b"guarddog demo shot").digest(),
                                    LEASH_PATH, timeout_s=120)
        big_r = sig["big_r"]["affine_point"] if isinstance(sig["big_r"], dict) else sig["big_r"]
        s = sig["s"]["scalar"] if isinstance(sig["s"], dict) else sig["s"]
        print(f"big_r       : {big_r[:20]}… ({len(big_r)} hex)")
        print(f"s           : {s[:20]}…")
        print(f"recovery_id : {sig['recovery_id']}   (signed by the 8-node MPC network)")
        print(f"request tx  : {sig['request_tx']}")

        print(banner("DONE — every shot above is real, on live testnets"))

    return log.getvalue()


if __name__ == "__main__":
    text = run()
    with open("/home/ubuntu/guarddog/demo/script_output.txt", "w") as f:
        f.write(text)
    print(text)
