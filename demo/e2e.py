"""T9 — E2E integration: attacker → decoy → verdict → Leash deny.

Full loop over live testnets (Base Sepolia + NEAR testnet):

  1. demo.strike              — attacker max-approves the bait token
  2. sentinel.trap watch      — capture lands in events.db
  3. sentinel.publish         — verdict goes on-chain (owner fallback)
  4. leash.guard check        — the attacker address is now DENIED

Run: venv/bin/python -m demo.e2e
"""

from __future__ import annotations

import time

from sentinel import db, publish


def run() -> dict:
    import subprocess
    import sys

    venv_py = sys.executable

    print("[1/4] strike — attacker max-approves the bait token")
    out = subprocess.run([venv_py, "-m", "demo.strike"], capture_output=True, text=True)
    assert out.returncode == 0, f"strike failed: {out.stderr[-300:]}"
    print("      ", out.stdout.strip().splitlines()[-2])

    print("[2/4] trap watch — capture the hostile approval")
    out = subprocess.run([venv_py, "-m", "sentinel.trap", "watch", "--once"],
                         capture_output=True, text=True)
    assert out.returncode == 0, f"trap failed: {out.stderr[-300:]}"
    caps = db.list_captures(limit=1)
    cap = caps[0]
    print(f"       capture #{cap['id']} {cap['kind']} attacker={cap['attacker_addr'][:12]}…")

    print("[3/4] publish verdict on-chain")
    res = publish.publish_capture(cap["id"])
    v, near = res["verdict"], res["near"]
    print(f"       {v['id']} tx {near['tx_hash'][:18]}… result={near.get('result')}")

    print("[4/4] leash guard — attacker must now be DENIED")
    from leash.guard import Guard
    g = Guard()
    d = g.check(v["chain"], v["attacker"], 0.001)
    assert not d.allowed and d.rule == "blocklist", f"expected blocklist deny, got {d}"
    print(f"       DENY [{d.rule}]: {d.reason}")

    # allow a clean address as contrast
    d2 = g.check(v["chain"], "0x000000000000000000000000000000000000c0de", 0.001)
    print(f"       clean address: {'ALLOW' if d2.allowed else d2.reason}")

    return {"capture": cap, "verdict": v, "near_tx": near["tx_hash"], "deny": d}


if __name__ == "__main__":
    run()
