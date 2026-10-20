# GUARDDOG 🐕‍🦺

> Honeypot-backed immune system for AI agents that hold money.
> Built for **NEAR HACKATHON** (Nov 1–14, 2026 · $250K · track: AI Security & Defense).

Every other team builds agents that hold money. GUARDDOG builds the immune system —
learned from real attackers, not static lists.

## What it is

**Sentinel** deploys believable decoy wallets (loose token approvals, dummy balances,
bait endpoints). When a rogue agent or scam bot strikes one, it gets fingerprinted
(selector, call pattern, chain) and a **verdict is published on-chain via NEAR Chain
Signatures** — first-party empirical evidence, not ML guesses.

**Leash** is a firewall at the *signing layer*: every agent transaction is checked
against the live threat feed + owner policy (caps, velocity, blocklist) **before**
being signed via MPC. A denied transaction is never signed — prompt injection
cannot bypass a wallet the model never holds.

## Status

🚧 Sprint in progress (ends Nov 7). **Week-1 core loop is LIVE on testnets** —
the demo below runs end-to-end against real chains right now.

## Do X, see Y — judges-replicable walkthrough

Everything runs on **Base Sepolia** (decoys, attacks) and **NEAR testnet**
(verdict registry, MPC signing). No mainnet funds anywhere.

```bash
python3.11 -m venv venv && venv/bin/pip install -r requirements.txt
cp .env.example .env   # fill in testnet keys (see .env.example comments)
venv/bin/pytest -q     # 25 tests green
```

**1 · Attack a decoy and watch the trap catch it**

```bash
venv/bin/python -m demo.strike          # simulated drainer max-approves the bait token
venv/bin/python -m sentinel.trap watch --once
venv/bin/python -m sentinel.trap captures
```

*See:* `[CAPTURE] approval …` with selector `approve(address,uint256)`,
confidence 95%, evidence tx hash.

**2 · Publish the verdict on-chain (NEAR)**

```bash
venv/bin/python -c "
from sentinel import db, publish
r = publish.publish_capture(db.list_captures(limit=1)[0]['id'])
print(r['verdict']['id'], r['near']['tx_hash'], r['near']['result'])"
```

*See:* `{'accepted': True, 'updated': True, ...}` — the verdict now lives on
NEAR testnet at `guarddog-sentinel.testnet`. Verify independently:

```bash
curl -s -X POST https://rpc.testnet.near.org -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"query","params":{"request_type":"call_function",
  "account_id":"guarddog-sentinel.testnet","method_name":"stats","args_base64":"",
  "finality":"final"}}' | python3 -m json.tool
```

**3 · Prompt-injected agent vs healthy agent — Leash judges both**

```bash
venv/bin/python -m demo.injection
```

*See:* healthy transfer `ALLOW ✅`; injected drain `DENY 🚫 [blocklist]` —
**the denied transaction is never signed, so it never exists on any chain.**

**4 · Full E2E loop in one command** (strike → capture → verdict → deny)

```bash
venv/bin/python -m demo.e2e
```

**5 · Read API**

```bash
venv/bin/uvicorn sentinel.api:app --port 8080 &
curl -s "localhost:8080/is_blocked?chain=base-sepolia&addr=<attacker>"   # {"blocked": true}
curl -s localhost:8080/stats
```

**6 · Live MPC signing (Chain Signatures)**

```bash
venv/bin/python -c "
import hashlib
from leash.signer import request_mpc_signature, LEASH_PATH
sig = request_mpc_signature(hashlib.sha256(b'probe').digest(), LEASH_PATH)
print(sig['big_r'], sig['s'], sig['recovery_id'])"
```

*See:* a real (big_r, s, recovery_id) produced by the 8-node MPC network for
our account+derivation path — the same machinery that will sign Leash-guarded
EVM transactions.

## Chain Signatures usage (why this is non-trivial)

- The registry **verifies MPC signatures on-chain**: it re-derives the expected
  key for `(publisher, path)` with the exact `crypto_shared::kdf` algorithm
  (sha3-256 epsilon, `P_mpc + ε·G`) and recovers the signer from
  `(big_r, s, recovery_id)` — a verdict needs a signature that only the
  MPC network could produce for that publisher.
- Leash **signs through MPC**: the EVM key never exists outside the MPC network,
  so a compromised agent cannot exfiltrate it.
- Contract: `registry/src/lib.rs` (near-sdk 5.29.1, 17 unit tests).

## Honest limitations

- The demo attacker is **simulated** (`demo/strike.py`) — the capture pipeline
  itself is fully real end-to-end on testnet. Real-attacker honeypots on mainnet
  are post-MVP.
- Verdicts currently publish via the **owner fallback** (blueprint risk-table
  mitigation); the contract's on-chain MPC verification path is implemented and
  unit-tested, and will carry production verdicts in T14 polish.
- TEE scoring via NEAR AI Cloud is **future work** (`sentinel/scoring.py` falls
  back to local rule-based scoring when unconfigured).
- Docker files are provided; the image build was not smoke-tested on this box.

## Architecture

```
attacker/scam-bot → SENTINEL decoys (Base Sepolia) → fingerprint
   → publish_verdict via NEAR Chain Signatures → SENTINEL REGISTRY (NEAR contract)
   → LEASH pre-sign check (blocklist + caps + velocity) → sign or DENY (tx never exists)
```

## License

MIT — see [LICENSE](LICENSE).
