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

🚧 WIP — sprint started Oct 24, 2026. See `HACKATHON.md` for the judge walkthrough and `docs/` for design notes.

## Quickstart

```bash
python3.11 -m venv venv && venv/bin/pip install -r requirements.txt
cp .env.example .env   # fill in testnet keys
venv/bin/pytest -q
```

## Architecture

```
attacker/scam-bot → SENTINEL decoys (Base Sepolia) → fingerprint
   → publish_verdict via NEAR Chain Signatures → SENTINEL REGISTRY (NEAR contract)
   → LEASH pre-sign check (blocklist + caps + velocity) → sign or DENY (tx never exists)
```

## License

MIT — see [LICENSE](LICENSE).
