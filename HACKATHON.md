# HACKATHON.md — GUARDDOG judge walkthrough

> Follow NEAR HACKATHON guidance: every step is "do X, see Y". Judges should never guess.

## Prerequisites
- Python 3.11, a Base Sepolia RPC URL, a NEAR testnet account (see README Quickstart).

## Walkthrough (filled in at T15, before Nov 7)

1. **See the decoys.** Do: `venv/bin/python -m sentinel.factory --list`
   See: N decoy wallets on Base Sepolia with balances and a loose-approval token.
2. **Strike a decoy.** Do: `venv/bin/python -m demo.attacker --target <decoy_addr>`
   See: the attack lands, Telegram alert arrives within ~10s.
3. **See the verdict on-chain.** Do: `venv/bin/python -m sentinel.publish --latest`
   See: verdict recorded in the NEAR registry (<60s from capture) with the evidence tx hash.
4. **Watch Leash refuse the attacker.** Do: `venv/bin/python -m demo.attacker --via-leash <blocked_addr>`
   See: `DENIED at signing layer` — no transaction appears on-chain.
5. **Watch Leash allow a healthy agent.** Do: `venv/bin/python -m demo.healthy_agent`
   See: transfer executes normally under the same caps.

## Tech used (named per HACKATHON guidance)
- NEAR Chain Signatures (MPC) — verdict publication + Leash cross-chain signing
- NEAR smart contract (Rust) — Sentinel Registry
- NEAR AI Cloud (TEE) — fingerprint scoring (planned T11)
