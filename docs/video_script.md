# GUARDDOG video script — <3 minutes, shot-by-shot

Recording guide for BOS. Run `venv/bin/python -m demo.video_script` in a
second terminal — it executes the whole story live and prints the exact
output below (also saved to `demo/script_output.txt`). Record the terminal
plus the dashboard browser tab.

Narration text is what you say (or caption) per shot. Total ~2:30.

---

**SHOT 0 (0:00–0:15) — Hook**
Visual: README hero / the architecture diagram.
Say: "AI agents are starting to hold real money. Who protects them?
GUARDDOG is an immune system: honeypots that catch bad agents, and a
firewall that stops them at the signature layer. Everything you're about
to see is live on testnets."

**SHOT 1 (0:15–0:35) — The decoys are live**
Visual: terminal, `python -m sentinel.cli list` output.
Say: "Five decoy wallets on Base Sepolia — real balances, a bait token
with loose approvals. Believable enough that a drainer wants them."

**SHOT 2 (0:35–0:55) — Strike**
Visual: `python -m demo.strike` — the attacker address prints, the
max-approval tx lands.
Say: "A drainer — here honestly simulated — finds decoy-00 and does what
drainers do: max approval to its spender address."

**SHOT 3 (0:55–1:15) — Capture**
Visual: `python -m sentinel.trap watch --once` prints `[CAPTURE]`.
Say: "The trap listener sees the contact on-chain, fingerprints it:
approve selector, pattern hash, 95% confidence. First-party evidence —
not a blacklist, not a guess."

**SHOT 4 (1:15–1:35) — Verdict on-chain**
Visual: publish output with the NEAR tx hash; then the curl/rpc stats call
showing `total: 4`.
Say: "The verdict is published to a NEAR smart contract, with the evidence
transaction hash. Now it's public, tamper-proof threat intel."

**SHOT 5 (1:35–1:55) — Leash denies the attacker**
Visual: `DENY [blocklist]` line; caption "tx NEVER SIGNED".
Say: "Leash sits at the signing layer. Any agent that now tries to send
funds to this attacker is denied before a signature exists. A denied
transaction doesn't fail on-chain — it never exists."

**SHOT 6 (1:55–2:10) — Healthy agent flows**
Visual: `ALLOW — all checks passed`.
Say: "A normal agent under the exact same policy just flows. Security
that doesn't break the good ones."

**SHOT 7 (2:10–2:35) — Real Chain Signatures**
Visual: big_r / s / recovery_id from the live MPC network, request tx.
Say: "Signing itself goes through NEAR Chain Signatures — an 8-node MPC
network. The EVM key never exists outside it, so there's nothing for a
prompt injection to steal. GUARDDOG: learned from real attackers,
enforced where it can't be bypassed."

**SHOT 8 (2:35–2:50) — Outro**
Visual: GitHub repo screen.
Say: "Open source, fully replicable on testnets. Built for NEAR
HACKATHON. Link in the comments."
