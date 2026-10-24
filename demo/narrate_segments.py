#!/usr/bin/env python3
"""Generate per-scene ElevenLabs narration and place each clip at the exact
timestamp of the matching UI action in raw5.mp4."""
import json, os, subprocess, time, urllib.request

# ElevenLabs key comes from the environment (never commit it)
EL_KEY = os.environ.get("ELEVENLABS_API_KEY") or os.environ.get("EL_KEY")
if not EL_KEY:
    raise SystemExit("Set ELEVENLABS_API_KEY (or EL_KEY) in the environment before running this script.")
VOICE = "JBFqnCBsd6RMkjVDRZzb"      # George — warm storyteller
MODEL = "eleven_turbo_v2_5"
OUT = "/home/ubuntu/guarddog/demo/video/nar"

os.makedirs(OUT, exist_ok=True)

SEGMENTS = [
    (0.5,  "Every AI agent that holds money is a target. Guarddog is the immune system that learns from real attackers. Here is how it works, live, on testnet."),
    (13.5, "Sentinel deploys bait wallets on Base Sepolia. Decoys with real balances and loose token approvals, so a real drainer has something to take."),
    (20.5, "When one strikes, the trap captures the contact on chain and fingerprints it. Selector, pattern, and confidence."),
    (26.0, "The verdict is published to a NEAR smart contract. First party evidence, not a static blacklist. Anyone can verify it on chain."),
    (30.0, "Now watch Leash, the firewall at the signing layer. It checks any address against the live policy engine, before a signature ever exists."),
    (36.5, "That attacker is on the blocklist. Denied. The transaction is never signed. It does not exist."),
    (45.0, "A clean address? Allowed. Same policy, same engine. Security without breaking the good ones."),
    (55.0, "Now the signing layer itself. NEAR Chain Signatures. An eight node MPC network produces the signature, so the private key never leaves the network."),
    (71.0, "Signature in fourteen seconds, signed by the network. There is nothing for prompt injection to steal."),
    (78.0, "Guarddog. Learned from real attackers. Enforced where it cannot be bypassed. Built for the NEAR Hackathon."),
]

def tts(text, path):
    body = json.dumps({
        "text": text,
        "model_id": MODEL,
        "voice_settings": {"stability": 0.45, "similarity_boost": 0.78, "style": 0.35},
    })
    req = urllib.request.Request(
        f"https://api.elevenlabs.io/v1/text-to-speech/{VOICE}",
        data=body.encode(),
        headers={"xi-api-key": EL_KEY, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=180) as r:
        data = r.read()
    open(path, "wb").write(data)
    dur = subprocess.run(["ffprobe","-v","error","-show_entries","format=duration","-of","csv=p=0",path],
                         capture_output=True, text=True).stdout.strip()
    return float(dur)

plan = []
for i, (start, text) in enumerate(SEGMENTS):
    p = f"{OUT}/seg{i:02d}.mp3"
    d = tts(text, p)
    print(f"seg{i:02d} start={start:5.1f}s dur={d:5.2f}s  {text[:52]}...")
    plan.append({"i": i, "start": start, "dur": d, "path": p, "text": text})
    time.sleep(0.4)

json.dump(plan, open(f"{OUT}/plan.json","w"), indent=2)
print("\nTOTAL narration:", round(sum(x["dur"] for x in plan), 2), "s")
