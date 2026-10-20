"""Trap listener: watch Base Sepolia for hostile contact with the decoys.

Two capture paths:
  1. token logs (getLogs on the bait token) — approvals and transfers
  2. raw tx scan on latest blocks — ETH leaving decoys

Usage:
  venv/bin/python -m sentinel.trap watch --once   # single scan cycle
  venv/bin/python -m sentinel.trap watch --loop   # continuous daemon
  venv/bin/python -m sentinel.trap captures       # show recent captures
"""

import argparse
import sys
import time

from web3 import Web3

from . import config, db, fingerprint


def _decoy_set(state) -> set[str]:
    return {d["address"].lower() for d in state["decoys"]}


def _chunked_logs(w3: Web3, token: str, from_b: int, to_b: int, topics: list) -> list:
    """get_logs in ≤64-block windows — public RPCs 413 on large ranges."""
    logs = []
    step = 64
    a = from_b
    while a <= to_b:
        b = min(a + step - 1, to_b)
        logs += w3.eth.get_logs(
            {"fromBlock": a, "toBlock": b, "address": token, "topics": topics}
        )
        a = b + 1
    return logs


def _scan_token_logs(w3: Web3, state, last_block: int, decoys: set[str], token: str) -> tuple[int, int]:
    """Returns (new_captures, latest_block_scanned)."""
    latest = w3.eth.block_number
    if latest <= last_block:
        return 0, last_block
    approval_topic = "0x" + Web3.keccak(text="Approval(address,address,uint256)").hex()
    transfer_topic = "0x" + Web3.keccak(text="Transfer(address,address,uint256)").hex()
    logs = _chunked_logs(w3, token, last_block + 1, latest, [approval_topic, transfer_topic])
    new = 0
    for log in logs:
        # HexBytes.hex() returns bare hex (no 0x) — normalize explicitly
        topics = ["0x" + t.hex() for t in log["topics"]]
        tx_hash = "0x" + log["transactionHash"].hex()
        if topics[0] == approval_topic:
            owner = "0x" + topics[1][26:]
            spender = "0x" + topics[2][26:]
            if owner.lower() in decoys:
                kind = "approval"
                sig = fingerprint.decode_signature("0x095ea7b3")
                ph = fingerprint.pattern_hash("0x095ea7b3", kind, spender)
                if db.record_capture("base-sepolia", owner, spender, tx_hash, kind,
                                     "0x095ea7b3", sig, ph, fingerprint.score(kind, sig)):
                    new += 1
                    print(f"  [CAPTURE] approval {owner[:10]}…→ spender {spender[:10]}… tx {tx_hash[:16]}…")
        elif topics[0] == transfer_topic:
            src = "0x" + topics[1][26:]
            dst = "0x" + topics[2][26:]
            if src.lower() in decoys:
                kind = "token_out"
                sig = fingerprint.decode_signature("0xa9059cbb")
                ph = fingerprint.pattern_hash("0xa9059cbb", kind, dst)
                if db.record_capture("base-sepolia", src, dst, tx_hash, kind,
                                     "0xa9059cbb", sig, ph, fingerprint.score(kind, sig)):
                    new += 1
                    print(f"  [CAPTURE] token_out {src[:10]}…→ {dst[:10]}… tx {tx_hash[:16]}…")
    return new, latest


def _scan_eth_out(w3: Web3, state, last_block: int, decoys: set[str]) -> tuple[int, int]:
    """ETH-out capture is tail-limited: full-tx scans are heavy, so history is skipped
    on backfill (only the last 20 blocks get the deep scan)."""
    latest = w3.eth.block_number
    if latest <= last_block:
        return 0, last_block
    scan_from = max(last_block + 1, latest - 19)
    new = 0
    for bn in range(scan_from, latest + 1):
        if bn <= last_block:
            continue
        block = w3.eth.get_block(bn, full_transactions=True)
        for tx in block.transactions:
            frm = tx["from"].lower()
            if frm in decoys:
                kind = "eth_out"
                ph = fingerprint.pattern_hash(None, kind, tx["to"] or "")
                if db.record_capture("base-sepolia", frm, tx["to"] or "", tx.hash.hex(), kind,
                                     None, None, ph, fingerprint.score(kind, None)):
                    new += 1
                    print(f"  [CAPTURE] eth_out {frm[:10]}…→ {(tx['to'] or '')[:10]}… tx {tx.hash.hex()[:16]}…")
    return new, latest


def watch_once() -> int:
    db.init_db()
    w3 = Web3(Web3.HTTPProvider(config.BASE_SEPOLIA_RPC, request_kwargs={"timeout": 30}))
    state = __import__("sentinel.decoys", fromlist=["load_state"]).load_state()
    decoys = _decoy_set(state)
    last_block = state.get("last_scanned_block") or max(w3.eth.block_number - 500, 0)
    new_logs, last_block = _scan_token_logs(w3, state, last_block, decoys, state["token"])
    new_eth, last_block = _scan_eth_out(w3, state, last_block, decoys)
    state["last_scanned_block"] = last_block
    from . import decoys as decoys_mod

    decoys_mod.save_state(state["decoys"], extra={k: v for k, v in state.items() if k != "decoys"})
    total = new_logs + new_eth
    print(f"scan done: blocks →{last_block}, {total} new capture(s)")
    return total


def watch_loop(poll_s: int = 6):
    print(f"trap armed — polling every {poll_s}s, Ctrl-C to stop")
    while True:
        try:
            watch_once()
        except Exception as e:
            print(f"  scan error: {str(e)[:120]}")
        time.sleep(poll_s)


def show_captures():
    db.init_db()
    caps = db.list_captures()
    if not caps:
        print("no captures yet — bait untouched")
        return
    for c in caps:
        print(f"#{c['id']} {c['kind']:<10} conf={c['confidence']:.2f} "
              f"decoy={c['decoy_addr'][:10]}… attacker={c['attacker_addr'][:10]}… "
              f"sig={c['decoded_sig'] or '-'} pattern={c['pattern_hash']}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["watch", "captures"])
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--loop", action="store_true")
    args = ap.parse_args()
    if args.cmd == "watch":
        if args.loop:
            watch_loop()
        else:
            watch_once()
    else:
        show_captures()
