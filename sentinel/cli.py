"""Sentinel operator CLI — setup, list, fund, and arm decoys (T3/M1).

Usage:
  venv/bin/python -m sentinel.cli setup   # generate decoys + deploy bait token + fund
  venv/bin/python -m sentinel.cli list    # show decoys and their live balances
"""

import sys

from web3 import Web3

from . import config, decoys, token as token_mod


def cmd_setup():
    import os

    if os.path.exists(decoys.STATE_FILE):
        print("state.json already exists — setup is idempotent, aborting to avoid double-deploy.")
        print("delete decoys/state.json to re-run intentionally.")
        sys.exit(1)

    w3 = Web3(Web3.HTTPProvider(config.BASE_SEPOLIA_RPC, request_kwargs={"timeout": 30}))
    assert w3.is_connected(), "RPC not reachable"
    operator = config.operator_account()
    print(f"operator: {operator.address} | balance: {Web3.from_wei(w3.eth.get_balance(operator.address), 'ether')} ETH")

    print("generating decoys...")
    batch = decoys.generate_batch(config.DECOY_COUNT)
    nonce = w3.eth.get_transaction_count(operator.address)
    token_addr, txh, nonce = token_mod.deploy_token(w3, operator, batch[0].address, nonce=nonce)
    print(f"GULL token: {token_addr} (deploy tx {txh[:20]}...)")

    fund_amt = Web3.to_wei(config.DECOY_FUND_ETH, "ether")
    for i, d in enumerate(batch):
        tx = {
            "to": d.address,
            "value": fund_amt,
            "from": operator.address,
            "nonce": nonce + i,
            "gas": 21_000,
            "gasPrice": w3.eth.gas_price,
            "chainId": w3.eth.chain_id,
        }
        signed = operator.sign_transaction(tx)
        h = w3.eth.send_raw_transaction(signed.raw_transaction)
        rc = w3.eth.wait_for_transaction_receipt(h, timeout=180)
        assert rc.status == 1, f"fund tx failed for {d.address}"
        d.funded_eth = config.DECOY_FUND_ETH
        print(f"  {d.label}: {d.address} funded {config.DECOY_FUND_ETH} ETH")

    decoys.save_state(batch, extra={"token": token_addr, "chain": "base-sepolia"})
    print("state saved to decoys/state.json — decoys are LIVE")


def cmd_list():
    state = decoys.load_state()
    w3 = Web3(Web3.HTTPProvider(config.BASE_SEPOLIA_RPC, request_kwargs={"timeout": 30}))
    for d in state["decoys"]:
        bal = w3.eth.get_balance(d["address"])
        print(f"{d['label']:>12} {d['address']}  {Web3.from_wei(bal, 'ether')} ETH")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "setup":
        cmd_setup()
    elif cmd == "list":
        cmd_list()
    else:
        print(__doc__)
        sys.exit(1)
