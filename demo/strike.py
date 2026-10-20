"""Self-strike demo: simulate a drainer hitting a decoy (M1 test).

Loads decoy-00's bait key and sends the classic drainer MO: max approval of the
bait token to a fresh attacker address. The trap listener should capture this.
Testnet only, bait funds only.
"""

import sys

from eth_account import Account
from web3 import Web3

from sentinel import config
from sentinel.decoys import load_state

ERC20_APPROVE_ABI = [{
    "name": "approve",
    "type": "function",
    "inputs": [{"name": "spender", "type": "address"}, {"name": "amount", "type": "uint256"}],
    "outputs": [{"name": "", "type": "bool"}],
    "stateMutability": "nonpayable",
}]


def strike():
    state = load_state()
    decoy = state["decoys"][0]
    token_addr = state["token"]
    w3 = Web3(Web3.HTTPProvider(config.BASE_SEPOLIA_RPC, request_kwargs={"timeout": 30}))
    attacker = Account.create()
    print(f"attacker EOA: {attacker.address}")
    with open(decoy["keyfile"]) as f:
        bait = Account.from_key(__import__("json").load(f)["private_key"])
    print(f"bait victim : {bait.address} ({decoy['label']})")

    tok = w3.eth.contract(address=token_addr, abi=ERC20_APPROVE_ABI)
    tx = tok.functions.approve(attacker.address, 2**256 - 1).build_transaction({
        "from": bait.address,
        "nonce": w3.eth.get_transaction_count(bait.address),
        "gas": 60_000,
        "gasPrice": w3.eth.gas_price,
        "chainId": w3.eth.chain_id,
    })
    signed = bait.sign_transaction(tx)
    h = w3.eth.send_raw_transaction(signed.raw_transaction)
    rc = w3.eth.wait_for_transaction_receipt(h, timeout=180)
    assert rc.status == 1, "approve reverted"
    print(f"max-approval landed: tx {h.hex()}")
    print("→ trap listener should now capture this as a hostile approval")


if __name__ == "__main__":
    strike()
