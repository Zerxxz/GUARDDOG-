"""Compile + deploy GullibleToken (honeypot bait ERC20) on Base Sepolia."""

from __future__ import annotations

import os

from web3 import Web3

from . import config

SOL_VERSION = "0.8.24"
CONTRACTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "contracts")


def ensure_solc():
    import solcx

    try:
        solcx.set_solc_version(SOL_VERSION)
    except Exception:
        solcx.install_solc(SOL_VERSION)
        solcx.set_solc_version(SOL_VERSION)
    return solcx


def compile_token():
    solcx = ensure_solc()
    return solcx.compile_source(
        open(os.path.join(CONTRACTS_DIR, "GullibleToken.sol")).read(),
        output_values=["abi", "bin"],
        solc_version=SOL_VERSION,
    )


def deploy_token(w3: Web3, operator, mint_to: str, amount_eth=1000.0, nonce: int | None = None):
    """Deploy the bait token, mint bait balance to mint_to. Returns (address, tx_hash, last_nonce).

    nonce management is caller-owned (public RPCs lag on get_transaction_count after a
    broadcast — same-nonce resubmits read as underpriced replacements).
    """
    compiled = compile_token()
    _key, iface = next(iter(compiled.items()))
    abi, bytecode = iface["abi"], iface["bin"]

    if nonce is None:
        nonce = w3.eth.get_transaction_count(operator.address)

    token = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx = token.constructor().build_transaction(
        {
            "from": operator.address,
            "nonce": nonce,
            "gas": 1_500_000,
            "gasPrice": w3.eth.gas_price,
            "chainId": w3.eth.chain_id,
        }
    )
    signed = operator.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
    assert receipt.status == 1, "token deployment reverted"

    addr = receipt.contractAddress
    tok = w3.eth.contract(address=addr, abi=abi)
    amount = Web3.to_wei(amount_eth, "ether")
    mt = tok.functions.mint(mint_to, amount).build_transaction(
        {
            "from": operator.address,
            "nonce": nonce + 1,
            "gas": 120_000,
            "gasPrice": w3.eth.gas_price,
            "chainId": w3.eth.chain_id,
        }
    )
    signed = operator.sign_transaction(mt)
    mt_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    mrc = w3.eth.wait_for_transaction_receipt(mt_hash, timeout=180)
    assert mrc.status == 1, "mint reverted"
    return addr, tx_hash.hex(), nonce + 2

