"""MPC/Chain-Signatures constants and helpers shared by sentinel + leash."""

import os

MPC_CONTRACT = os.getenv("MPC_CONTRACT", "v1.signer-prod.testnet")

# Root MPC public key — verified live on-chain 2026-10-20 via the `public_key`
# view call on v1.signer-prod.testnet, cross-checked with docs.near.org.
MPC_PUBLIC_KEY = os.getenv(
    "MPC_PUBLIC_KEY",
    "secp256k1:4NfTiv3UsGahebgTaHyD9vF8KYKMBnfd6kh94mK6xv8fGBiJB8TBtFMP5WWXz6B89Ac1fbpzPwAvoyQebemHFwx3",
)
