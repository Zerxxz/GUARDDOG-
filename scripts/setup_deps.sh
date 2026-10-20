#!/usr/bin/env bash
# GUARDDOG dependency setup — install core Python deps into project venv
set -e
cd /home/ubuntu/guarddog
venv/bin/pip install --quiet web3 python-dotenv httpx fastapi uvicorn "aiogram>=3" pytest pytest-asyncio
venv/bin/python -c "import web3, httpx, fastapi, aiogram, pytest; from web3 import Web3; print('web3', web3.__version__, '| all imports OK')"
