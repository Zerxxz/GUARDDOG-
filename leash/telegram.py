"""Leash Telegram owner-only alerting (T6).

Plain-HTTP Bot API — no aiogram runtime needed for one-way alerts. The bot
token lives in .env (TG_BOT_TOKEN); messages go ONLY to TG_OWNER_CHAT_ID.

send_deny / send_allow / send_capture / send_verdict are one-shot helpers
usable from any component; `notify_*` wrappers are no-ops when the token is
unset so local dev stays quiet.
"""

from __future__ import annotations

import os

import httpx

API = "https://api.telegram.org/bot{token}/sendMessage"


def _token() -> str | None:
    t = os.getenv("TG_BOT_TOKEN", "").strip()
    return t or None


def _chat() -> str | None:
    c = os.getenv("TG_OWNER_CHAT_ID", "").strip()
    return c or None


def send(text: str, token: str | None = None, chat_id: str | None = None) -> bool:
    """Fire-and-forget message to the owner chat. Returns True on success."""
    token = token or _token()
    chat_id = chat_id or _chat()
    if not token or not chat_id:
        return False
    try:
        r = httpx.post(
            API.format(token=token),
            json={"chat_id": chat_id, "text": text, "parse_mode": "HTML",
                  "disable_web_page_preview": True},
            timeout=15,
        )
        return r.status_code == 200 and r.json().get("ok") is True
    except Exception:
        return False


def notify_deny(rule: str, reason: str, to: str, value_eth: float) -> bool:
    return send(
        f"🚫 <b>LEASH DENY</b> [{rule}]\n"
        f"to: <code>{to}</code>\n"
        f"value: {value_eth} ETH\n{reason}"
    )


def notify_allow(to: str, value_eth: float, evm_tx: str | None = None) -> bool:
    extra = f"\ntx: <code>{evm_tx}</code>" if evm_tx else ""
    return send(
        f"✅ <b>LEASH ALLOW</b>\n"
        f"to: <code>{to}</code>\n"
        f"value: {value_eth} ETH{extra}"
    )


def notify_capture(kind: str, decoy: str, attacker: str, tx_hash: str,
                   confidence: float) -> bool:
    return send(
        f"🐕 <b>SENTINEL CAPTURE</b> [{kind}]\n"
        f"decoy: <code>{decoy}</code>\n"
        f"attacker: <code>{attacker}</code>\n"
        f"tx: <code>{tx_hash}</code>\n"
        f"confidence: {confidence:.0%}"
    )


def notify_verdict(verdict_id: str, chain: str, attacker: str,
                   near_tx: str) -> bool:
    return send(
        f"⛓️ <b>VERDICT ON-CHAIN</b> {verdict_id}\n"
        f"chain: {chain}\n"
        f"attacker: <code>{attacker}</code>\n"
        f"near tx: <code>{near_tx}</code>"
    )
