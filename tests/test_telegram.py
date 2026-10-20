"""Unit tests for the Telegram notifier — offline (token unset = no-op)."""

from leash import telegram


def test_send_without_token_is_safe_noop(monkeypatch):
    monkeypatch.setenv("TG_BOT_TOKEN", "")
    monkeypatch.setenv("TG_OWNER_CHAT_ID", "")
    assert telegram.send("hello") is False
    assert telegram.notify_deny("blocklist", "bad addr", "0xDEAD", 0.1) is False


def test_send_with_bad_token_returns_false(monkeypatch):
    monkeypatch.setenv("TG_BOT_TOKEN", "123:invalid")
    monkeypatch.setenv("TG_OWNER_CHAT_ID", "1")
    # httpx will hit the real API with an invalid token → 401 → False
    assert telegram.send("hello") is False
