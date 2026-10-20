"""SQLite event store for captures and verdicts."""

import os
import sqlite3
import time

DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sentinel", "events.db"
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS captures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    chain TEXT NOT NULL,
    decoy_addr TEXT NOT NULL,
    attacker_addr TEXT NOT NULL,
    tx_hash TEXT NOT NULL,
    kind TEXT NOT NULL,            -- approval | token_out | eth_out
    selector TEXT,
    decoded_sig TEXT,
    pattern_hash TEXT NOT NULL,
    confidence REAL NOT NULL,
    UNIQUE(tx_hash, kind)
);
CREATE TABLE IF NOT EXISTS verdicts (
    id TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    capture_id INTEGER REFERENCES captures(id),
    near_tx_hash TEXT
);
CREATE TABLE IF NOT EXISTS bait_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    caller_ip TEXT NOT NULL,
    user_agent TEXT,
    method TEXT NOT NULL,
    params_digest TEXT
);
"""


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with connect() as conn:
        conn.executescript(SCHEMA)


def record_capture(chain, decoy_addr, attacker_addr, tx_hash, kind, selector,
                   decoded_sig, pattern_hash, confidence) -> int | None:
    """Insert a capture. Returns row id, or None if this tx/kind was already recorded."""
    with connect() as conn:
        cur = conn.execute(
            """INSERT OR IGNORE INTO captures
               (ts, chain, decoy_addr, attacker_addr, tx_hash, kind, selector,
                decoded_sig, pattern_hash, confidence)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (time.time(), chain, decoy_addr.lower(), attacker_addr.lower(),
             tx_hash, kind, selector, decoded_sig, pattern_hash, confidence),
        )
        return cur.lastrowid if cur.rowcount else None


def list_captures(limit=20):
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM captures ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def record_bait_request(ts, caller_ip, user_agent, method, params_digest) -> int:
    """Insert a fake-RPC contact row (T12). Never raises into the request path."""
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO bait_requests (ts, caller_ip, user_agent, method, params_digest)"
            " VALUES (?,?,?,?,?)",
            (ts, caller_ip, user_agent, method, params_digest),
        )
        return cur.lastrowid


def list_bait_requests(limit=50):
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM bait_requests ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
