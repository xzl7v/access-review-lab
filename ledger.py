"""Save reviewed decisions and their evidence as local SQLite records."""

from contextlib import closing
from pathlib import Path
import sqlite3

from evidence import canonical_json, digest

DECISIONS = """
    CREATE TABLE IF NOT EXISTS decisions (
        case_id TEXT NOT NULL,
        recorded_at TEXT NOT NULL,
        case_json TEXT NOT NULL,
        PRIMARY KEY (case_id, recorded_at)
    )
"""
PACKETS = """
    CREATE TABLE IF NOT EXISTS evidence_packets (
        case_id TEXT NOT NULL,
        recorded_at TEXT NOT NULL,
        packet_sha256 TEXT NOT NULL,
        packet_json TEXT NOT NULL,
        PRIMARY KEY (case_id, recorded_at, packet_sha256),
        FOREIGN KEY (case_id, recorded_at) REFERENCES decisions(case_id, recorded_at)
    )
"""


def record_review(path: Path, packet: dict) -> None:
    case = packet["case"]
    key = (case["id"], case["decision"]["recorded_at"])
    case_json = canonical_json(case)
    path.parent.mkdir(parents=True, exist_ok=True)

    with closing(sqlite3.connect(path, timeout=10)) as connection, connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(DECISIONS)
        connection.execute(PACKETS)
        connection.execute("INSERT OR IGNORE INTO decisions VALUES (?, ?, ?)", (*key, case_json))
        [stored] = connection.execute(
            "SELECT case_json FROM decisions WHERE case_id = ? AND recorded_at = ?", key
        ).fetchone()
        if stored != case_json:
            raise ValueError("a different decision already uses this case ID and timestamp")
        connection.execute(
            "INSERT OR IGNORE INTO evidence_packets VALUES (?, ?, ?, ?)",
            (*key, digest(packet), canonical_json(packet)),
        )
