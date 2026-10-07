"""Append-only referent journal: the second commitment root's own data path.

Root A reads the current-state tables (``beneficiaries``, ``accounts``) in the
primary database. This module maintains a physically separate, append-only
journal of referent mutations in its own SQLite file, from which the current
content of a referent is reconstructed as its highest-version entry.

The point is sourcing, not storage. Two functions that read the same row cannot
disagree when that row is corrupted, so agreement between them is a check on
read-path defects, not on compromise of the source. A root reading a different
physical store, in a different process, under a different credential, can still
report the honest value when the primary row is rewritten -- and that is what
``k``-of-``n`` Independent Commitment Confinement assumes.

Writes are additive: nothing is ever updated or deleted. They are *not* part of
the primary mutation's transaction, because a separate store cannot join a
SQLite transaction on another file. A crash between the two commits therefore
leaves the journal one version behind. That skew is safe in the direction that
matters: Root B then reports the older content, the two roots disagree, and the
gate refuses to commit a new intent until the journal catches up. Availability
is lost, authorization is not. A deployment needing both would put the journal
in a store that can participate in the same commit, or have the referent's
owning service write both under a single conditional write.

Nothing here is read by Root A, and the service that reads it never opens the
primary database.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Optional

from .settings import DATA_DIR

JOURNAL_PATH = Path(
    os.getenv("POIA_REFERENT_JOURNAL_PATH", str(DATA_DIR / "referent_journal.db"))
)

JOURNAL_ENABLED = os.getenv("POIA_REFERENT_JOURNAL_ENABLED", "false").lower() == "true"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS referent_journal (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    referent_type  TEXT    NOT NULL,
    referent_id    INTEGER NOT NULL,
    version        INTEGER NOT NULL,
    content_json   TEXT    NOT NULL,
    recorded_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_referent_journal_lookup
    ON referent_journal (referent_type, referent_id, version);
"""


def journal_connect(*, read_only: bool = False) -> sqlite3.Connection:
    """Open the journal. Root B's service always passes read_only=True, so a
    compromise of that process cannot rewrite the history it reads from."""
    path = Path(JOURNAL_PATH)
    if read_only:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_journal() -> None:
    with journal_connect() as conn:
        conn.executescript(_SCHEMA)


def append(
    referent_type: str,
    referent_id: int,
    version: int,
    content: Dict[str, Any],
    *,
    recorded_at: Optional[int] = None,
) -> None:
    """Record a referent's content at a version. Never updates or deletes."""
    if not JOURNAL_ENABLED:
        return
    init_journal()
    with journal_connect() as conn:
        conn.execute(
            "INSERT INTO referent_journal "
            "(referent_type, referent_id, version, content_json, recorded_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                referent_type,
                int(referent_id),
                int(version),
                json.dumps(content, sort_keys=True, separators=(",", ":")),
                int(recorded_at if recorded_at is not None else time.time()),
            ),
        )
        conn.commit()


_BENEFICIARY_FIELDS = ("name", "bank", "account_number")
_ACCOUNT_FIELDS = ("user_id", "status", "daily_transfer_limit")


def record_beneficiary(conn, beneficiary_id: int) -> None:
    """Journal a beneficiary's current content. Call after the primary write."""
    if not JOURNAL_ENABLED:
        return
    row = conn.execute(
        "SELECT * FROM beneficiaries WHERE id = ?", (beneficiary_id,)
    ).fetchone()
    if row is None:
        return
    append(
        "beneficiary",
        beneficiary_id,
        row["version"],
        {field: row[field] for field in _BENEFICIARY_FIELDS},
    )


def record_account(conn, account_id: int) -> None:
    """Journal an account's current content. Call after the primary write."""
    if not JOURNAL_ENABLED:
        return
    row = conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
    if row is None:
        return
    append(
        "account",
        account_id,
        row["version"],
        {field: row[field] for field in _ACCOUNT_FIELDS},
    )


def reconstruct(referent_type: str, referent_id: int) -> Optional[Dict[str, Any]]:
    """Current content of a referent, as the highest version the journal holds.

    Returns None when the journal has never seen the referent -- the caller must
    treat that as a failure to source the value, not as an empty value.
    """
    try:
        with journal_connect(read_only=True) as conn:
            row = conn.execute(
                "SELECT version, content_json FROM referent_journal "
                "WHERE referent_type = ? AND referent_id = ? "
                "ORDER BY version DESC, seq DESC LIMIT 1",
                (referent_type, int(referent_id)),
            ).fetchone()
    except sqlite3.Error:
        return None
    if row is None:
        return None
    content = json.loads(row["content_json"])
    content["version"] = row["version"]
    return content
