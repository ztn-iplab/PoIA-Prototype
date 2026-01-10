import secrets
import time
from typing import Optional

import sqlite3

from .db import db_connect
from .security import hash_reset_token
from .settings import RESET_TOKEN_TTL_SECONDS, SESSION_SECRET


def issue_reset_token(user_id: int, purpose: str) -> str:
    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_reset_token(raw_token, SESSION_SECRET)
    expires_at = int(time.time()) + RESET_TOKEN_TTL_SECONDS
    with db_connect() as conn:
        conn.execute(
            "UPDATE users SET reset_token_hash = ?, reset_token_expires = ?, reset_token_purpose = ? WHERE id = ?",
            (token_hash, expires_at, purpose, user_id),
        )
    return raw_token


def validate_reset_token(raw_token: str, purpose: str) -> Optional[sqlite3.Row]:
    if not raw_token:
        return None
    token_hash = hash_reset_token(raw_token, SESSION_SECRET)
    now = int(time.time())
    with db_connect() as conn:
        user = conn.execute(
            """
            SELECT * FROM users
            WHERE reset_token_hash = ? AND reset_token_purpose = ? AND reset_token_expires > ?
            """,
            (token_hash, purpose, now),
        ).fetchone()
    return user


def clear_reset_token(user_id: int) -> None:
    with db_connect() as conn:
        conn.execute(
            "UPDATE users SET reset_token_hash = NULL, reset_token_expires = NULL, reset_token_purpose = NULL WHERE id = ?",
            (user_id,),
        )
