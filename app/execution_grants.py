"""Single-use handoff from proof consumption to a protected GET endpoint."""

import hashlib
import secrets
import time

from .db import db_connect
from .intent_codec import canonical_json


def issue_grant(user_id, action, scope):
    token = secrets.token_urlsafe(32)
    with db_connect() as conn:
        conn.execute("DELETE FROM execution_grants WHERE expires_at <= ?", (time.time(),))
        conn.execute("INSERT INTO execution_grants VALUES (?, ?, ?, ?, ?)", (
            hashlib.sha256(token.encode()).hexdigest(), user_id, action,
            hashlib.sha256(canonical_json(scope)).hexdigest(), time.time() + 60,
        ))
    return token


def consume_grant(token, user_id, action, scope):
    if not token:
        return False
    with db_connect() as conn:
        return conn.execute(
            "DELETE FROM execution_grants WHERE token_hash=? AND user_id=? "
            "AND action=? AND scope_hash=? AND expires_at>?",
            (hashlib.sha256(token.encode()).hexdigest(), user_id, action,
             hashlib.sha256(canonical_json(scope)).hexdigest(), time.time()),
        ).rowcount == 1
