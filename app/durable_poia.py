"""SQLite-backed authorization state and local transactional execution."""

import json
import secrets
import time
from collections.abc import MutableMapping
from contextvars import ContextVar
from dataclasses import asdict
from functools import wraps

from .db import db_connect, transaction
from .model import InMemoryPoIA, IntentRecord, ChallengeRecord, ProofRecord

_batch = ContextVar("poia_execution_batch", default=None)


class RecordMap(MutableMapping):
    def __init__(self, kind, record_type):
        self.kind, self.record_type = kind, record_type

    def __getitem__(self, key):
        with db_connect() as conn:
            row = conn.execute("SELECT payload FROM poia_records WHERE kind=? AND record_id=?", (self.kind, key)).fetchone()
        if row is None:
            raise KeyError(key)
        expected = row["payload"]
        record = self.record_type(**json.loads(expected))

        def persist(value):
            nonlocal expected
            payload = json.dumps(asdict(value), sort_keys=True)
            with db_connect() as conn:
                count = conn.execute("UPDATE poia_records SET payload=? WHERE kind=? AND record_id=? AND payload=?",
                                     (payload, self.kind, key, expected)).rowcount
            if count != 1:
                raise RuntimeError("Authorization record changed concurrently; reload before retrying")
            expected = payload

        object.__setattr__(record, "_persist", persist)
        return record

    def __setitem__(self, key, value):
        with db_connect() as conn:
            conn.execute("INSERT INTO poia_records VALUES (?, ?, ?) ON CONFLICT(kind,record_id) DO UPDATE SET payload=excluded.payload",
                         (self.kind, key, json.dumps(asdict(value), sort_keys=True)))

    def __delitem__(self, key):
        with db_connect() as conn:
            count = conn.execute("DELETE FROM poia_records WHERE kind=? AND record_id=?", (self.kind, key)).rowcount
        if not count:
            raise KeyError(key)

    def __iter__(self):
        with db_connect() as conn:
            rows = conn.execute("SELECT record_id FROM poia_records WHERE kind=?", (self.kind,)).fetchall()
        return iter(row["record_id"] for row in rows)

    def __len__(self):
        with db_connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM poia_records WHERE kind=?", (self.kind,)).fetchone()[0]

    def clear(self):
        with db_connect() as conn:
            conn.execute("DELETE FROM poia_records WHERE kind=?", (self.kind,))

    # ---- bulk read paths -------------------------------------------------
    # items() on a MutableMapping calls __getitem__ once per key, and each of
    # those opens its own connection. Any caller that needs to filter across
    # the store therefore pays one round trip per record, over every record
    # ever written, on every request. These two helpers let such a caller do
    # the same work in a fixed number of queries. They are read-only: the
    # records returned carry no _persist callback, so a caller that intends to
    # mutate must re-read that record through __getitem__.

    def active_ids(self, json_path: str, threshold: float) -> list:
        """Record ids whose numeric JSON field is strictly above threshold.

        Ordered by record_id, matching the order __iter__ yields from the
        (kind, record_id) primary-key index, so callers that pick the first
        match keep selecting the same record they did before.
        """
        with db_connect() as conn:
            rows = conn.execute(
                "SELECT record_id FROM poia_records WHERE kind=? "
                "AND CAST(json_extract(payload, ?) AS REAL) > ? ORDER BY record_id",
                (self.kind, json_path, threshold),
            ).fetchall()
        return [row["record_id"] for row in rows]

    def fetch_many(self, keys) -> dict:
        """Read many records in one query per 500 keys. Read-only (see above)."""
        keys = list(keys)
        if not keys:
            return {}
        out = {}
        with db_connect() as conn:
            for start in range(0, len(keys), 500):
                chunk = keys[start:start + 500]
                placeholders = ",".join("?" * len(chunk))
                rows = conn.execute(
                    f"SELECT record_id, payload FROM poia_records "
                    f"WHERE kind=? AND record_id IN ({placeholders})",
                    (self.kind, *chunk),
                ).fetchall()
                for row in rows:
                    out[row["record_id"]] = self.record_type(**json.loads(row["payload"]))
        return out


class DurablePoIA(InMemoryPoIA):
    def __init__(self):
        super().__init__()
        self.intents = RecordMap("intent", IntentRecord)
        self.challenges = RecordMap("challenge", ChallengeRecord)
        self.proofs = RecordMap("proof", ProofRecord)

    def approve_proof(self, proof, now):
        with transaction():
            return super().approve_proof(proof, now)

    def reserve_execution(self, intent_id, principal_id, now, requested_intent_body=None):
        with transaction() as conn:
            result = super().reserve_execution(intent_id, principal_id, now, requested_intent_body)
            if result[0]:
                conn.execute("INSERT INTO poia_execution_journal VALUES (?, ?, ?, ?, NULL, 'reserved', NULL)",
                             (intent_id, _batch.get(), principal_id, now))
            return result


def atomic_execution(function):
    """Local DB writes, consumption, and audit commit or roll back together."""
    @wraps(function)
    def wrapped(*args, **kwargs):
        payload = kwargs.get("payload")
        if payload is None and args and isinstance(args[0], dict):
            payload = args[0]
        operation = payload.get("requested_intent", payload) if isinstance(payload, dict) else {}
        if isinstance(operation, dict) and operation.get("action") == "ledger_post":
            # A remote ledger is not part of the local SQLite transaction.
            return function(*args, **kwargs)
        batch = secrets.token_urlsafe(16)
        token = _batch.set(batch)
        try:
            with transaction() as conn:
                response = function(*args, **kwargs)
                reason = response.headers.get("X-PoIA-Rejection-Reason")
                rejected = reason is not None or response.status_code >= 400
                conn.execute("UPDATE poia_execution_journal SET completed_at=?, outcome=?, reason=? WHERE batch_id=?",
                             (time.time(), "rejected" if rejected else "executed", reason, batch))
                rows = conn.execute("SELECT intent_id,principal_id,outcome,reason FROM poia_execution_journal WHERE batch_id=?", (batch,)).fetchall()
                for row in rows:
                    conn.execute("INSERT INTO audit_logs (user_id,action,details,created_at) VALUES (?, 'poia_execution', ?, ?)",
                                 (row["principal_id"], json.dumps(dict(row), sort_keys=True), int(time.time())))
                return response
        finally:
            _batch.reset(token)
    return wrapped
