from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .security import canonical_json, verify_attestation, verify_service_request

# Namespaced by uid rather than a bare "/tmp/poia-downstream": /tmp is
# world-writable on a shared host, so a fixed, predictable path there is
# susceptible to symlink/pre-creation races by another local user. This
# default is only ever used outside the container -- compose.yaml sets
# POIA_DOWNSTREAM_DATA_DIR explicitly for real deployments -- but a
# non-container default under the module's own directory isn't a safe
# substitute either: it can land inside a synced/mounted checkout where
# sqlite3 refuses to open a database file (mount-specific I/O restrictions).
DATA_DIR = Path(
    os.getenv(
        "POIA_DOWNSTREAM_DATA_DIR",
        str(Path(tempfile.gettempdir()) / f"poia-downstream-{os.getuid()}"),
    )
)
DB_PATH = DATA_DIR / "ledger.db"
SERVICE_ID = os.getenv("POIA_DOWNSTREAM_SERVICE_ID", "poia-bank")
SHARED_SECRET = os.getenv("POIA_DOWNSTREAM_SECRET", "")
REQUIRE_POIA = os.getenv("POIA_DOWNSTREAM_REQUIRE_POIA", "true").lower() == "true"
MAX_CLOCK_SKEW_SECONDS = 30

app = FastAPI(title="PoIA Track A Downstream Ledger")


class LedgerConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    conn = sqlite3.connect(DB_PATH, factory=LedgerConnection)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS ledger_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT UNIQUE NOT NULL,
                principal TEXT NOT NULL,
                object_id TEXT NOT NULL,
                amount REAL NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ledger_receipts (
                proof_id TEXT PRIMARY KEY,
                request_id TEXT UNIQUE NOT NULL,
                body_hash TEXT NOT NULL,
                response TEXT NOT NULL
            );
            """
        )


def state_for(principal: str) -> Dict[str, Any]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT request_id, object_id, amount FROM ledger_entries "
            "WHERE principal = ? ORDER BY id",
            (principal,),
        ).fetchall()
    entries = [dict(row) for row in rows]
    return {
        "principal_hash": hashlib.sha256(principal.encode("utf-8")).hexdigest(),
        "entry_count": len(entries),
        "digest": hashlib.sha256(canonical_json({"entries": entries})).hexdigest(),
    }


async def authenticate_service(request: Request) -> Tuple[Optional[Dict[str, Any]], Optional[JSONResponse]]:
    if not SHARED_SECRET:
        return None, JSONResponse(
            status_code=503, content={"status": "denied", "reason": "service_not_configured"}
        )
    try:
        body = await request.json()
    except Exception:
        return None, JSONResponse(
            status_code=400, content={"status": "denied", "reason": "invalid_json"}
        )
    if not isinstance(body, dict):
        return None, JSONResponse(status_code=400, content={"status": "denied", "reason": "invalid_json_object"})
    service_id = request.headers.get("x-poia-service-id", "")
    timestamp = request.headers.get("x-poia-service-timestamp", "")
    signature = request.headers.get("x-poia-service-signature", "")
    try:
        request_time = int(timestamp)
    except ValueError:
        request_time = 0
    if service_id != SERVICE_ID:
        return None, JSONResponse(
            status_code=401, content={"status": "denied", "reason": "service_identity_mismatch"}
        )
    if abs(int(time.time()) - request_time) > MAX_CLOCK_SKEW_SECONDS:
        return None, JSONResponse(
            status_code=401, content={"status": "denied", "reason": "service_request_expired"}
        )
    if not verify_service_request(SHARED_SECRET, timestamp, body, signature):
        return None, JSONResponse(
            status_code=401, content={"status": "denied", "reason": "service_signature_invalid"}
        )
    return body, None


def validate_poia(body: Dict[str, Any]) -> Optional[str]:
    attestation = body.get("poia_attestation")
    if not isinstance(attestation, dict):
        return "poia_attestation_missing"
    claims = attestation.get("claims")
    signature = attestation.get("signature")
    if not isinstance(claims, dict) or not isinstance(signature, str):
        return "poia_attestation_invalid"
    if not verify_attestation(SHARED_SECRET, claims, signature):
        return "poia_attestation_invalid"
    for field in ("action", "scope", "context", "request_id"):
        if claims.get(field) != body.get(field):
            return f"attested_{field}_mismatch"
    context = body.get("context", {})
    if not context.get("on_behalf_of"):
        return "delegation_missing"
    if claims.get("intent_hash") in (None, ""):
        return "intent_hash_missing"
    if not isinstance(claims.get("proof_id"), str) or not claims["proof_id"]:
        return "proof_id_missing"
    return None


@app.post("/ledger/state")
async def ledger_state(request: Request) -> JSONResponse:
    body, error = await authenticate_service(request)
    if error is not None:
        return error
    if body is None:
        # Unreachable given authenticate_service's contract (error is None iff
        # body is not None); guard explicitly rather than with `assert`, which
        # is stripped under `python -O` and would otherwise raise a bare
        # AttributeError below instead of failing predictably.
        return JSONResponse(status_code=500, content={"status": "denied", "reason": "internal_error"})
    principal = str(body.get("principal") or "")
    if not principal:
        return JSONResponse(
            status_code=400, content={"status": "denied", "reason": "principal_missing"}
        )
    return JSONResponse(content={"status": "ok", "state": state_for(principal)})


@app.post("/ledger/entries")
async def ledger_entry(request: Request) -> JSONResponse:
    body, error = await authenticate_service(request)
    if error is not None:
        return error
    if body is None:
        return JSONResponse(status_code=500, content={"status": "denied", "reason": "internal_error"})
    if not isinstance(body.get("context"), dict) or not isinstance(body.get("scope"), dict):
        return JSONResponse(status_code=400, content={"status": "denied", "reason": "invalid_ledger_request"})
    if REQUIRE_POIA:
        reason = validate_poia(body)
        if reason is not None:
            return JSONResponse(status_code=403, content={"status": "denied", "reason": reason})
    if body.get("action") != "ledger_post":
        return JSONResponse(
            status_code=400, content={"status": "denied", "reason": "action_not_allowed"}
        )
    context = body.get("context", {})
    scope = body.get("scope", {})
    principal = str(context.get("on_behalf_of") or "")
    request_id = str(body.get("request_id") or "")
    object_id = str(scope.get("object_id") or "")
    try:
        amount = float(scope.get("amount"))
    except (TypeError, ValueError):
        amount = -1.0
    if not principal or not request_id or not object_id or isinstance(scope.get("amount"), bool) or not math.isfinite(amount) or amount <= 0:
        return JSONResponse(
            status_code=400, content={"status": "denied", "reason": "invalid_ledger_request"}
        )
    try:
        with connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            proof_id = body.get("poia_attestation", {}).get("claims", {}).get("proof_id")
            body_hash = hashlib.sha256(canonical_json(body)).hexdigest()
            if proof_id:
                receipt = conn.execute("SELECT * FROM ledger_receipts WHERE proof_id=? OR request_id=?",
                                       (proof_id, request_id)).fetchone()
                if receipt:
                    if receipt["proof_id"] != proof_id or receipt["request_id"] != request_id or receipt["body_hash"] != body_hash:
                        return JSONResponse(status_code=409, content={"status": "denied", "reason": "idempotency_conflict"})
                    return JSONResponse(status_code=200, content=json.loads(receipt["response"]))
            conn.execute(
                "INSERT INTO ledger_entries "
                "(request_id, principal, object_id, amount, created_at) VALUES (?, ?, ?, ?, ?)",
                (request_id, principal, object_id, amount, int(time.time())),
            )
            result = {"status": "accepted", "request_id": request_id, "proof_id": proof_id}
            if proof_id:
                conn.execute("INSERT INTO ledger_receipts VALUES (?,?,?,?)",
                             (proof_id, request_id, body_hash, json.dumps(result, sort_keys=True)))
    except sqlite3.IntegrityError:
        return JSONResponse(
            status_code=409, content={"status": "denied", "reason": "downstream_replay"}
        )
    return JSONResponse(
        status_code=201,
        content=result,
    )


init_db()
