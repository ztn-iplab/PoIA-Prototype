"""Durable, retryable delivery; not a distributed atomic transaction."""
import json
import time

from fastapi.responses import JSONResponse

from .db import transaction
from .model import canonical_json, intent_mismatch_reason


def execute_remote(store, client, intent_id, principal_id, requested):
    encoded = canonical_json(requested).decode()
    with transaction() as conn:
        job = conn.execute("SELECT * FROM poia_remote_jobs WHERE intent_id=?", (intent_id,)).fetchone()
        if job:
            if job["principal_id"] != principal_id or job["body"] != encoded:
                return JSONResponse(status_code=409, content={"status": "denied", "reason": "retry_binding_mismatch"})
            if job["status"] != "pending":
                return JSONResponse(status_code=job["http_status"], content=json.loads(job["response"]))
        else:
            record = store.intents.get(intent_id)
            reason = intent_mismatch_reason(record.intent_body, requested) if record else "intent_invalid"
            if requested.get("context", {}).get("workflow_id"):
                reason = "remote_workflow_unsupported"
            if reason:
                return JSONResponse(status_code=400, content={"status": "denied", "reason": reason})
            allowed, reason, _, _ = store.reserve_execution(intent_id, principal_id, time.time(), requested)
            if not allowed:
                return JSONResponse(status_code=409, content={"status": "denied", "reason": reason})
            conn.execute("INSERT INTO poia_remote_jobs VALUES (?,?,?,'pending',NULL,NULL)",
                         (intent_id, principal_id, encoded))

    # Never hold the bank's writer lock while waiting for a remote service.
    status, body = client.post_ledger_entry(requested, intent_id)
    accepted = status in (200, 201) and body.get("status") == "accepted" and body.get("proof_id") == intent_id
    if not accepted and status not in (400, 401, 403, 409, 422):
        return JSONResponse(status_code=503, content={"status": "pending", "reason": "remote_outcome_unknown"})
    with transaction() as conn:
        updated = conn.execute("UPDATE poia_remote_jobs SET status=?,response=?,http_status=? WHERE intent_id=? AND status='pending'",
                               ("executed" if accepted else "rejected", json.dumps(body), status, intent_id)).rowcount
        if updated:
            outcome = "executed" if accepted else "rejected"
            reason = None if accepted else body.get("reason", "downstream_denied")
            conn.execute("UPDATE poia_execution_journal SET outcome=?,reason=?,completed_at=? WHERE intent_id=?",
                         (outcome, reason, time.time(), intent_id))
            conn.execute("INSERT INTO audit_logs (user_id,action,details,created_at) VALUES (?,'poia_remote_execution',?,?)",
                         (principal_id, json.dumps({"intent_id": intent_id, "outcome": outcome, "reason": reason}), int(time.time())))
        job = conn.execute("SELECT response,http_status FROM poia_remote_jobs WHERE intent_id=?", (intent_id,)).fetchone()
        return JSONResponse(status_code=job["http_status"], content=json.loads(job["response"]))
