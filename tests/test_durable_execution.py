import json
import copy
import hashlib
import base64
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.responses import Response
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app import db
from app.durable_poia import DurablePoIA, atomic_execution
from app.model import IntentRecord, ChallengeRecord, ProofRecord
from app.settings import SESSION_SECRET


@pytest.fixture
def authorized():
    with tempfile.TemporaryDirectory() as directory, patch.object(db, "DB_PATH", Path(directory) / "bank.db"):
        db.init_db()
        with db.db_connect() as conn:
            conn.execute("INSERT INTO users (id,email,password_hash,created_at) VALUES (71,'durability@example.invalid','unused',0)")
            conn.execute("INSERT INTO accounts (id,user_id,account_type,balance,created_at) VALUES (81,71,'checking',1000,0)")
        store = DurablePoIA()
        store.intents["test-intent"] = IntentRecord("test-intent", {"action": "transfer", "scope": {"amount": 10}, "context": {"user_id": 71}}, time.time())
        store.challenges["test-intent"] = ChallengeRecord("test-intent", "nonce", time.time() + 120)
        store.proofs["test-intent"] = ProofRecord("test-intent", "preverified-test-fixture", "approved", "", 0)
        yield store


def executor(store, fault=False):
    @atomic_execution
    def execute():
        allowed, reason, _, _ = store.reserve_execution("test-intent", 71, time.time())
        if not allowed:
            return Response(status_code=409, headers={"X-PoIA-Rejection-Reason": reason})
        with db.db_connect() as conn:
            conn.execute("UPDATE accounts SET balance=balance-10 WHERE id=81")
            conn.execute("INSERT INTO audit_logs (user_id,action,details,created_at) VALUES (71,'transfer','durability test',0)")
        if fault:
            raise RuntimeError("injected failure after mutation and audit")
        return Response(status_code=200)
    return execute


def test_failure_rolls_back_consumption_state_and_audit(authorized):
    with pytest.raises(RuntimeError, match="injected failure"):
        executor(authorized, fault=True)()
    fresh = DurablePoIA()
    assert fresh.proofs["test-intent"].status == "approved"
    with db.db_connect() as conn:
        assert conn.execute("SELECT balance FROM accounts WHERE id=81").fetchone()[0] == 1000
        assert conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM poia_execution_journal").fetchone()[0] == 0
    assert executor(fresh)().status_code == 200


def test_restart_retains_consumption_and_completed_receipt(authorized):
    assert executor(authorized)().status_code == 200
    assert executor(DurablePoIA())().status_code == 409
    with db.db_connect() as conn:
        assert conn.execute("SELECT balance FROM accounts WHERE id=81").fetchone()[0] == 990
        row = conn.execute("SELECT outcome,completed_at FROM poia_execution_journal").fetchone()
        assert row["outcome"] == "executed" and row["completed_at"] is not None
        audit = conn.execute("SELECT details FROM audit_logs WHERE action='poia_execution'").fetchone()
        assert json.loads(audit[0])["intent_id"] == "test-intent"


def test_independent_stores_cannot_execute_same_proof_twice(authorized):
    barrier = threading.Barrier(2)
    statuses, errors = [], []
    def worker():
        try:
            barrier.wait(3)
            statuses.append(executor(DurablePoIA())().status_code)
        except Exception as error:
            errors.append(error)
    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(5)
        assert not thread.is_alive()
    assert not errors
    assert sorted(statuses) == [200, 409]


def test_stale_record_cannot_overwrite_consumed_proof(authorized):
    stale = authorized.proofs["test-intent"]
    assert executor(DurablePoIA())().status_code == 200
    with pytest.raises(RuntimeError, match="concurrently"):
        stale.status = "approved"
    assert DurablePoIA().proofs["test-intent"].status == "consumed"


def test_process_exit_before_commit_rolls_back(authorized):
    code = """
import os, time
from pathlib import Path
from app import db
from app.db import transaction
from app.durable_poia import DurablePoIA
db.DB_PATH = Path(os.environ['CRASH_TEST_DB'])
with transaction() as conn:
    assert DurablePoIA().reserve_execution('test-intent',71,time.time())[0]
    conn.execute('UPDATE accounts SET balance=balance-10 WHERE id=81')
    os._exit(17)
"""
    env = {**os.environ, "CRASH_TEST_DB": str(db.DB_PATH)}
    result = subprocess.run([sys.executable, "-c", code], env=env, timeout=10)
    assert result.returncode == 17
    assert DurablePoIA().proofs["test-intent"].status == "approved"
    with db.db_connect() as conn:
        assert conn.execute("SELECT balance FROM accounts WHERE id=81").fetchone()[0] == 1000


def test_http_executor_rolls_back_when_audit_write_fails(authorized):
    from app.core import create_poia_intent, poia_store
    from app.main import app
    from app.routes import banking
    intent_id = create_poia_intent(action="transfer", scope={"from_account": 81, "amount": 10.0,
        "currency": "USD", "external_account": "9007"}, context={"user_id": 71, "rp_id": "poia-demo-bank"})
    assert poia_store.approve_proof(ProofRecord(intent_id, "preverified-test-fixture", "pending", "", 0), time.time())[0]
    with TestClient(app, base_url="https://testserver", raise_server_exceptions=False) as client:
        session = base64.b64encode(json.dumps({"user_id": 71}).encode())
        client.cookies.set("session", TimestampSigner(SESSION_SECRET).sign(session).decode())
        with patch.object(banking, "log_audit", side_effect=RuntimeError("audit storage unavailable")):
            response = client.get(f"/poia/execute/{intent_id}")
        assert response.status_code == 500
        assert DurablePoIA().proofs[intent_id].status == "approved"
        with db.db_connect() as conn:
            assert conn.execute("SELECT count(*) FROM transactions").fetchone()[0] == 0
            assert conn.execute("SELECT balance FROM accounts WHERE id=81").fetchone()[0] == 1000
        assert client.get(f"/poia/execute/{intent_id}").status_code == 200
        assert client.get(f"/poia/execute/{intent_id}").status_code == 409


@pytest.mark.parametrize("mutation", [None, "amount", "external_account", "currency"])
def test_real_p256_approval_and_http_execution(authorized, mutation):
    """Software signing tests the server path, not a phone or human approval."""
    from app.core import create_poia_intent, poia_store, build_proof_payload
    from app.main import app
    from app.routes import poia

    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    with db.db_connect() as conn:
        conn.execute("INSERT INTO devices VALUES (91,71,'Test signer','test',0)")
        conn.execute("INSERT INTO device_keys VALUES (1,91,'poia-demo-bank','p256',?,0)",
                     (base64.b64encode(public).decode(),))
    intent_id = create_poia_intent(action="transfer", scope={"from_account": 81,
        "amount": 10.0, "currency": "USD", "external_account": "9007"},
        context={"user_id": 71, "rp_id": "poia-demo-bank"})
    body = poia_store.intents[intent_id].intent_body
    challenge = poia_store.challenges[intent_id]
    digest = hashlib.sha256(build_proof_payload(body, challenge.nonce, challenge.expires_at)).hexdigest()
    message = f"{challenge.nonce}|91|poia-demo-bank|poia-approve:{digest}".encode()
    signature = base64.b64encode(key.sign(message, ec.ECDSA(hashes.SHA256()))).decode()
    approval = {"intent_id": intent_id, "device_id": 91, "rp_id": "poia-demo-bank",
                "nonce": challenge.nonce, "intent_hash": digest, "signature": signature}
    with TestClient(app, base_url="https://testserver") as client, patch.object(poia, "POIA_EXPERIMENT_MODE", True):
        session = base64.b64encode(json.dumps({"user_id": 71}).encode())
        client.cookies.set("session", TimestampSigner(SESSION_SECRET).sign(session).decode())
        forged = {**approval, "signature": base64.b64encode(b"invalid signature").decode()}
        response = client.post("/api/poia/approve", json=forged)
        assert response.status_code == 400 and response.json()["reason"] == "invalid_signature"
        assert poia_store.proofs[intent_id].status == "pending"
        assert client.post("/api/poia/approve", json=approval).status_code == 200
        requested = copy.deepcopy(body)
        if mutation:
            requested["scope"][mutation] = {"amount": 11.0, "external_account": "7781", "currency": "EUR"}[mutation]
        response = client.post("/api/poia/experiment/execute",
                               json={"intent_id": intent_id, "requested_intent": requested})
        assert response.status_code == (400 if mutation else 200)
        if mutation:
            assert response.json()["reason"] == "scope_mismatch"
            assert poia_store.proofs[intent_id].status == "approved"
        with db.db_connect() as conn:
            assert conn.execute("SELECT balance FROM accounts WHERE id=81").fetchone()[0] == (1000 if mutation else 990)
            assert conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0] == (0 if mutation else 1)
        if not mutation:
            assert client.post("/api/poia/approve", json=approval).status_code == 409
            assert client.get(f"/poia/execute/{intent_id}").status_code == 409


def test_remote_commit_lost_response_and_restart_retry(authorized, tmp_path, monkeypatch):
    from app.core import create_poia_intent, poia_store
    from app.downstream_client import DownstreamClient
    from app.remote_execution import execute_remote
    from downstream import main as ledger
    from downstream.security import sign_service_request

    monkeypatch.setattr(ledger, "DB_PATH", tmp_path / "ledger.db")
    monkeypatch.setattr(ledger, "SHARED_SECRET", "isolated-test-secret")
    ledger.init_db()
    client = DownstreamClient()
    client.secret = ledger.SHARED_SECRET
    intent_id = create_poia_intent(action="ledger_post", scope={"object_id": "item", "amount": 10},
        context={"user_id": 71, "rp_id": "poia-ledger", "on_behalf_of": "person-71"})
    assert poia_store.approve_proof(ProofRecord(intent_id, "preverified-test-fixture", "pending", "", 0), time.time())[0]
    body = poia_store.intents[intent_id].intent_body
    calls = []
    with TestClient(ledger.app) as http:
        def post(path, payload):
            timestamp = str(int(time.time()))
            response = http.post(path, json=payload, headers={"X-PoIA-Service-Id": ledger.SERVICE_ID,
                "X-PoIA-Service-Timestamp": timestamp,
                "X-PoIA-Service-Signature": sign_service_request(client.secret, timestamp, payload)})
            calls.append(response.status_code)
            if len(calls) == 1:
                return 503, {"reason": "injected_lost_response"}
            return response.status_code, response.json()
        monkeypatch.setattr(client, "_post", post)
        assert execute_remote(poia_store, client, intent_id, 71, body).status_code == 503
        assert ledger.state_for("person-71")["entry_count"] == 1
        assert execute_remote(DurablePoIA(), client, intent_id, 71, body).status_code == 200
        assert execute_remote(DurablePoIA(), client, intent_id, 71, body).status_code == 200
        assert calls == [201, 200]
        assert ledger.state_for("person-71")["entry_count"] == 1
        changed = copy.deepcopy(body)
        changed["scope"]["amount"] = 99
        assert execute_remote(DurablePoIA(), client, intent_id, 71, changed).status_code == 409
        with db.db_connect() as conn:
            assert conn.execute("SELECT outcome FROM poia_execution_journal WHERE intent_id=?", (intent_id,)).fetchone()[0] == "executed"
