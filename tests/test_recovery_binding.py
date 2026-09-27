import base64
import json
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner

from app import db
from app.main import app
from app.reset import issue_reset_token, validate_reset_token
from app.security import hash_password, verify_password
from app.settings import SESSION_SECRET
from app.execution_grants import issue_grant, consume_grant


@pytest.fixture
def recovery_users():
    with tempfile.TemporaryDirectory() as directory, patch.object(db, "DB_PATH", Path(directory) / "bank.db"):
        db.init_db()
        ids = []
        with db.db_connect() as conn:
            for name in ("owner", "other"):
                ids.append(conn.execute(
                    "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
                    (f"{name}@example.invalid", hash_password("Original-Test-123!"), int(time.time())),
                ).lastrowid)
        yield ids


def client_with_approval(user, purpose="password", expires_at=None):
    # Seed the exact session state created after a successful owner assertion.
    session = {"reset_webauthn_approval": {
        "user_id": user["id"], "purpose": purpose,
        "token_hash": user["reset_token_hash"],
        "expires_at": expires_at if expires_at is not None else time.time() + 120,
    }}
    client = TestClient(app, base_url="https://testserver")
    cookie = TimestampSigner(SESSION_SECRET).sign(base64.b64encode(json.dumps(session).encode())).decode()
    client.cookies.set("session", cookie)
    return client


@pytest.mark.parametrize("case", ["other_account", "expired", "reissued", "wrong_purpose", "valid"])
def test_password_recovery_is_bound(recovery_users, case):
    owner, other = recovery_users
    token = issue_reset_token(owner, "password")
    user = validate_reset_token(token, "password")
    client = client_with_approval(user, "totp" if case == "wrong_purpose" else "password",
                                  time.time() - 1 if case == "expired" else None)
    target = other if case == "other_account" else owner
    if case in {"other_account", "reissued"}:
        token = issue_reset_token(target, "password")
    client.post("/reset-password", data={"token": token, "password": "Changed-Test-456!",
                "confirm_password": "Changed-Test-456!"}, follow_redirects=False)
    with db.db_connect() as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE id = ?", (target,)).fetchone()
    assert verify_password("Changed-Test-456!", row["password_hash"]) is (case == "valid")
    client.close()


def test_reset_endpoints_never_disclose_tokens(recovery_users):
    with TestClient(app, base_url="https://testserver") as client, patch("app.routes.auth.send_email", return_value=False):
        for endpoint in ("/forgot-password", "/request-totp-reset"):
            response = client.post(endpoint, data={"email": "owner@example.invalid"})
            assert "?token=" not in response.text
            assert "Demo reset link" not in response.text


def test_grants_are_scoped_and_single_use(recovery_users):
    owner, other = recovery_users
    scope = {"date_from": "2026-09-01"}
    token = issue_grant(owner, "statement_export", scope)
    assert not consume_grant(token, other, "statement_export", scope)
    assert not consume_grant(token, owner, "admin_audit_view", scope)
    assert not consume_grant(token, owner, "statement_export", {})
    assert consume_grant(token, owner, "statement_export", scope)
    assert not consume_grant(token, owner, "statement_export", scope)


def test_query_flag_does_not_authorize_export(recovery_users):
    owner, _ = recovery_users
    with TestClient(app, base_url="https://testserver") as client:
        cookie = TimestampSigner(SESSION_SECRET).sign(base64.b64encode(json.dumps({"user_id": owner}).encode())).decode()
        client.cookies.set("session", cookie)
        response = client.get("/statements.csv?poia=1", follow_redirects=False)
        assert response.status_code == 303
        assert "poia_intent=" in response.headers["location"]
