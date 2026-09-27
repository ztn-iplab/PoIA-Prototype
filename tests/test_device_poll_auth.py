import base64
import secrets
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from app import db
from app.main import app


@pytest.fixture
def enrolled(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "bank.db")
    db.init_db()
    private = ec.generate_private_key(ec.SECP256R1())
    public = base64.b64encode(private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    with db.db_connect() as conn:
        user = conn.execute("INSERT INTO users(email,password_hash,created_at,poia_zt_enabled) VALUES ('poll@test.invalid','unused',0,1)").lastrowid
        device = conn.execute("INSERT INTO devices(user_id,device_label,platform,created_at) VALUES (?,'test','android',0)", (user,)).lastrowid
        conn.execute("INSERT INTO device_keys(device_id,rp_id,key_type,public_key,created_at) VALUES (?,'poia-demo-bank','p256',?,0)", (device, public))
    return private, {"user_id": user, "device_id": device, "rp_id": "poia-demo-bank"}


def signed_headers(private, params, path, age=0):
    nonce, stamp = secrets.token_hex(24), str(int(time.time()) + age)
    purpose = f"poll-v1:{path}:{params['user_id']}:{stamp}"
    payload = f"{nonce}|{params['device_id']}|{params['rp_id']}|{purpose}".encode()
    signature = base64.b64encode(private.sign(payload, ec.ECDSA(hashes.SHA256()))).decode()
    return {"x-poia-poll-nonce": nonce, "x-poia-poll-time": stamp, "x-poia-poll-signature": signature}


@pytest.mark.parametrize("path", ["/api/auth/login/pending", "/api/poia/pending"])
def test_poll_requires_fresh_endpoint_and_owner_bound_signature(enrolled, path):
    private, params = enrolled
    with TestClient(app) as client:
        assert client.get(path, params=params).status_code == 401
        assert client.get(path, params=params, headers=signed_headers(private, params, path, -100)).status_code == 401
        assert client.get(path, params=params, headers=signed_headers(private, params, "/other")).status_code == 401
        headers = signed_headers(private, params, path)
        assert client.get(path, params={**params, "user_id": params["user_id"] + 100}, headers=headers).status_code == 401
        assert client.get(path, params=params, headers=headers).status_code == 200
        assert client.get(path, params=params, headers=headers).status_code == 401
