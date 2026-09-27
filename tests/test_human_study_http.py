import base64
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


try:
    import fastapi  # noqa: F401
    from fastapi.testclient import TestClient
    from itsdangerous import TimestampSigner

    HTTP_DEPS_AVAILABLE = True
except ModuleNotFoundError:
    HTTP_DEPS_AVAILABLE = False


@unittest.skipUnless(HTTP_DEPS_AVAILABLE, "FastAPI HTTP test dependencies are not installed")
class HumanStudyHTTPTests(unittest.TestCase):
    def test_live_study_mutations_use_original_binding_and_semantic_gate(self) -> None:
        from app import db, poia_metrics
        from app.core import poia_store
        from app.main import app
        from app.model import ProofRecord
        from app.routes import poia as poia_routes
        from app.settings import SESSION_SECRET

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db.DB_PATH = root / "bank.db"
            poia_metrics.METRICS_CSV = root / "metrics.csv"
            db.init_db()
            poia_routes.POIA_EXPERIMENT_MODE = True
            poia_store.intents.clear()
            poia_store.challenges.clear()
            poia_store.proofs.clear()
            with db.db_connect() as conn:
                user_id = conn.execute(
                    "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)",
                    ("participant@example.invalid", "unused", int(time.time())),
                ).lastrowid
                account_id = conn.execute(
                    "INSERT INTO accounts (user_id, account_type, balance, created_at) VALUES (?, ?, ?, ?)",
                    (user_id, "checking", 1000.0, int(time.time())),
                ).lastrowid
                conn.execute("UPDATE users SET poia_zt_enabled = 1 WHERE id = ?", (user_id,))
                conn.execute(
                    "INSERT INTO webauthn_credentials "
                    "(user_id, credential_id, public_key, sign_count, transports, created_at) "
                    "VALUES (?, 'test-credential', 'test-key', 0, '[]', ?)",
                    (user_id, int(time.time())),
                )
                device_id = conn.execute(
                    "INSERT INTO devices (user_id, device_label, platform, created_at) "
                    "VALUES (?, 'Study phone', 'test', ?)",
                    (user_id, int(time.time())),
                ).lastrowid
                conn.execute(
                    "INSERT INTO device_keys (device_id, rp_id, key_type, public_key, created_at) "
                    "VALUES (?, 'poia-demo-bank', 'p256', 'test-device-key', ?)",
                    (device_id, int(time.time())),
                )

            session_data = base64.b64encode(json.dumps({"user_id": user_id}).encode("utf-8"))
            session_cookie = TimestampSigner(str(SESSION_SECRET)).sign(session_data).decode("utf-8")
            with TestClient(app) as client:
                client.cookies.set("session", session_cookie)
                console = client.get("/poia/experiment/human-study")
                pre_display = client.post(
                    "/api/poia/experiment/human-study/start",
                    json={
                        "study_run_id": "http-test-01",
                        "trial_id": "P01-W-pre-display",
                        "participant_id": "P01",
                        "signing_backend": "webauthn",
                        "mutation_stage": "pre_display",
                        "mutation_type": "scope",
                        "action": "transfer",
                        "scope": {"from_account": account_id, "amount": 100, "currency": "USD", "external_account": "9007"},
                        "mutations": [{"path": "scope.amount", "value": 1000}],
                    },
                )
                self.assertEqual(pre_display.status_code, 201)
                pre_id = pre_display.json()["intent_id"]
                forged_condition = client.post(
                    "/api/poia/experiment/human-study/start",
                    json={
                        "study_run_id": "http-test-01",
                        "trial_id": "P01-W-forged-label",
                        "participant_id": "P01",
                        "signing_backend": "webauthn",
                        "mutation_stage": "session_repurpose",
                        "mutation_type": "target",
                        "action": "transfer",
                        "scope": {"from_account": account_id, "amount": 100, "currency": "USD", "external_account": "9007"},
                        "mutations": [{"path": "scope.amount", "value": 1000}],
                    },
                )
                rendered = client.get(f"/poia/intent/{pre_id}")
                client.post(
                    "/api/poia/telemetry",
                    json={"event": "intent_loaded", "intent_id": pre_id, "method": "webauthn"},
                )
                assertion_options = SimpleNamespace(
                    public_key=SimpleNamespace(
                        challenge=b"test-challenge",
                        rp_id="poia.local",
                        allow_credentials=[],
                        user_verification="required",
                        timeout=60000,
                    )
                )
                with patch.object(poia_routes, "load_credentials", return_value=([object()], [])), patch.object(
                    poia_routes.server,
                    "authenticate_begin",
                    return_value=(assertion_options, {"challenge": b"test-challenge"}),
                ):
                    blocked_sign = client.post(
                        "/poia/assertion-begin", json={"intent_id": pre_id}
                    )

                post_signature = client.post(
                    "/api/poia/experiment/human-study/start",
                    json={
                        "study_run_id": "http-test-01",
                        "trial_id": "P01-Z-post-signature",
                        "participant_id": "P01",
                        "signing_backend": "zt_authenticator",
                        "mutation_stage": "post_signature",
                        "mutation_type": "scope",
                        "action": "transfer",
                        "scope": {"from_account": account_id, "amount": 100, "currency": "USD", "external_account": "9007"},
                        "mutations": [{"path": "scope.amount", "value": 1000}],
                    },
                )
                self.assertEqual(post_signature.status_code, 201)
                post_id = post_signature.json()["intent_id"]
                client.cookies.delete("session")
                unauthenticated_pending = client.get(
                    f"/api/poia/pending?user_id={user_id}"
                )
                unsigned_denial = client.post(
                    "/api/poia/deny",
                    json={"intent_id": post_id, "reason": "user_denied"},
                )
                client.cookies.set("session", session_cookie)
                zt_rendered = client.get(f"/poia/intent/{post_id}")
                wrong_backend = client.post(
                    "/poia/assertion-begin", json={"intent_id": post_id}
                )
                approved, reason = poia_store.approve_proof(
                    ProofRecord(post_id, "test-proof", "approved", "Approved", 1), time.time()
                )
                self.assertTrue(approved, reason)
                mutated = client.post(
                    "/api/poia/experiment/human-study/execute",
                    json={"trial_id": "P01-Z-post-signature", "variant": "mutated"},
                )
                relabeled_exact = client.post(
                    "/api/poia/experiment/human-study/execute",
                    json={"trial_id": "P01-Z-post-signature", "variant": "exact"},
                )
                replay = client.post(
                    "/api/poia/experiment/human-study/execute",
                    json={"trial_id": "P01-Z-post-signature", "variant": "mutated"},
                )

            self.assertEqual(console.status_code, 200)
            self.assertEqual(forged_condition.status_code, 400)
            self.assertEqual(forged_condition.json()["reason"], "invalid_study_trial")
            self.assertEqual(unauthenticated_pending.status_code, 401)
            self.assertEqual(unauthenticated_pending.json()["reason"], "device_auth_required")
            self.assertEqual(unsigned_denial.status_code, 401)
            self.assertIn("Run a participant trial", console.text)
            self.assertEqual(rendered.status_code, 200)
            self.assertEqual(rendered.json()["intent"]["scope"]["amount"], 1000)
            self.assertEqual(rendered.json()["signing_backend"], "webauthn")
            self.assertEqual(zt_rendered.json()["signing_backend"], "zt_authenticator")
            self.assertEqual(wrong_backend.status_code, 409)
            self.assertEqual(wrong_backend.json()["error"], "wrong_signing_backend")
            self.assertEqual(blocked_sign.status_code, 200)
            self.assertEqual(mutated.status_code, 409)
            self.assertEqual(mutated.json()["reason"], "scope_mismatch")
            self.assertFalse(mutated.json()["state_changed"])
            self.assertEqual(relabeled_exact.status_code, 400)
            self.assertEqual(relabeled_exact.json()["reason"], "execution_variant_mismatch")
            self.assertEqual(replay.status_code, 409)
            self.assertEqual(replay.json()["reason"], "scope_mismatch")
            self.assertFalse(replay.json()["state_changed"])
            with db.db_connect() as conn:
                balance = conn.execute("SELECT balance FROM accounts WHERE id = ?", (account_id,)).fetchone()[0]
                events = conn.execute(
                    "SELECT system_decision, rejection_reason, state_changed "
                    "FROM poia_human_study_events WHERE trial_id = ? ORDER BY event_id",
                    ("P01-Z-post-signature",),
                ).fetchall()
                pre_trial = conn.execute(
                    "SELECT participant_decision, system_decision, rejection_reason, decision_time_ms "
                    "FROM poia_human_study_trials WHERE trial_id = ?",
                    ("P01-W-pre-display",),
                ).fetchone()
            self.assertEqual(balance, 1000.0)
            self.assertEqual(
                [tuple(row) for row in events],
                [("reject", "scope_mismatch", 0), ("reject", "scope_mismatch", 0)],
            )
            self.assertEqual(tuple(pre_trial[:3]), (None, None, None))
            self.assertIsNone(pre_trial["decision_time_ms"])


if __name__ == "__main__":
    unittest.main()
