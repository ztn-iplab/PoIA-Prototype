import base64
import json
import tempfile
import time
import unittest
from pathlib import Path


try:
    import fastapi  # noqa: F401
    from fastapi.testclient import TestClient
    from itsdangerous import TimestampSigner

    HTTP_DEPS_AVAILABLE = True
except ModuleNotFoundError:
    HTTP_DEPS_AVAILABLE = False


@unittest.skipUnless(HTTP_DEPS_AVAILABLE, "FastAPI HTTP test dependencies are not installed")
class PoIAExecutionHTTPTests(unittest.TestCase):
    def test_replayed_execution_changes_protected_state_only_once(self) -> None:
        from app import db, poia_metrics
        from app.core import create_poia_intent, poia_store
        from app.main import app
        from app.model import ProofRecord
        from app.routes import poia as poia_routes
        from app.settings import SESSION_SECRET
        from app.track_a_recorder import TrackARecorder

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db.DB_PATH = root / "bank.db"
            poia_metrics.METRICS_CSV = root / "metrics.csv"
            db.init_db()
            with db.db_connect() as conn:
                user_id = conn.execute(
                    "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)",
                    ("track-a@example.invalid", "unused", int(time.time())),
                ).lastrowid
                account_id = conn.execute(
                    "INSERT INTO accounts (user_id, account_type, balance, created_at) VALUES (?, ?, ?, ?)",
                    (user_id, "checking", 1000.0, int(time.time())),
                ).lastrowid

            run_dir = root / "run-http-1"
            run_dir.mkdir()
            manifest = {
                "run_id": "run-http-1",
                "batch_id": "http-regression",
                "configuration": "poia_webauthn",
                "random_seed": 42,
                "sample_size_per_scenario": 200,
                "rp_repository": {"commit": "a" * 40},
                "authenticator_repository": None,
            }
            manifest_path = run_dir / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            poia_routes.track_a_recorder = TrackARecorder(
                manifest_path, scenario_id="exact_legitimate_match"
            )
            poia_routes.POIA_EXPERIMENT_MODE = True

            poia_store.intents.clear()
            poia_store.challenges.clear()
            poia_store.proofs.clear()
            intent_id = create_poia_intent(
                action="transfer",
                scope={
                    "from_account": account_id,
                    "amount": 100.0,
                    "currency": "USD",
                    "external_account": "synthetic-target",
                },
                context={"rp_id": "poia-demo-bank", "user_id": user_id},
            )
            approved, reason = poia_store.approve_proof(
                ProofRecord(intent_id, "opaque", "approved", "Approved", 1),
                time.time(),
            )
            self.assertTrue(approved, reason)

            session_data = base64.b64encode(json.dumps({"user_id": user_id}).encode("utf-8"))
            session_cookie = TimestampSigner(str(SESSION_SECRET)).sign(session_data).decode("utf-8")
            with TestClient(app) as client:
                client.cookies.set("session", session_cookie)
                first = client.get(
                    f"/poia/execute/{intent_id}",
                    headers={"X-PoIA-Expected-Decision": "accept"},
                )
                second = client.get(
                    f"/poia/execute/{intent_id}",
                    headers={
                        "X-PoIA-Expected-Decision": "reject",
                        "X-PoIA-Scenario-Id": "replay",
                    },
                )
                tamper_id = create_poia_intent(
                    action="transfer",
                    scope={
                        "from_account": account_id,
                        "amount": 100.0,
                        "currency": "USD",
                        "external_account": "synthetic-target",
                    },
                    context={"rp_id": "poia-demo-bank", "user_id": user_id},
                )
                poia_store.approve_proof(
                    ProofRecord(tamper_id, "opaque", "approved", "Approved", 1),
                    time.time(),
                )
                requested = json.loads(json.dumps(poia_store.intents[tamper_id].intent_body))
                requested["scope"]["amount"] = 700.0
                tampered = client.post(
                    "/api/poia/experiment/execute",
                    json={"intent_id": tamper_id, "requested_intent": requested},
                    headers={
                        "X-PoIA-Expected-Decision": "reject",
                        "X-PoIA-Scenario-Id": "request_tampering",
                    },
                )

            self.assertEqual(first.status_code, 200)
            self.assertIn("Transfer completed", first.text)
            self.assertEqual(second.status_code, 200)
            self.assertIn("already been used", second.text)
            self.assertEqual(tampered.status_code, 400)
            self.assertEqual(tampered.json()["reason"], "scope_mismatch")
            with db.db_connect() as conn:
                balance = conn.execute(
                    "SELECT balance FROM accounts WHERE id = ?", (account_id,)
                ).fetchone()[0]
                transactions = conn.execute(
                    "SELECT COUNT(*) FROM transactions WHERE account_id = ?", (account_id,)
                ).fetchone()[0]
            self.assertEqual(balance, 900.0)
            self.assertEqual(transactions, 1)
            rows = [
                json.loads(line)
                for line in (run_dir / "decisions" / "decisions.jsonl").read_text().splitlines()
            ]
            self.assertEqual(
                [row["decision"] for row in rows], ["accept", "reject", "reject"]
            )
            self.assertEqual(rows[1]["rejection_reason"], "proof_consumed")
            self.assertEqual(rows[2]["rejection_reason"], "scope_mismatch")
            self.assertTrue(rows[0]["state_changed"])
            self.assertFalse(rows[1]["state_changed"])
            self.assertFalse(rows[2]["state_changed"])
            self.assertEqual(poia_store.proofs[tamper_id].status, "approved")
            request_artifacts = sorted((run_dir / "requests").glob("*.json"))
            tamper_artifact = json.loads(request_artifacts[-1].read_text())
            self.assertEqual(tamper_artifact["approved_intent"]["scope"]["amount"], 100.0)
            self.assertEqual(tamper_artifact["requested_intent"]["scope"]["amount"], 700.0)


if __name__ == "__main__":
    unittest.main()
