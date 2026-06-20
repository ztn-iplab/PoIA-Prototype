import base64
import json
import tempfile
import time
import unittest
from pathlib import Path


try:
    from fastapi.testclient import TestClient
    from itsdangerous import TimestampSigner

    HTTP_DEPS_AVAILABLE = True
except ModuleNotFoundError:
    HTTP_DEPS_AVAILABLE = False


@unittest.skipUnless(HTTP_DEPS_AVAILABLE, "FastAPI HTTP test dependencies are not installed")
class TokenReuseHTTPTests(unittest.TestCase):
    def test_session_token_reuse_succeeds_but_poia_substitution_fails(self) -> None:
        from app import db, poia_metrics
        from app.core import poia_store
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
                    ("token-test@example.invalid", "unused", int(time.time())),
                ).lastrowid

            run_dir = root / "token-run"
            run_dir.mkdir()
            manifest = {
                "run_id": "token-run",
                "batch_id": "token-regression",
                "configuration": "session_only",
                "random_seed": 42,
                "sample_size_per_scenario": 200,
                "rp_repository": {"commit": "b" * 40},
                "authenticator_repository": None,
            }
            manifest_path = run_dir / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            recorder = TrackARecorder(manifest_path, scenario_id="token_reuse")
            poia_routes.track_a_recorder = recorder
            poia_routes.POIA_EXPERIMENT_MODE = True
            poia_store.intents.clear()
            poia_store.challenges.clear()
            poia_store.proofs.clear()

            session_data = base64.b64encode(json.dumps({"user_id": user_id}).encode("utf-8"))
            session_cookie = TimestampSigner(str(SESSION_SECRET)).sign(session_data).decode("utf-8")
            with TestClient(app) as client:
                client.cookies.set("session", session_cookie)
                issued = client.post(
                    "/api/poia/experiment/token/issue",
                    json={"intended_action": "deploy_config"},
                )
                access_token = issued.json()["access_token"]
                bearer_headers = {
                    "Authorization": f"Bearer {access_token}",
                    "X-PoIA-Expected-Decision": "reject",
                    "X-PoIA-Scenario-Id": "token_reuse",
                }
                baseline = client.post(
                    "/api/poia/experiment/token/action",
                    json={"action": "api_key_rotate", "scope": {"object_id": "key-1"}},
                    headers=bearer_headers,
                )

                poia_run_dir = root / "token-run-poia"
                poia_run_dir.mkdir()
                poia_manifest = {
                    **manifest,
                    "run_id": "token-run-poia",
                    "batch_id": "token-poia-regression",
                    "configuration": "poia_webauthn",
                }
                poia_manifest_path = poia_run_dir / "manifest.json"
                poia_manifest_path.write_text(json.dumps(poia_manifest), encoding="utf-8")
                poia_routes.track_a_recorder = TrackARecorder(
                    poia_manifest_path, scenario_id="token_reuse"
                )
                started = client.post(
                    "/api/poia/experiment/token/intent/start",
                    json={"action": "deploy_config", "scope": {"object_id": "config-1"}},
                )
                intent_id = started.json()["intent_id"]
                poia_store.approve_proof(
                    ProofRecord(intent_id, "opaque", "approved", "Approved", 1),
                    time.time(),
                )
                poia_denied = client.post(
                    "/api/poia/experiment/token/action",
                    json={
                        "action": "api_key_rotate",
                        "scope": {"object_id": "config-1"},
                        "intent_id": intent_id,
                    },
                    headers=bearer_headers,
                )
                exact = client.post(
                    "/api/poia/experiment/token/action",
                    json={
                        "action": "deploy_config",
                        "scope": {"object_id": "config-1"},
                        "intent_id": intent_id,
                    },
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "X-PoIA-Expected-Decision": "accept",
                        "X-PoIA-Scenario-Id": "token_legitimate_control",
                    },
                )

            self.assertEqual(issued.status_code, 201)
            self.assertEqual(baseline.status_code, 201)
            self.assertEqual(poia_denied.status_code, 403)
            self.assertEqual(poia_denied.json()["reason"], "action_mismatch")
            self.assertEqual(exact.status_code, 201)
            with db.db_connect() as conn:
                operations = conn.execute(
                    "SELECT action FROM experiment_api_operations ORDER BY id"
                ).fetchall()
            self.assertEqual([row["action"] for row in operations], ["api_key_rotate", "deploy_config"])
            baseline_rows = [
                json.loads(line)
                for line in (run_dir / "decisions" / "decisions.jsonl").read_text().splitlines()
            ]
            poia_rows = [
                json.loads(line)
                for line in (poia_run_dir / "decisions" / "decisions.jsonl").read_text().splitlines()
            ]
            self.assertEqual([row["decision"] for row in baseline_rows], ["accept"])
            self.assertEqual([row["decision"] for row in poia_rows], ["reject", "accept"])
            self.assertTrue(baseline_rows[0]["state_changed"])
            self.assertFalse(poia_rows[0]["state_changed"])
            self.assertEqual(poia_rows[0]["rejection_reason"], "action_mismatch")
            all_evidence = "".join(
                path.read_text()
                for path in root.rglob("*")
                if path.is_file()
                and path.name != "manifest.json"
                and path.suffix in {".json", ".jsonl"}
            )
            self.assertNotIn(access_token, all_evidence)


if __name__ == "__main__":
    unittest.main()
