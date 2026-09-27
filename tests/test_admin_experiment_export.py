import base64
import csv
import hashlib
import io
import json
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace


class AdminExperimentExportTests(unittest.TestCase):
    def setUp(self):
        from app import db, poia_metrics
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        for patcher in (patch.object(db, "DB_PATH", root / "bank.db"),
                        patch.object(poia_metrics, "METRICS_CSV", root / "telemetry.csv")):
            patcher.start()
            self.addCleanup(patcher.stop)
        db.init_db()
        from app.main import app
        from fastapi.testclient import TestClient
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        with db.db_connect() as conn:
            self.admin = conn.execute("INSERT INTO users(email,password_hash,is_admin,created_at) VALUES ('admin@test.invalid','SECRET-PASSWORD',1,?)", (time.time(),)).lastrowid
            self.customer = conn.execute("INSERT INTO users(email,password_hash,is_admin,created_at) VALUES ('customer@test.invalid','SECRET-PASSWORD',0,?)", (time.time(),)).lastrowid
            for index in range(2):
                conn.execute(
                    "INSERT INTO poia_participant_sessions(session_id,participant_id,study_run_id,user_id,schedule_json,created_at,post_session_response) VALUES (?,?,?,?,?,?,?)",
                    (f"session-{index}", f"participant-{index}", f"run-{index}", self.customer, "[]", time.time(), json.dumps({"final_comment": "=1+1", "confusion": "none"})),
                )
        poia_metrics.log_poia_event(event="test_approval", method="webauthn", latency_ms=123)

    def login(self, user_id):
        from itsdangerous import TimestampSigner
        from app.settings import SESSION_SECRET
        data = base64.b64encode(json.dumps({"user_id": user_id}).encode())
        self.client.cookies.set("session", TimestampSigner(str(SESSION_SECRET)).sign(data).decode())

    def test_access_control_and_dashboard_separation(self):
        self.assertEqual(self.client.get("/admin/experiments/export").status_code, 401)
        self.login(self.customer)
        self.assertEqual(self.client.get("/admin/experiments/export").status_code, 403)
        self.assertEqual(self.client.get("/admin/dashboard", follow_redirects=False).status_code, 302)
        self.assertNotIn("/admin/experiments/export", self.client.get("/dashboard").text)
        self.login(self.admin)
        dashboard = self.client.get("/admin/dashboard").text
        self.assertIn("Experiment control dashboard", dashboard)
        self.assertIn("Export data", dashboard)
        self.assertIn("Open audit log", dashboard)
        self.assertIn("Open MFA metrics", dashboard)
        self.assertIn("Post-session responses", dashboard)
        self.assertIn("participant-0", dashboard)
        self.assertEqual(self.client.get("/admin/experiments/export", headers={"Sec-Fetch-Site": "cross-site"}).status_code, 403)

    def test_export_all_runs_exact_json_checksums_and_no_database_mutation(self):
        from app import db
        with db.db_connect() as conn:
            before = list(conn.iterdump())
        self.login(self.admin)
        response = self.client.get("/admin/experiments/export")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertIn("attachment", response.headers["content-disposition"])
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            manifest = json.loads(archive.read("manifest.json"))
            self.assertEqual(manifest["format_version"], 2)
            self.assertEqual(len(archive.namelist()), 8)
            self.assertEqual(manifest["row_counts"]["poia_participant_sessions"], 2)
            self.assertEqual(manifest["row_counts"]["approval_telemetry"], 1)
            self.assertEqual(manifest["row_counts"]["questionnaire_responses"], 2)
            for name, info in manifest["files"].items():
                self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(), info["sha256"])
                self.assertNotIn(b"SECRET-PASSWORD", archive.read(name))
            raw_records = [
                json.loads(line) for line in archive.read("raw/database_records.jsonl").splitlines()
            ]
            rows = [record["row"] for record in raw_records
                    if record["table"] == "poia_participant_sessions"]
            self.assertEqual({row["study_run_id"] for row in rows}, {"run-0", "run-1"})
            self.assertEqual(json.loads(rows[0]["post_session_response"])["final_comment"], "=1+1")
            questionnaire = list(csv.DictReader(io.StringIO(
                archive.read("analysis/questionnaire_responses.csv").decode()
            )))
            self.assertEqual(len(questionnaire), 2)
            self.assertEqual(questionnaire[0]["final_comment"], "'=1+1")
            self.assertNotIn("users.csv", archive.namelist())
        with db.db_connect() as conn:
            self.assertEqual(before, list(conn.iterdump()))

    def test_csv_formula_protection_and_incomplete_telemetry(self):
        from app.experiment_export import csv_bytes
        from app import poia_metrics
        encoded = csv_bytes(["value"], [{"value": "=1+1"}, {"value": "\t@SUM(1)"}])
        rows = list(csv.DictReader(io.StringIO(encoded.decode())))
        self.assertEqual(rows[0]["value"], "'=1+1")
        self.assertTrue(rows[1]["value"].startswith("'"))
        with poia_metrics.METRICS_CSV.open("ab") as handle:
            handle.write(b"unfinished")
        self.login(self.admin)
        self.assertEqual(self.client.get("/admin/experiments/export").status_code, 409)

    def test_expiry_is_not_a_participant_refusal(self):
        from app import db
        from app.core import poia_store
        intent_id = "expiry-fixture"
        with db.db_connect() as conn:
            conn.execute(
                "INSERT INTO poia_human_study_trials(trial_id,study_run_id,participant_id,signing_backend,mutation_stage,mutation_type,original_request_id,intent_id,original_sha256,displayed_sha256,expected_participant_decision,task_body,displayed_body,mutation_spec,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("expiry-trial","run-0","participant-0","webauthn","none","none","original",intent_id,"hash","hash","sign","{}","{}","[]",time.time()),
            )
        from app.model import IntentRecord, ChallengeRecord, ProofRecord
        intent = IntentRecord(intent_id, {"context":{"user_id":self.customer},"action":"transfer"}, time.time()-60)
        challenge = ChallengeRecord(intent_id, "test", time.time()+60)
        proof = ProofRecord(intent_id, "", "pending", "", 0)
        self.login(self.customer)
        with patch.dict(poia_store.intents, {intent_id:intent}), patch.dict(poia_store.challenges, {intent_id:challenge}), patch.dict(poia_store.proofs, {intent_id:proof}):
            response = self.client.post("/api/poia/deny",json={"intent_id":intent_id,"reason":"expired"})
            self.assertEqual(response.status_code,409)
            self.assertEqual(proof.status,"pending")
            poia_store.challenges[intent_id].expires_at = time.time()-1
            response = self.client.post("/api/poia/deny",json={"intent_id":intent_id,"reason":"expired"})
            self.assertEqual(response.status_code,200)
        with db.db_connect() as conn:
            row = conn.execute("SELECT participant_decision,system_decision FROM poia_human_study_trials WHERE trial_id='expiry-trial'").fetchone()
            self.assertIsNone(row["participant_decision"])
            self.assertEqual(row["system_decision"],"expired")


if __name__ == "__main__":
    unittest.main()
