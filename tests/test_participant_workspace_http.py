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
class ParticipantWorkspaceHTTPTests(unittest.TestCase):
    def test_participant_flow_keeps_conditions_server_side_and_tags_data(self) -> None:
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
                    "INSERT INTO users (email, password_hash, is_admin, created_at, poia_zt_enabled) "
                    "VALUES (?, 'unused', 0, ?, 1)",
                    ("spontaneous@example.invalid", int(time.time())),
                ).lastrowid
                account_id = conn.execute(
                    "INSERT INTO accounts (user_id, account_type, balance, created_at) VALUES (?, 'checking', 5000, ?)",
                    (user_id, int(time.time())),
                ).lastrowid
                conn.execute(
                    "INSERT INTO webauthn_credentials "
                    "(user_id, credential_id, public_key, sign_count, transports, created_at) "
                    "VALUES (?, 'participant-credential', 'test-key', 0, '[]', ?)",
                    (user_id, int(time.time())),
                )
                device_id = conn.execute(
                    "INSERT INTO devices (user_id, device_label, platform, created_at) VALUES (?, 'Study phone', 'test', ?)",
                    (user_id, int(time.time())),
                ).lastrowid
                conn.execute(
                    "INSERT INTO device_keys (device_id, rp_id, key_type, public_key, created_at) "
                    "VALUES (?, 'poia-demo-bank', 'p256', 'test-key', ?)",
                    (device_id, int(time.time())),
                )
                conn.execute(
                    "INSERT INTO beneficiaries (user_id, name, bank, account_number, created_at) "
                    "VALUES (?, 'Participant Choice', 'Example Bank', '77553311', ?)",
                    (user_id, int(time.time())),
                )

            session_data = base64.b64encode(json.dumps({"user_id": user_id}).encode())
            session_cookie = TimestampSigner(str(SESSION_SECRET)).sign(session_data).decode()
            with TestClient(app) as client:
                client.cookies.set("session", session_cookie)
                landing = client.get("/poia/experiment/participant")
                self.assertEqual(landing.status_code, 200)
                self.assertNotIn("session_repurpose", landing.text)
                self.assertNotIn("post_signature", landing.text)
                self.assertNotIn("mutation_type", landing.text)

                poia_routes.ensure_cloud_resources(user_id)
                with db.db_connect() as conn:
                    conn.execute(
                        "UPDATE experiment_cloud_resources SET status = 'deleted', "
                        "public_access = 1, version = 7 WHERE user_id = ?",
                        (user_id,),
                    )

                missing_orientation = client.post("/api/poia/experiment/participant/begin")
                self.assertEqual(missing_orientation.status_code, 400)
                begun = client.post("/api/poia/experiment/participant/begin", json={
                    "consent": True, "sign_meaning": "authorize", "decline_meaning": "do_not_authorize",
                })
                self.assertEqual(begun.status_code, 201)
                next_url = begun.json()["next_url"]
                session_id = next_url.split("session=", 1)[1]
                with db.db_connect() as conn:
                    session_row = conn.execute(
                        "SELECT schedule_json, cohort FROM poia_participant_sessions WHERE session_id = ?",
                        (session_id,),
                    ).fetchone()
                    session_schedule = json.loads(session_row["schedule_json"])
                self.assertEqual(session_row["cohort"], "webauthn_first")
                self.assertEqual(len(session_schedule), 18)
                self.assertEqual(
                    {item["key"] for item in session_schedule},
                    {
                        "transfer_control", "transfer_target", "statement_control",
                        "beneficiary_control", "cloud_view_control", "withdrawal_control",
                        "transfer_subtle", "cloud_view_delete", "beneficiary_target",
                        "withdrawal_pre_amount", "statement_repurpose", "statement_pre_context",
                        "cloud_download_share", "withdrawal_post_amount", "cloud_view_overwrite",
                        "transfer_multiple", "cloud_post_delete", "cloud_delete_control",
                    },
                )
                self.assertEqual(
                    {family: sum(item["family"] == family for item in session_schedule)
                     for family in {item["family"] for item in session_schedule}},
                    {"transfer": 5, "statement": 2, "cloud": 6, "withdrawal": 3, "beneficiary": 2},
                )
                self.assertEqual(
                    [item["backend"] for item in session_schedule],
                    ["webauthn" if index % 2 == 0 else "zt_authenticator" for index in range(18)],
                )
                with db.db_connect() as conn:
                    restored = conn.execute(
                        "SELECT status, public_access, version FROM experiment_cloud_resources "
                        "WHERE user_id = ?",
                        (user_id,),
                    ).fetchall()
                self.assertEqual(len(restored), 3)
                self.assertTrue(
                    all(
                        row["status"] == "active"
                        and row["public_access"] == 0
                        and row["version"] == 1
                        for row in restored
                    )
                )
                workspace = client.get(next_url)
                self.assertIn("Make a transfer", workspace.text)
                self.assertIn("Study recipient directory", workspace.text)
                self.assertIn("Your beneficiaries", workspace.text)
                self.assertIn("Participant Choice", workspace.text)
                from app.human_study import PARTICIPANT_RECIPIENTS
                for recipient_number, recipient_name in PARTICIPANT_RECIPIENTS:
                    self.assertIn(recipient_number, workspace.text)
                    self.assertIn(recipient_name, workspace.text)
                self.assertNotIn("$5000.00", workspace.text)
                self.assertNotIn('href="/dashboard"', workspace.text)
                self.assertNotIn('href="/transfer"', workspace.text)

                operation = client.post(
                    "/api/poia/experiment/participant/operate",
                    json={
                        "session_id": session_id,
                        "from_account": account_id,
                        "external_account": "9007",
                        "amount": "25.00",
                    },
                )
                self.assertEqual(operation.status_code, 201)
                self.assertEqual(set(operation.json()), {"status", "signing_backend", "next_url"})
                self.assertNotIn("trial_id", operation.text)
                self.assertNotIn("expected", operation.text)
                with db.db_connect() as conn:
                    trial = conn.execute(
                        "SELECT * FROM poia_human_study_trials WHERE participant_session_id = ?",
                        (session_id,),
                    ).fetchone()
                self.assertEqual(trial["study_mode"], "spontaneous")
                self.assertEqual(trial["cohort"], "webauthn_first")
                self.assertEqual(trial["scenario_key"], "transfer_control")
                self.assertEqual(trial["step_index"], 0)
                self.assertEqual(trial["proof_status"], "pending")

                poia_store.approve_proof(
                    ProofRecord(trial["intent_id"], "test-proof", "approved", "Approved", 1),
                    time.time(),
                )
                with db.db_connect() as conn:
                    conn.execute(
                        "UPDATE poia_human_study_trials SET participant_decision = 'sign', system_decision = 'approved' "
                        "WHERE trial_id = ?",
                        (trial["trial_id"],),
                    )
                status = client.get(
                    "/api/poia/experiment/participant/status", params={"session": session_id}
                )
                self.assertEqual(status.json()["status"], "closed")
                self.assertEqual(set(status.json()), {"status", "next_url"})

                altered = client.post(
                    "/api/poia/experiment/participant/operate",
                    json={
                        "session_id": session_id,
                        "from_account": account_id,
                        "external_account": "77553311",
                        "amount": "30.00",
                    },
                )
                self.assertEqual(altered.status_code, 201)
                with db.db_connect() as conn:
                    altered_trial = conn.execute(
                        "SELECT * FROM poia_human_study_trials WHERE participant_session_id = ? "
                        "AND step_index = 1",
                        (session_id,),
                    ).fetchone()
                self.assertEqual(altered_trial["scenario_key"], "transfer_target")
                self.assertEqual(
                    json.loads(altered_trial["task_body"])["scope"]["external_account"],
                    "77553311",
                )
                self.assertNotEqual(
                    json.loads(altered_trial["displayed_body"])["scope"]["external_account"],
                    "77553311",
                )
                poia_store.approve_proof(
                    ProofRecord(altered_trial["intent_id"], "test-proof", "approved", "Approved", 1),
                    time.time(),
                )
                with db.db_connect() as conn:
                    conn.execute(
                        "UPDATE poia_human_study_trials SET participant_decision = 'sign', "
                        "system_decision = 'approved' WHERE trial_id = ?",
                        (altered_trial["trial_id"],),
                    )
                altered_status = client.get(
                    "/api/poia/experiment/participant/status", params={"session": session_id}
                )
                self.assertEqual(altered_status.json()["status"], "closed")
                with db.db_connect() as conn:
                    conn.execute(
                        "UPDATE poia_participant_sessions SET status = 'complete' WHERE session_id = ?",
                        (session_id,),
                    )
                questionnaire = client.get(
                    "/poia/experiment/participant", params={"session": session_id}
                ).text
                self.assertIn("how likely would you be to use it in everyday life", questionnaire)
                self.assertIn("What should be changed or improved", questionnaire)
                questions = client.post(
                    "/api/poia/experiment/participant/debrief",
                    json={
                        "session_id": session_id,
                        "phase": "questions",
                        "purpose_guess": "Routine authorization usability",
                        "noticed_unusual": "yes",
                        "unusual_detail": "Some prompts differed from the task.",
                        "semantic_fields": ["operation", "amount", "destination"],
                        "semantic_other": "",
                        "matching_ease": "easy",
                        "confusion": "slight",
                        "frustration": "none",
                        "technical_difficulty": "no",
                        "decision_explanation": "I declined because the recipient differed.",
                        "real_world_use_likelihood": "likely",
                        "improvement_suggestion": "Make the most important fields easier to scan.",
                        "age_band": "25_34",
                        "banking_frequency": "several_weekly",
                        "passkey_familiarity": "occasional",
                        "authenticator_familiarity": "regular",
                        "technical_experience": "general_it",
                        "webauthn_review_ease": "easy",
                        "zt_review_ease": "very_easy",
                        "backend_preference": "zt_authenticator",
                        "trust_confident": "agree",
                        "trust_secure": "somewhat_agree",
                        "trust_integrity": "strongly_agree",
                        "trust_dependable": "agree",
                        "trust_reliable": "neutral",
                        "trust_overall": "agree",
                        "trust_familiar": "somewhat_agree",
                        "preference_reason": "The operation details were easier to review.",
                        "final_comment": "The sequence was straightforward.",
                    },
                )
                self.assertEqual(questions.status_code, 200)

            with db.db_connect() as conn:
                session_row = conn.execute(
                    "SELECT current_step FROM poia_participant_sessions WHERE session_id = ?",
                    (session_id,),
                ).fetchone()
                balance = conn.execute(
                    "SELECT balance FROM accounts WHERE id = ?", (account_id,)
                ).fetchone()[0]
                altered_result = conn.execute(
                    "SELECT system_decision, rejection_reason, proof_status "
                    "FROM poia_human_study_trials "
                    "WHERE trial_id = ?",
                    (altered_trial["trial_id"],),
                ).fetchone()
                exact_result = conn.execute(
                    "SELECT proof_status FROM poia_human_study_trials WHERE trial_id = ?",
                    (trial["trial_id"],),
                ).fetchone()
                post_session = json.loads(
                    conn.execute(
                        "SELECT post_session_response FROM poia_participant_sessions WHERE session_id = ?",
                        (session_id,),
                    ).fetchone()[0]
                )
            self.assertEqual(session_row["current_step"], 2)
            self.assertEqual(balance, 4975.0)
            self.assertEqual(altered_result["system_decision"], "reject")
            self.assertEqual(altered_result["rejection_reason"], "original_request_mismatch")
            self.assertEqual(exact_result["proof_status"], "consumed")
            self.assertEqual(altered_result["proof_status"], "approved")
            self.assertEqual(post_session["semantic_fields"], ["amount", "destination", "operation"])
            self.assertEqual(post_session["matching_ease"], "easy")
            self.assertEqual(post_session["confusion"], "slight")
            self.assertEqual(post_session["questionnaire_version"], "2026-09-04-participant-beneficiaries-v4")
            self.assertEqual(post_session["real_world_use_likelihood"], "likely")
            self.assertEqual(
                post_session["improvement_suggestion"],
                "Make the most important fields easier to scan.",
            )
            self.assertEqual(post_session["age_band"], "25_34")
            self.assertEqual(post_session["backend_preference"], "zt_authenticator")
            self.assertEqual(post_session["zt_review_ease"], "very_easy")
            self.assertEqual(post_session["trust_confident"], "agree")
            self.assertEqual(post_session["trust_reliable"], "neutral")
            self.assertEqual(post_session["trust_familiar"], "somewhat_agree")


if __name__ == "__main__":
    unittest.main()
