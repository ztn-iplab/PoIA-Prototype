import json
import tempfile
import time
import unittest
from pathlib import Path
from starlette.requests import Request


class HumanStudyReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        from app import db
        from app.core import poia_store

        self.directory = tempfile.TemporaryDirectory()
        self.previous_path = db.DB_PATH
        db.DB_PATH = Path(self.directory.name) / "bank.db"
        db.init_db()
        poia_store.intents.clear()
        poia_store.challenges.clear()
        poia_store.proofs.clear()
        with db.db_connect() as conn:
            self.user_id = conn.execute(
                "INSERT INTO users (email, password_hash, is_admin, created_at) "
                "VALUES ('ready@example.invalid', 'unused', 0, ?)",
                (int(time.time()),),
            ).lastrowid
            self.account_id = conn.execute(
                "INSERT INTO accounts (user_id, account_type, balance, created_at) "
                "VALUES (?, 'checking', 1000, ?)",
                (self.user_id, int(time.time())),
            ).lastrowid

    def tearDown(self) -> None:
        from app import db

        db.DB_PATH = self.previous_path
        self.directory.cleanup()

    def enroll_both_signers(self) -> None:
        from app import db

        with db.db_connect() as conn:
            conn.execute("UPDATE users SET poia_zt_enabled = 1 WHERE id = ?", (self.user_id,))
            conn.execute(
                "INSERT INTO webauthn_credentials "
                "(user_id, credential_id, public_key, sign_count, transports, created_at) "
                "VALUES (?, 'credential', 'public-key', 0, '[]', ?)",
                (self.user_id, int(time.time())),
            )
            device_id = conn.execute(
                "INSERT INTO devices (user_id, device_label, platform, created_at) "
                "VALUES (?, 'Study phone', 'test', ?)",
                (self.user_id, int(time.time())),
            ).lastrowid
            conn.execute(
                "INSERT INTO device_keys (device_id, rp_id, key_type, public_key, created_at) "
                "VALUES (?, 'poia-demo-bank', 'p256', 'device-key', ?)",
                (device_id, int(time.time())),
            )

    def test_readiness_requires_account_and_both_registered_signers(self) -> None:
        from app.human_study import study_account_readiness

        incomplete = study_account_readiness(self.user_id)
        self.assertFalse(incomplete["ready"])
        self.assertTrue(incomplete["checks"]["active_account"])
        self.assertFalse(incomplete["checks"]["webauthn_registered"])
        self.assertFalse(incomplete["checks"]["zt_authenticator_registered"])

        self.enroll_both_signers()
        complete = study_account_readiness(self.user_id)
        self.assertTrue(complete["ready"])
        self.assertTrue(all(complete["checks"].values()))

    def test_study_objects_must_belong_to_signed_in_participant(self) -> None:
        from app.human_study import ensure_cloud_resources, validate_study_ownership

        ensure_cloud_resources(self.user_id)
        validate_study_ownership(
            self.user_id, "transfer", {"from_account": self.account_id}
        )
        validate_study_ownership(
            self.user_id,
            "cloud_file_view",
            {
                "resource_id": "identity-access-policy",
                "resource_name": "Identity and access policy.json",
                "classification": "restricted",
            },
        )
        with self.assertRaisesRegex(ValueError, "does not belong"):
            validate_study_ownership(
                self.user_id, "transfer", {"from_account": self.account_id + 999}
            )

    def test_zt_pending_queue_skips_webauthn_trials(self) -> None:
        from app.core import create_poia_intent, poia_store
        from app.human_study import create_trial_record
        from app.intent_codec import build_intent
        from app.routes import poia as poia_routes

        poia_routes.POIA_EXPERIMENT_MODE = True
        self.enroll_both_signers()
        body = build_intent(
            action="transfer",
            scope={
                "from_account": self.account_id,
                "amount": 10,
                "currency": "USD",
                "external_account": "9007",
            },
            context={"rp_id": "poia-demo-bank", "user_id": self.user_id},
        )
        intent_ids = []
        for index, backend in enumerate(("webauthn", "zt_authenticator"), start=1):
            intent_id = create_poia_intent(
                action=body["action"],
                scope=body["scope"],
                context=body["context"],
                original_request_body=body,
            )
            intent_ids.append(intent_id)
            record = poia_store.intents[intent_id]
            create_trial_record(
                trial_id=f"P01-{'W' if backend == 'webauthn' else 'Z'}-T01",
                study_run_id="test",
                participant_id="P01",
                signing_backend=backend,
                mutation_stage="none",
                mutation_type="none",
                original_request_id=str(record.original_request_id),
                intent_id=intent_id,
                task_body=body,
                displayed_body=body,
                mutations=[],
                expected_participant_decision="sign",
            )

        request = Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/api/poia/pending",
                "headers": [],
                "session": {"user_id": self.user_id},
            }
        )
        response = poia_routes.api_poia_pending(self.user_id, request, force=1)
        pending = json.loads(response.body)
        self.assertEqual(pending["intent_id"], intent_ids[1])
        self.assertNotEqual(pending["intent_id"], intent_ids[0])


if __name__ == "__main__":
    unittest.main()
