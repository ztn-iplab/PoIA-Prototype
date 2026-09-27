import tempfile
import time
import unittest
from pathlib import Path


class HumanStudyCrossOperationTests(unittest.TestCase):
    def setUp(self) -> None:
        from app import db

        self._directory = tempfile.TemporaryDirectory()
        self._previous_path = db.DB_PATH
        db.DB_PATH = Path(self._directory.name) / "bank.db"
        db.init_db()
        with db.db_connect() as conn:
            self.user_id = conn.execute(
                "INSERT INTO users (email, password_hash, is_admin, created_at) "
                "VALUES (?, ?, 0, ?)",
                ("cross-operation@example.invalid", "unused", int(time.time())),
            ).lastrowid
            self.account_id = conn.execute(
                "INSERT INTO accounts (user_id, account_type, balance, created_at) "
                "VALUES (?, 'checking', 1000, ?)",
                (self.user_id, int(time.time())),
            ).lastrowid

    def tearDown(self) -> None:
        from app import db

        db.DB_PATH = self._previous_path
        self._directory.cleanup()

    def test_transfer_repurposed_to_statement_export_retains_original_order(self) -> None:
        from app.core import create_poia_intent, original_request_binding_reason, poia_store
        from app.human_study import apply_mutations
        from app.intent_codec import build_intent

        task = build_intent(
            action="transfer",
            scope={
                "from_account": self.account_id,
                "amount": 100,
                "currency": "USD",
                "external_account": "9007",
            },
            context={"rp_id": "poia-demo-bank", "user_id": self.user_id},
        )
        displayed = apply_mutations(
            task,
            [
                {"path": "action", "value": "statement_export"},
                {
                    "path": "scope",
                    "value": {
                        "account_id": str(self.account_id),
                        "txn_type": "",
                        "date_from": "2026-08-01",
                        "date_to": "2026-08-28",
                    },
                },
            ],
        )
        intent_id = create_poia_intent(
            action=displayed["action"],
            scope=displayed["scope"],
            context=displayed["context"],
            original_request_body=task,
        )

        self.assertEqual(displayed["action"], "statement_export")
        self.assertEqual(
            original_request_binding_reason(poia_store.intents[intent_id]),
            "original_request_mismatch",
        )

    def test_cloud_delete_changes_only_synthetic_resource_and_can_be_restored(self) -> None:
        from app.human_study import (
            ensure_cloud_resources,
            execute_cloud_study_action,
            list_cloud_resources,
            reset_cloud_resources,
        )

        ensure_cloud_resources(self.user_id)
        scope = {"resource_id": "production-recovery-backup"}
        accepted, reason = execute_cloud_study_action(
            self.user_id, "cloud_file_delete", scope
        )
        deleted = {
            row["resource_id"]: row for row in list_cloud_resources(self.user_id)
        }["production-recovery-backup"]

        self.assertTrue(accepted)
        self.assertIsNone(reason)
        self.assertEqual(deleted["status"], "deleted")

        reset_cloud_resources(self.user_id)
        restored = {
            row["resource_id"]: row for row in list_cloud_resources(self.user_id)
        }["production-recovery-backup"]
        self.assertEqual(restored["status"], "active")
        self.assertFalse(restored["public_access"])
        self.assertEqual(restored["version"], 1)

    def test_cloud_public_share_and_overwrite_have_distinct_state_effects(self) -> None:
        from app.human_study import (
            ensure_cloud_resources,
            execute_cloud_study_action,
            list_cloud_resources,
        )

        ensure_cloud_resources(self.user_id)
        resource_id = "identity-access-policy"
        execute_cloud_study_action(
            self.user_id, "cloud_file_share_public", {"resource_id": resource_id}
        )
        execute_cloud_study_action(
            self.user_id, "cloud_file_overwrite", {"resource_id": resource_id}
        )
        resource = {
            row["resource_id"]: row for row in list_cloud_resources(self.user_id)
        }[resource_id]

        self.assertTrue(resource["public_access"])
        self.assertEqual(resource["version"], 2)

    def test_diverse_schedule_and_high_consequence_scopes_are_validated(self) -> None:
        from collections import Counter

        from app.human_study import (
            PARTICIPANT_SCENARIOS,
            select_alternate_account,
            validate_study_operation,
            validate_study_ownership,
        )

        self.assertEqual(len(PARTICIPANT_SCENARIOS), 18)
        self.assertEqual(
            Counter(item["family"] for item in PARTICIPANT_SCENARIOS),
            Counter({"cloud": 6, "transfer": 5, "withdrawal": 3, "statement": 2, "beneficiary": 2}),
        )
        self.assertEqual(Counter(item["stage"] for item in PARTICIPANT_SCENARIOS)["none"], 6)
        validate_study_operation(
            "withdrawal", {"account_id": self.account_id, "amount": 25, "currency": "USD"}
        )
        validate_study_operation(
            "beneficiary_add",
            {"name": "Participant Choice", "bank": "Example Bank", "account_number": "77553311"},
        )
        validate_study_ownership(
            self.user_id,
            "beneficiary_add",
            {"name": "Participant Choice", "bank": "Example Bank", "account_number": "77553311"},
        )
        targets = {
            select_alternate_account(
                ["9007", "2148", "6732", "4815", "315902", "684217"],
                "9007",
                f"participant-seed-{index}",
            )
            for index in range(20)
        }
        self.assertNotIn("9007", targets)
        self.assertGreater(len(targets), 1)
        with self.assertRaises(ValueError):
            select_alternate_account(["9007", "not-an-account"], "9007", "seed")
        with self.assertRaises(ValueError):
            validate_study_operation(
                "beneficiary_add",
                {"name": "Line\nbreak", "bank": "Example Bank", "account_number": "77553311"},
            )
        for invalid in (-25, 0, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                validate_study_operation(
                    "withdrawal",
                    {"account_id": self.account_id, "amount": invalid, "currency": "USD"},
                )


if __name__ == "__main__":
    unittest.main()
