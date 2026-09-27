import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path


class OriginalRequestBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        from app import db
        from app.core import poia_store

        self.temporary = tempfile.TemporaryDirectory()
        db.DB_PATH = Path(self.temporary.name) / "bank.db"
        db.init_db()
        poia_store.intents.clear()
        poia_store.challenges.clear()
        poia_store.proofs.clear()
        with db.db_connect() as conn:
            self.user_id = conn.execute(
                "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)",
                ("binding@example.invalid", "unused", int(time.time())),
            ).lastrowid

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_exact_intent_matches_append_only_original_request(self) -> None:
        from app import db
        from app.core import create_poia_intent, original_request_binding_reason, poia_store

        intent_id = create_poia_intent(
            action="transfer",
            scope={"amount": 100, "currency": "USD", "external_account": "9007"},
            context={"rp_id": "poia-demo-bank", "user_id": self.user_id},
        )
        record = poia_store.intents[intent_id]
        self.assertIsNone(original_request_binding_reason(record))

        with db.db_connect() as conn:
            row = conn.execute(
                "SELECT canonical_body, canonical_sha256 FROM poia_original_requests WHERE request_id = ?",
                (record.original_request_id,),
            ).fetchone()
        self.assertEqual(json.loads(row["canonical_body"]), record.intent_body)
        self.assertEqual(row["canonical_sha256"], record.original_request_hash)

    def test_pre_display_mutation_is_rejected_against_original_order(self) -> None:
        from app.core import create_poia_intent, original_request_binding_reason, poia_store
        from app.intent_codec import build_intent

        original = build_intent(
            action="transfer",
            scope={"amount": 100, "currency": "USD", "external_account": "9007"},
            context={"rp_id": "poia-demo-bank", "user_id": self.user_id},
        )
        intent_id = create_poia_intent(
            action="transfer",
            scope={"amount": 1000, "currency": "USD", "external_account": "9007"},
            context={"rp_id": "poia-demo-bank", "user_id": self.user_id},
            original_request_body=original,
        )
        self.assertEqual(
            original_request_binding_reason(poia_store.intents[intent_id]),
            "original_request_mismatch",
        )

    def test_original_request_rows_cannot_be_updated_or_deleted(self) -> None:
        from app import db
        from app.core import create_poia_intent, poia_store

        intent_id = create_poia_intent(
            action="transfer",
            scope={"amount": 100, "currency": "USD", "external_account": "9007"},
            context={"rp_id": "poia-demo-bank", "user_id": self.user_id},
        )
        request_id = poia_store.intents[intent_id].original_request_id
        with self.assertRaises(sqlite3.IntegrityError):
            with db.db_connect() as conn:
                conn.execute(
                    "UPDATE poia_original_requests SET canonical_sha256 = 'changed' WHERE request_id = ?",
                    (request_id,),
                )
        with self.assertRaises(sqlite3.IntegrityError):
            with db.db_connect() as conn:
                conn.execute("DELETE FROM poia_original_requests WHERE request_id = ?", (request_id,))


if __name__ == "__main__":
    unittest.main()
