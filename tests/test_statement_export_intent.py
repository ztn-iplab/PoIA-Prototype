import base64
import json
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse


try:
    import fastapi  # noqa: F401
    from fastapi.testclient import TestClient
    from itsdangerous import TimestampSigner

    HTTP_DEPS_AVAILABLE = True
except ModuleNotFoundError:
    HTTP_DEPS_AVAILABLE = False


@unittest.skipUnless(HTTP_DEPS_AVAILABLE, "FastAPI HTTP test dependencies are not installed")
class StatementExportIntentTests(unittest.TestCase):
    def test_statement_export_intent_preserves_selected_filters(self) -> None:
        from app import db, poia_metrics
        from app.core import poia_store
        from app.main import app
        from app.settings import SESSION_SECRET

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db.DB_PATH = root / "bank.db"
            poia_metrics.METRICS_CSV = root / "metrics.csv"
            db.init_db()
            poia_store.intents.clear()
            poia_store.challenges.clear()
            poia_store.proofs.clear()

            with db.db_connect() as conn:
                user_id = conn.execute(
                    "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)",
                    ("statements@example.invalid", "unused", int(time.time())),
                ).lastrowid
                account_id = conn.execute(
                    "INSERT INTO accounts (user_id, account_type, balance, created_at) VALUES (?, ?, ?, ?)",
                    (user_id, "checking", 1000.0, int(time.time())),
                ).lastrowid

            session_data = base64.b64encode(json.dumps({"user_id": user_id}).encode("utf-8"))
            session_cookie = TimestampSigner(str(SESSION_SECRET)).sign(session_data).decode("utf-8")
            with TestClient(app) as client:
                client.cookies.set("session", session_cookie)
                response = client.get(
                    "/statements.csv",
                    params={
                        "account_id": str(account_id),
                        "txn_type": "deposit",
                        "date_from": "2026-08-01",
                        "date_to": "2026-08-24",
                    },
                    follow_redirects=False,
                )

            self.assertEqual(response.status_code, 303)
            location = response.headers["location"]
            parsed = urlparse(location)
            query = parse_qs(parsed.query)
            self.assertEqual(parsed.path, "/statements")
            self.assertEqual(query["account_id"], [str(account_id)])
            self.assertEqual(query["txn_type"], ["deposit"])
            self.assertEqual(query["date_from"], ["2026-08-01"])
            self.assertEqual(query["date_to"], ["2026-08-24"])

            intent_id = query["poia_intent"][0]
            scope = poia_store.intents[intent_id].intent_body["scope"]
            self.assertEqual(
                scope,
                {
                    "account_id": str(account_id),
                    "txn_type": "deposit",
                    "date_from": "2026-08-01",
                    "date_to": "2026-08-24",
                },
            )

    def test_export_link_reads_current_filter_form_values(self) -> None:
        template = (Path(__file__).resolve().parents[1] / "app" / "templates" / "statements.html").read_text(
            encoding="utf-8"
        )

        self.assertIn('id="statement-filters"', template)
        self.assertIn('id="statement-export-link"', template)
        self.assertIn("new FormData(form)", template)
        self.assertIn("URLSearchParams", template)
        self.assertIn("exportLink.href = `/statements.csv?${params.toString()}`", template)


if __name__ == "__main__":
    unittest.main()
