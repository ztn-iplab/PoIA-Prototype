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
class TransferValidationTests(unittest.TestCase):
    def test_external_account_must_be_numeric_before_intent_creation(self) -> None:
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
                    ("transfer-validation@example.invalid", "unused", int(time.time())),
                ).lastrowid
                account_id = conn.execute(
                    "INSERT INTO accounts (user_id, account_type, balance, created_at) VALUES (?, ?, ?, ?)",
                    (user_id, "checking", 1000.0, int(time.time())),
                ).lastrowid

            session_data = base64.b64encode(json.dumps({"user_id": user_id}).encode("utf-8"))
            session_cookie = TimestampSigner(str(SESSION_SECRET)).sign(session_data).decode("utf-8")

            with TestClient(app) as client:
                client.cookies.set("session", session_cookie)
                response = client.post(
                    "/transfer",
                    data={
                        "from_account": str(account_id),
                        "amount": "250.00",
                        "to_type": "external",
                        "external_account": "ABC123",
                        "currency": "USD",
                    },
                    follow_redirects=False,
                )
                negative_response = client.post(
                    "/transfer",
                    data={
                        "from_account": str(account_id),
                        "amount": "-25.00",
                        "to_type": "external",
                        "external_account": "9007",
                        "currency": "USD",
                    },
                    follow_redirects=False,
                )
                non_finite_response = client.post(
                    "/transfer",
                    data={
                        "from_account": str(account_id),
                        "amount": "nan",
                        "to_type": "external",
                        "external_account": "9007",
                        "currency": "USD",
                    },
                    follow_redirects=False,
                )

            self.assertEqual(response.status_code, 200)
            self.assertIn("External account must contain numbers only.", response.text)
            self.assertIn("Amount must be greater than 0.", negative_response.text)
            self.assertIn("Amount must be greater than 0.", non_finite_response.text)
            self.assertEqual(poia_store.intents, {})


if __name__ == "__main__":
    unittest.main()
