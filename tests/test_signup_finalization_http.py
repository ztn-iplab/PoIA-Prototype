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
class SignupFinalizationHTTPTests(unittest.TestCase):
    def setUp(self) -> None:
        from app import db

        self.original_db_path = db.DB_PATH
        self.directory = tempfile.TemporaryDirectory()
        db.DB_PATH = Path(self.directory.name) / "bank.db"
        db.init_db()

    def tearDown(self) -> None:
        from app import db

        db.DB_PATH = self.original_db_path
        self.directory.cleanup()

    def test_signup_keeps_email_and_accounts_out_of_permanent_records(self) -> None:
        from app import db
        from app.main import app

        email = "unfinished@example.invalid"
        with TestClient(app) as client:
            started = client.post(
                "/signup",
                data={"email": email.upper(), "password": "Strong!Password123"},
                follow_redirects=False,
            )
            setup = client.get("/api/mfa/setup")

        self.assertEqual(started.status_code, 303)
        self.assertEqual(started.headers["location"], "/mfa/setup")
        self.assertEqual(setup.status_code, 200)
        with db.db_connect() as conn:
            permanent = conn.execute(
                "SELECT id FROM users WHERE lower(email) = ?", (email,)
            ).fetchone()
            provisional = conn.execute(
                "SELECT * FROM users WHERE signup_pending = 1"
            ).fetchone()
            pending = conn.execute(
                "SELECT * FROM pending_totp WHERE user_id = ?", (provisional["id"],)
            ).fetchone()
            account_count = conn.execute(
                "SELECT COUNT(*) FROM accounts WHERE user_id = ?", (provisional["id"],)
            ).fetchone()[0]

        self.assertIsNone(permanent)
        self.assertTrue(provisional["email"].endswith("@signup.invalid"))
        self.assertNotEqual(pending["email"], email)
        self.assertTrue(pending["email"].endswith("@signup.invalid"))
        self.assertEqual(account_count, 0)

    def test_retry_replaces_provisional_signup_without_resuming_by_password(self) -> None:
        from app import db
        from app.main import app

        email = "retry@example.invalid"
        with TestClient(app) as first:
            first.post(
                "/signup",
                data={"email": email, "password": "Original!Password123"},
                follow_redirects=False,
            )
            first.get("/api/mfa/setup")

        with TestClient(app) as retry:
            response = retry.post(
                "/signup",
                data={"email": email, "password": "Different!Password123"},
                follow_redirects=False,
            )

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/mfa/setup")
        with db.db_connect() as conn:
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM users WHERE signup_pending = 1").fetchone()[0],
                1,
            )
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM users WHERE lower(email) = ?", (email,)).fetchone()[0],
                0,
            )
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0], 0)

    def test_approved_device_finalizes_identity_and_accounts_atomically(self) -> None:
        from app import db
        from app.main import app
        from app.settings import APP_RP_ID, SESSION_SECRET

        email = "completed@example.invalid"
        password = "Completed!Password123"
        with db.db_connect() as conn:
            user_id = conn.execute(
                """
                INSERT INTO users
                    (email, password_hash, is_admin, signup_pending, created_at,
                     otp_secret, otp_email_label, otp_rp_id)
                VALUES (?, 'hash', 0, 1, ?, 'secret', ?, ?)
                """,
                ("pending-finalize@signup.invalid", int(time.time()), email, APP_RP_ID),
            ).lastrowid
            device_id = conn.execute(
                "INSERT INTO devices (user_id, device_label, platform, created_at) VALUES (?, 'Phone', 'test', ?)",
                (user_id, int(time.time())),
            ).lastrowid
            challenge_id = conn.execute(
                """
                INSERT INTO login_challenges
                    (user_id, device_id, rp_id, nonce, otp_hash, status, created_at, expires_at)
                VALUES (?, ?, ?, 'nonce', 'otp', 'ok', ?, ?)
                """,
                (user_id, device_id, APP_RP_ID, int(time.time()), int(time.time()) + 120),
            ).lastrowid

        session_data = base64.b64encode(
            json.dumps(
                {
                    "pre_mfa_user_id": user_id,
                    "pre_mfa_email": email,
                    "pending_login_id": challenge_id,
                    "totp_verified": True,
                }
            ).encode("utf-8")
        )
        session_cookie = TimestampSigner(str(SESSION_SECRET)).sign(session_data).decode("utf-8")
        with TestClient(app) as client:
            client.cookies.set("session", session_cookie)
            completed = client.get("/api/mfa/device-status")

        self.assertEqual(completed.status_code, 200)
        self.assertEqual(completed.json()["status"], "ok")
        with db.db_connect() as conn:
            user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            accounts = conn.execute(
                "SELECT account_type FROM accounts WHERE user_id = ? ORDER BY account_type",
                (user_id,),
            ).fetchall()
        self.assertEqual(user["email"], email)
        self.assertEqual(user["signup_pending"], 0)
        self.assertEqual(user["mfa_enrolled"], 1)
        self.assertEqual([row["account_type"] for row in accounts], ["checking", "savings"])

    def test_completed_account_still_blocks_duplicate_signup(self) -> None:
        from app import db
        from app.main import app

        email = "existing@example.invalid"
        with db.db_connect() as conn:
            conn.execute(
                "INSERT INTO users (email, password_hash, is_admin, signup_pending, created_at) VALUES (?, 'hash', 0, 0, ?)",
                (email, int(time.time())),
            )
        with TestClient(app) as client:
            duplicate = client.post(
                "/signup",
                data={"email": email, "password": "Another!Password123"},
                follow_redirects=False,
            )

        self.assertEqual(duplicate.status_code, 200)
        self.assertIn("Email already registered", duplicate.text)


if __name__ == "__main__":
    unittest.main()
