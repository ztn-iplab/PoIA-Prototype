import base64
import json
import tempfile
import time
import unittest
from pathlib import Path


class AdminUserManagementTests(unittest.TestCase):
    def setUp(self):
        from app import db
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        db.DB_PATH = Path(self.temp.name) / "bank.db"
        db.init_db()
        from app.main import app
        from fastapi.testclient import TestClient
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        with db.db_connect() as conn:
            self.admin = conn.execute(
                "INSERT INTO users(email,password_hash,is_admin,created_at,otp_secret,mfa_enrolled) "
                "VALUES ('admin@test.invalid','SECRET-PASSWORD',1,?,'ADMINSECRET',1)",
                (time.time(),),
            ).lastrowid
            self.customer = conn.execute(
                "INSERT INTO users(email,password_hash,is_admin,created_at,otp_secret,mfa_enrolled) "
                "VALUES ('customer@test.invalid','SECRET-PASSWORD',0,?,'CUSTOMERSECRET',1)",
                (time.time(),),
            ).lastrowid
            device_id = conn.execute(
                "INSERT INTO devices (user_id, device_label, platform, created_at) VALUES (?, ?, ?, ?)",
                (self.customer, "Customer device", "test", int(time.time())),
            ).lastrowid
            conn.execute(
                "INSERT INTO device_keys (device_id, rp_id, key_type, public_key, created_at) VALUES (?, ?, ?, ?, ?)",
                (device_id, "poia-demo-bank", "p256", "unused", int(time.time())),
            )
            conn.execute(
                "INSERT INTO totp_recovery_codes (user_id, code_hash, created_at) VALUES (?, 'deadbeef', ?)",
                (self.customer, int(time.time())),
            )

    def login(self, user_id):
        from itsdangerous import TimestampSigner
        from app.settings import SESSION_SECRET
        data = base64.b64encode(json.dumps({"user_id": user_id}).encode())
        self.client.cookies.set("session", TimestampSigner(str(SESSION_SECRET)).sign(data).decode())

    def test_reset_and_delete_require_admin(self):
        self.assertEqual(
            self.client.post(f"/admin/users/{self.customer}/reset", follow_redirects=False).status_code, 302
        )
        self.login(self.customer)
        resp = self.client.post(f"/admin/users/{self.customer}/reset", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.headers["location"], "/dashboard")

    def test_reset_clears_totp_devices_and_recovery_codes(self):
        from app import db
        self.login(self.admin)
        resp = self.client.post(f"/admin/users/{self.customer}/reset", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.headers["location"], "/admin/dashboard#users")
        with db.db_connect() as conn:
            user = conn.execute("SELECT * FROM users WHERE id = ?", (self.customer,)).fetchone()
            device_count = conn.execute("SELECT COUNT(*) FROM devices WHERE user_id = ?", (self.customer,)).fetchone()[0]
            code_count = conn.execute(
                "SELECT COUNT(*) FROM totp_recovery_codes WHERE user_id = ?", (self.customer,)
            ).fetchone()[0]
            audit = conn.execute(
                "SELECT action FROM audit_logs WHERE action = 'admin_account_reset'"
            ).fetchone()
        self.assertIsNone(user["otp_secret"])
        self.assertEqual(user["mfa_enrolled"], 0)
        self.assertEqual(device_count, 0)
        self.assertEqual(code_count, 0)
        self.assertIsNotNone(audit)
        dashboard = self.client.get("/admin/dashboard").text
        self.assertIn("must set up TOTP again", dashboard)

    def test_delete_disables_account_and_blocks_login(self):
        from app import db
        self.login(self.admin)
        resp = self.client.post(f"/admin/users/{self.customer}/delete", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        with db.db_connect() as conn:
            user = conn.execute("SELECT * FROM users WHERE id = ?", (self.customer,)).fetchone()
        self.assertEqual(user["disabled"], 1)
        self.assertNotEqual(user["password_hash"], "SECRET-PASSWORD")
        self.assertIsNone(user["otp_secret"])

        # A session cookie forged for the now-disabled user must be treated
        # as logged out everywhere, not just blocked at the login form.
        self.client.cookies.clear()
        self.login(self.customer)
        dashboard = self.client.get("/dashboard", follow_redirects=False)
        self.assertEqual(dashboard.status_code, 302)
        self.assertEqual(dashboard.headers["location"], "/login")

    def test_admin_cannot_delete_own_account(self):
        self.login(self.admin)
        resp = self.client.post(f"/admin/users/{self.admin}/delete", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        dashboard = self.client.get("/admin/dashboard").text
        self.assertIn("cannot delete your own account", dashboard)

    def test_reset_and_delete_of_missing_user_reports_not_found(self):
        self.login(self.admin)
        resp = self.client.post("/admin/users/999999/reset", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("Account not found.", self.client.get("/admin/dashboard").text)

    def test_pending_signup_shows_as_pending_not_raw_placeholder_email(self):
        # A user who has started signup but not finished MFA enrollment has no
        # confirmed identity yet (app/routes/auth.py stores a random
        # "pending-...@signup.invalid" placeholder on purpose, so no real
        # email or bank account exists until enrollment completes). The admin
        # dashboard must present that row as a clean "Pending signup" state,
        # not leak the internal placeholder address or make the row look like
        # a real, active user.
        resp = self.client.post(
            "/signup",
            data={
                "email": "pending-customer@test.invalid",
                "password": "Sup3rSecret!123",
                "confirm_password": "Sup3rSecret!123",
            },
            follow_redirects=False,
        )
        self.assertEqual(resp.status_code, 303)

        # The signup response itself sets a session cookie (for the pending
        # pre-MFA identity); the client's cookie jar must be cleared before
        # forging the admin's session, the same way test_delete_disables_
        # account_and_blocks_login has to clear it before switching identity
        # on one TestClient instance.
        self.client.cookies.clear()
        self.login(self.admin)
        dashboard = self.client.get("/admin/dashboard").text
        self.assertIn("Pending signup", dashboard)
        self.assertNotIn("@signup.invalid", dashboard)
        self.assertNotIn("No users yet.", dashboard)
        # A pending signup has nothing to reset yet; only removal makes sense.
        self.assertIn(">Remove<", dashboard)


if __name__ == "__main__":
    unittest.main()
