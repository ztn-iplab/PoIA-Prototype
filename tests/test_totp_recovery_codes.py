import base64
import json
import tempfile
import time
import unittest
from pathlib import Path


class TotpRecoveryCodeTests(unittest.TestCase):
    def _enroll(self, client, db):
        from app.mfa_utils import issue_enroll_token
        from app.settings import APP_RP_ID
        with db.db_connect() as conn:
            user_id = conn.execute(
                "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)",
                ("recovery-user@example.invalid", "unused", int(time.time())),
            ).lastrowid
            pending_id = conn.execute(
                "INSERT INTO pending_totp (user_id, secret, email, expires_at) VALUES (?, ?, ?, ?)",
                (user_id, "JBSWY3DPEHPK3PXP", "recovery-user@example.invalid", int(time.time()) + 600),
            ).lastrowid
        token = issue_enroll_token(
            {
                "pending_id": pending_id,
                "user_id": user_id,
                "email": "recovery-user@example.invalid",
                "rp_id": APP_RP_ID,
            }
        )
        response = client.post(
            "/api/mfa/totp/register",
            json={
                "user_id": str(user_id),
                "rp_id": APP_RP_ID,
                "account_name": "recovery-user@example.invalid",
                "issuer": "PoIA Bank",
                "enroll_token": token,
            },
        )
        self.assertEqual(response.status_code, 200)
        return user_id, response.json()["recovery_codes"]

    def test_registration_persists_hashed_recovery_codes(self):
        from app import db
        from app.main import app
        from app.security import hash_recovery_code
        from fastapi.testclient import TestClient

        with tempfile.TemporaryDirectory() as directory:
            db.DB_PATH = Path(directory) / "bank.db"
            db.init_db()
            with TestClient(app) as client:
                user_id, codes = self._enroll(client, db)

            self.assertEqual(len(codes), 8)
            with db.db_connect() as conn:
                rows = conn.execute(
                    "SELECT code_hash, used_at FROM totp_recovery_codes WHERE user_id = ?", (user_id,)
                ).fetchall()
            self.assertEqual(len(rows), 8)
            self.assertTrue(all(row["used_at"] is None for row in rows))
            stored_hashes = {row["code_hash"] for row in rows}
            self.assertEqual(stored_hashes, {hash_recovery_code(code) for code in codes})

    def test_valid_unused_code_resets_totp_and_requires_relogin(self):
        from app import db
        from app.main import app
        from app.settings import SESSION_SECRET
        from fastapi.testclient import TestClient
        from itsdangerous import TimestampSigner

        with tempfile.TemporaryDirectory() as directory:
            db.DB_PATH = Path(directory) / "bank.db"
            db.init_db()
            with TestClient(app) as client:
                user_id, codes = self._enroll(client, db)
                # Simulate having actually completed enrollment (otp_secret set),
                # then losing the device -- the scenario recovery codes exist for.
                with db.db_connect() as conn:
                    conn.execute(
                        "UPDATE users SET otp_secret = 'JBSWY3DPEHPK3PXP', mfa_enrolled = 1 WHERE id = ?",
                        (user_id,),
                    )
                session_data = base64.b64encode(json.dumps({"pre_mfa_user_id": user_id}).encode())
                client.cookies.set("session", TimestampSigner(str(SESSION_SECRET)).sign(session_data).decode())

                page = client.get("/mfa/recovery")
                self.assertEqual(page.status_code, 200)

                first_use = client.post("/mfa/recovery", data={"code": codes[0]}, follow_redirects=False)
                self.assertEqual(first_use.status_code, 303)
                self.assertEqual(first_use.headers["location"], "/login")

                with db.db_connect() as conn:
                    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                    unused = conn.execute(
                        "SELECT COUNT(*) FROM totp_recovery_codes WHERE user_id = ? AND used_at IS NULL",
                        (user_id,),
                    ).fetchone()[0]
                self.assertIsNone(user["otp_secret"])
                self.assertEqual(user["mfa_enrolled"], 0)
                self.assertEqual(unused, 7)

                # The session was cleared of pre_mfa_user_id, so a second
                # attempt with the same (now-consumed) code and no active
                # login-in-progress session must not succeed either.
                reuse = client.post("/mfa/recovery", data={"code": codes[0]}, follow_redirects=False)
                self.assertEqual(reuse.status_code, 302)
                self.assertEqual(reuse.headers["location"], "/login")

    def test_invalid_code_is_rejected_without_side_effects(self):
        from app import db
        from app.main import app
        from app.settings import SESSION_SECRET
        from fastapi.testclient import TestClient
        from itsdangerous import TimestampSigner

        with tempfile.TemporaryDirectory() as directory:
            db.DB_PATH = Path(directory) / "bank.db"
            db.init_db()
            with TestClient(app) as client:
                user_id, _codes = self._enroll(client, db)
                session_data = base64.b64encode(json.dumps({"pre_mfa_user_id": user_id}).encode())
                client.cookies.set("session", TimestampSigner(str(SESSION_SECRET)).sign(session_data).decode())

                response = client.post("/mfa/recovery", data={"code": "not-a-real-code"})
                self.assertEqual(response.status_code, 200)
                self.assertIn("Invalid or already-used recovery code.", response.text)

                with db.db_connect() as conn:
                    unused = conn.execute(
                        "SELECT COUNT(*) FROM totp_recovery_codes WHERE user_id = ? AND used_at IS NULL",
                        (user_id,),
                    ).fetchone()[0]
                self.assertEqual(unused, 8)


if __name__ == "__main__":
    unittest.main()
