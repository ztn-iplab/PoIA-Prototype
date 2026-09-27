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
class MFAEnrollmentHTTPTests(unittest.TestCase):
    def test_totp_accepts_only_the_current_thirty_second_step(self) -> None:
        import pyotp

        from app.mfa_utils import verify_totp_code

        secret = "JBSWY3DPEHPK3PXP"
        totp = pyotp.TOTP(secret, interval=30)
        self.assertTrue(verify_totp_code(secret, totp.at(60), for_time=60))
        self.assertFalse(verify_totp_code(secret, totp.at(30), for_time=60))

    def test_expired_pending_totp_forces_fresh_enrollment(self) -> None:
        from app import db
        from app.main import app
        from app.settings import SESSION_SECRET

        with tempfile.TemporaryDirectory() as directory:
            db.DB_PATH = Path(directory) / "bank.db"
            db.init_db()
            with db.db_connect() as conn:
                user_id = conn.execute(
                    "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)",
                    ("expired-enrollment@example.invalid", "unused", int(time.time())),
                ).lastrowid
                conn.execute(
                    "INSERT INTO pending_totp (user_id, secret, email, expires_at) VALUES (?, ?, ?, ?)",
                    (user_id, "JBSWY3DPEHPK3PXP", "expired-enrollment@example.invalid", int(time.time()) - 1),
                )
                device_id = conn.execute(
                    "INSERT INTO devices (user_id, device_label, platform, created_at) VALUES (?, ?, ?, ?)",
                    (user_id, "Incomplete enrollment", "test", int(time.time()) - 2),
                ).lastrowid
                conn.execute(
                    "INSERT INTO device_keys (device_id, rp_id, key_type, public_key, created_at) VALUES (?, ?, ?, ?, ?)",
                    (device_id, "poia-demo-bank", "p256", "unused", int(time.time()) - 2),
                )

            session_data = base64.b64encode(json.dumps({"pre_mfa_user_id": user_id}).encode("utf-8"))
            session_cookie = TimestampSigner(str(SESSION_SECRET)).sign(session_data).decode("utf-8")
            with TestClient(app) as client:
                client.cookies.set("session", session_cookie)
                response = client.post("/mfa/verify", data={"otp": "123456"}, follow_redirects=False)
                setup_response = client.get("/api/mfa/setup")

            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.headers["location"], "/mfa/setup?reason=expired")
            self.assertEqual(setup_response.status_code, 200)
            self.assertIn("qr_code", setup_response.json())
            with db.db_connect() as conn:
                pending_count = conn.execute(
                    "SELECT COUNT(*) FROM pending_totp WHERE user_id = ?", (user_id,)
                ).fetchone()[0]
                device_count = conn.execute(
                    "SELECT COUNT(*) FROM devices WHERE user_id = ?", (user_id,)
                ).fetchone()[0]
            self.assertEqual(pending_count, 1)
            self.assertEqual(device_count, 0)

    def test_setup_payload_exposes_the_ten_minute_expiry(self) -> None:
        from app import db
        from app.main import app
        from app.settings import MFA_ENROLL_TTL_MINUTES, SESSION_SECRET

        with tempfile.TemporaryDirectory() as directory:
            db.DB_PATH = Path(directory) / "bank.db"
            db.init_db()
            with db.db_connect() as conn:
                user_id = conn.execute(
                    "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)",
                    ("expiry-payload@example.invalid", "unused", int(time.time())),
                ).lastrowid
            session_data = base64.b64encode(
                json.dumps({"pre_mfa_user_id": user_id}).encode("utf-8")
            )
            session_cookie = TimestampSigner(str(SESSION_SECRET)).sign(session_data).decode("utf-8")
            with TestClient(app) as client:
                client.cookies.set("session", session_cookie)
                response = client.get("/api/mfa/setup")

            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertLessEqual(
                payload["expires_at"] - payload["issued_at"],
                MFA_ENROLL_TTL_MINUTES * 60,
            )
            self.assertGreater(payload["expires_at"], payload["issued_at"])

    def test_totp_registration_cannot_revive_expired_enrollment(self) -> None:
        from app import db
        from app.main import app
        from app.mfa_utils import issue_enroll_token
        from app.settings import APP_RP_ID

        with tempfile.TemporaryDirectory() as directory:
            db.DB_PATH = Path(directory) / "bank.db"
            db.init_db()
            with db.db_connect() as conn:
                user_id = conn.execute(
                    "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)",
                    ("expired-register@example.invalid", "unused", int(time.time())),
                ).lastrowid
                pending_id = conn.execute(
                    "INSERT INTO pending_totp (user_id, secret, email, expires_at) VALUES (?, ?, ?, ?)",
                    (
                        user_id,
                        "JBSWY3DPEHPK3PXP",
                        "expired-register@example.invalid",
                        int(time.time()) - 1,
                    ),
                ).lastrowid
            token = issue_enroll_token(
                {
                    "pending_id": pending_id,
                    "user_id": user_id,
                    "email": "expired-register@example.invalid",
                    "rp_id": APP_RP_ID,
                }
            )
            body = {
                "user_id": str(user_id),
                "rp_id": APP_RP_ID,
                "account_name": "expired-register@example.invalid",
                "issuer": "PoIA Bank",
            }
            with TestClient(app) as client:
                missing_token = client.post("/api/auth/totp/register", json=body)
                expired = client.post(
                    "/api/auth/totp/register",
                    json={**body, "enroll_token": token},
                )

            self.assertEqual(missing_token.status_code, 400)
            self.assertEqual(missing_token.json()["detail"], "missing_fields")
            self.assertEqual(expired.status_code, 400)
            self.assertEqual(expired.json()["detail"], "pending_expired")
            with db.db_connect() as conn:
                self.assertEqual(
                    conn.execute(
                        "SELECT COUNT(*) FROM pending_totp WHERE user_id = ?",
                        (user_id,),
                    ).fetchone()[0],
                    0,
                )

    def test_same_account_cannot_create_two_device_registrations(self) -> None:
        from app import db
        from app.main import app
        from app.mfa_utils import issue_enroll_token
        from app.settings import APP_RP_ID

        with tempfile.TemporaryDirectory() as directory:
            db.DB_PATH = Path(directory) / "bank.db"
            db.init_db()
            with db.db_connect() as conn:
                user_id = conn.execute(
                    "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)",
                    ("single-registration@example.invalid", "unused", int(time.time())),
                ).lastrowid
                pending_id = conn.execute(
                    "INSERT INTO pending_totp (user_id, secret, email, expires_at) VALUES (?, ?, ?, ?)",
                    (
                        user_id,
                        "JBSWY3DPEHPK3PXP",
                        "single-registration@example.invalid",
                        int(time.time()) + 600,
                    ),
                ).lastrowid

            token = issue_enroll_token(
                {
                    "pending_id": pending_id,
                    "user_id": user_id,
                    "email": "single-registration@example.invalid",
                    "rp_id": APP_RP_ID,
                }
            )
            enrollment = {
                "enroll_token": token,
                "email": "single-registration@example.invalid",
                "rp_id": APP_RP_ID,
                "public_key": "stable-public-key",
            }
            with TestClient(app) as client:
                first = client.post("/api/mfa/enroll", json=enrollment)
                retry = client.post("/api/mfa/enroll", json=enrollment)
                duplicate = client.post(
                    "/api/mfa/enroll", json={**enrollment, "public_key": "different-public-key"}
                )

            self.assertEqual(first.status_code, 200)
            self.assertEqual(retry.status_code, 200)
            self.assertEqual(first.json()["device"]["id"], retry.json()["device"]["id"])
            self.assertEqual(duplicate.status_code, 409)
            self.assertEqual(duplicate.json()["error"], "account_already_registered")
            with db.db_connect() as conn:
                device_count = conn.execute(
                    "SELECT COUNT(*) FROM devices WHERE user_id = ?", (user_id,)
                ).fetchone()[0]
            self.assertEqual(device_count, 1)

    def test_different_accounts_must_use_distinct_device_keys(self) -> None:
        from app import db
        from app.main import app
        from app.mfa_utils import issue_enroll_token
        from app.settings import APP_RP_ID

        with tempfile.TemporaryDirectory() as directory:
            db.DB_PATH = Path(directory) / "bank.db"
            db.init_db()
            enrollments = []
            with db.db_connect() as conn:
                for index in (1, 2):
                    email = f"shared-device-{index}@example.invalid"
                    user_id = conn.execute(
                        "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)",
                        (email, "unused", int(time.time())),
                    ).lastrowid
                    pending_id = conn.execute(
                        "INSERT INTO pending_totp (user_id, secret, email, expires_at) VALUES (?, ?, ?, ?)",
                        (user_id, "JBSWY3DPEHPK3PXP", email, int(time.time()) + 600),
                    ).lastrowid
                    enrollments.append(
                        {
                            "enroll_token": issue_enroll_token(
                                {
                                    "pending_id": pending_id,
                                    "user_id": user_id,
                                    "email": email,
                                    "rp_id": APP_RP_ID,
                                }
                            ),
                            "email": email,
                            "rp_id": APP_RP_ID,
                            "public_key": "shared-physical-device-key",
                        }
                    )

            with TestClient(app) as client:
                responses = [client.post("/api/mfa/enroll", json=item) for item in enrollments]

            self.assertEqual([response.status_code for response in responses], [200, 409])
            self.assertEqual(responses[1].json()["error"], "device_key_already_bound")
            with db.db_connect() as conn:
                registrations = conn.execute(
                    """
                    SELECT devices.user_id, COUNT(*) AS count
                    FROM devices
                    JOIN device_keys ON device_keys.device_id = devices.id
                    WHERE device_keys.public_key = ?
                    GROUP BY devices.user_id
                    ORDER BY devices.user_id
                    """,
                    ("shared-physical-device-key",),
                ).fetchall()
            self.assertEqual([row["count"] for row in registrations], [1])


if __name__ == "__main__":
    unittest.main()
