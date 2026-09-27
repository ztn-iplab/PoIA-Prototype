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


class DisplayVariantAssignmentTests(unittest.TestCase):
    """Unit coverage for the Dataset 2 (display-variant comparison) balancing
    logic in app/human_study.py, independent of any HTTP route."""

    def setUp(self) -> None:
        from app import db

        self.directory = tempfile.TemporaryDirectory()
        self.previous_path = db.DB_PATH
        db.DB_PATH = Path(self.directory.name) / "bank.db"
        db.init_db()
        with db.db_connect() as conn:
            self.user_id = conn.execute(
                "INSERT INTO users (email, password_hash, is_admin, created_at) "
                "VALUES ('variant@example.invalid', 'unused', 0, ?)",
                (int(time.time()),),
            ).lastrowid

    def tearDown(self) -> None:
        from app import db

        db.DB_PATH = self.previous_path
        self.directory.cleanup()

    def test_auto_assignment_stays_balanced_within_one(self) -> None:
        from app import db
        from app.human_study import create_participant_session

        tally = {"legacy": 0, "redesigned": 0}
        for _ in range(21):
            session = create_participant_session(self.user_id)
            self.assertIn(session["display_variant"], ("legacy", "redesigned"))
            tally[session["display_variant"]] += 1
            self.assertLessEqual(abs(tally["legacy"] - tally["redesigned"]), 1)

        with db.db_connect() as conn:
            stored = conn.execute(
                "SELECT display_variant, COUNT(*) c FROM poia_participant_sessions "
                "GROUP BY display_variant"
            ).fetchall()
        stored_tally = {row["display_variant"]: row["c"] for row in stored}
        self.assertLessEqual(abs(stored_tally.get("legacy", 0) - stored_tally.get("redesigned", 0)), 1)
        self.assertEqual(sum(stored_tally.values()), 21)

    def test_explicit_override_is_honored_and_validated(self) -> None:
        from app.human_study import create_participant_session

        forced = create_participant_session(self.user_id, display_variant="legacy")
        self.assertEqual(forced["display_variant"], "legacy")

        with self.assertRaises(ValueError):
            create_participant_session(self.user_id, display_variant="bogus")

    def test_default_session_column_is_redesigned_for_non_study_sessions(self) -> None:
        # A row created without going through create_participant_session (the
        # column's SQL DEFAULT) must still resolve to the production layout,
        # never to the study-only 'legacy' arm.
        from app import db

        with db.db_connect() as conn:
            conn.execute(
                "INSERT INTO poia_participant_sessions "
                "(session_id, participant_id, study_run_id, cohort, user_id, schedule_json, created_at) "
                "VALUES ('s1', 'P-TEST', 'legacy', 'webauthn_first', ?, '[]', ?)",
                (self.user_id, time.time()),
            )
            row = conn.execute(
                "SELECT display_variant FROM poia_participant_sessions WHERE session_id = 's1'"
            ).fetchone()
        self.assertEqual(row["display_variant"], "redesigned")


@unittest.skipUnless(HTTP_DEPS_AVAILABLE, "FastAPI HTTP test dependencies are not installed")
class DisplayVariantRenderingHTTPTests(unittest.TestCase):
    """Confirms the assigned arm actually reaches the rendered page, and that
    ordinary (non-study) banking pages are unaffected."""

    def _make_ready_user(self, db, email: str) -> int:
        with db.db_connect() as conn:
            user_id = conn.execute(
                "INSERT INTO users (email, password_hash, is_admin, created_at, poia_zt_enabled) "
                "VALUES (?, 'unused', 0, ?, 1)",
                (email, int(time.time())),
            ).lastrowid
            conn.execute(
                "INSERT INTO accounts (user_id, account_type, balance, created_at) "
                "VALUES (?, 'checking', 5000, ?)",
                (user_id, int(time.time())),
            )
            conn.execute(
                "INSERT INTO webauthn_credentials "
                "(user_id, credential_id, public_key, sign_count, transports, created_at) "
                "VALUES (?, 'cred', 'test-key', 0, '[]', ?)",
                (user_id, int(time.time())),
            )
            account_id = conn.execute(
                "SELECT id FROM accounts WHERE user_id = ?", (user_id,)
            ).fetchone()["id"]
        return user_id, account_id

    def test_legacy_and_redesigned_sessions_render_their_assigned_variant(self) -> None:
        from app import db
        from app.main import app
        from app.routes import poia as poia_routes
        from app.human_study import create_participant_session
        from app.settings import SESSION_SECRET

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db.DB_PATH = root / "bank.db"
            db.init_db()
            poia_routes.POIA_EXPERIMENT_MODE = True
            user_id, account_id = self._make_ready_user(db, "variant-http@example.invalid")

            legacy_session = create_participant_session(user_id, display_variant="legacy")
            redesigned_session = create_participant_session(user_id, display_variant="redesigned")

            session_data = base64.b64encode(json.dumps({"user_id": user_id}).encode())
            session_cookie = TimestampSigner(str(SESSION_SECRET)).sign(session_data).decode()
            with TestClient(app) as client:
                client.cookies.set("session", session_cookie)

                def start_first_trial_and_load(session_id: str) -> str:
                    poia_routes.ensure_cloud_resources(user_id)
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
                    with db.db_connect() as conn:
                        trial = conn.execute(
                            "SELECT intent_id FROM poia_human_study_trials "
                            "WHERE participant_session_id = ? ORDER BY created_at DESC LIMIT 1",
                            (session_id,),
                        ).fetchone()
                    page = client.get(
                        "/poia/experiment/participant",
                        params={"session": session_id, "poia_intent": trial["intent_id"]},
                    )
                    self.assertEqual(page.status_code, 200)
                    return page.text

                legacy_html = start_first_trial_and_load(legacy_session["session_id"])
                self.assertIn('data-display-variant="legacy"', legacy_html)

                redesigned_html = start_first_trial_and_load(redesigned_session["session_id"])
                self.assertIn('data-display-variant="redesigned"', redesigned_html)

                # An ordinary banking page (an in-flight real transfer, not a
                # study session at all) must still default to the production
                # layout, regardless of whichever arm the most recently
                # created *study* session above was assigned.
                transfer = client.post(
                    "/transfer",
                    data={
                        "from_account": str(account_id),
                        "amount": "10",
                        "currency": "USD",
                        "to_type": "external",
                        "external_account": "417723",
                    },
                    follow_redirects=False,
                )
                self.assertEqual(transfer.status_code, 303)
                confirm_url = transfer.headers["location"]
                confirm_page = client.get(confirm_url)
                self.assertEqual(confirm_page.status_code, 200)
                self.assertIn('data-display-variant="redesigned"', confirm_page.text)
                self.assertNotIn('data-display-variant="legacy"', confirm_page.text)


if __name__ == "__main__":
    unittest.main()
