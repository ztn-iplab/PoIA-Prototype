"""Coverage for the Jian, Bisantz & Drury (2000) trust-in-automation short
scale added to the post-session questionnaire: (a) an end-to-end HTTP check
that submitting the 7 trust items through the real debrief route stores them
on poia_participant_sessions.post_session_response, and (b) a hand-verified
arithmetic check of the composite-score function in
scripts/analyze_human_study.py, including its by-display_variant breakout.
"""

import base64
import json
import tempfile
import time
import unittest
from pathlib import Path

from scripts.analyze_human_study import (
    TRUST_SCALE_ITEMS,
    TRUST_SCALE_VALUE_SCORES,
    trust_composite,
    trust_summary,
)

try:
    import fastapi  # noqa: F401
    from fastapi.testclient import TestClient
    from itsdangerous import TimestampSigner

    HTTP_DEPS_AVAILABLE = True
except ModuleNotFoundError:
    HTTP_DEPS_AVAILABLE = False


@unittest.skipUnless(HTTP_DEPS_AVAILABLE, "FastAPI HTTP test dependencies are not installed")
class TrustInstrumentHTTPTests(unittest.TestCase):
    """Submits a debrief payload through the real HTTP route and confirms the
    7 trust items round-trip into the stored post_session_response, the same
    way tests/test_participant_workspace_http.py checks the other items."""

    def test_trust_items_are_stored_by_the_debrief_route(self) -> None:
        from app import db
        from app.main import app
        from app.human_study import create_participant_session
        from app.settings import SESSION_SECRET

        with tempfile.TemporaryDirectory() as directory:
            db.DB_PATH = Path(directory) / "bank.db"
            db.init_db()
            with db.db_connect() as conn:
                user_id = conn.execute(
                    "INSERT INTO users (email, password_hash, is_admin, created_at) "
                    "VALUES ('trust-scale@example.invalid', 'unused', 0, ?)",
                    (int(time.time()),),
                ).lastrowid

            session = create_participant_session(user_id)
            session_id = session["session_id"]
            with db.db_connect() as conn:
                conn.execute(
                    "UPDATE poia_participant_sessions SET status = 'complete' WHERE session_id = ?",
                    (session_id,),
                )

            session_data = base64.b64encode(json.dumps({"user_id": user_id}).encode())
            session_cookie = TimestampSigner(str(SESSION_SECRET)).sign(session_data).decode()

            with TestClient(app) as client:
                client.cookies.set("session", session_cookie)
                trust_payload = {
                    "trust_confident": "agree",
                    "trust_secure": "somewhat_agree",
                    "trust_integrity": "strongly_agree",
                    "trust_dependable": "agree",
                    "trust_reliable": "neutral",
                    "trust_overall": "agree",
                    "trust_familiar": "somewhat_agree",
                }
                response = client.post(
                    "/api/poia/experiment/participant/debrief",
                    json={
                        "session_id": session_id,
                        "phase": "questions",
                        "purpose_guess": "Whether the confirmation screen is trustworthy.",
                        "noticed_unusual": "no",
                        "unusual_detail": "",
                        "semantic_fields": ["amount", "destination"],
                        "semantic_other": "",
                        "matching_ease": "easy",
                        "age_band": "35_44",
                        "banking_frequency": "weekly",
                        "passkey_familiarity": "occasional",
                        "authenticator_familiarity": "heard_of",
                        "technical_experience": "general_it",
                        "webauthn_review_ease": "easy",
                        "zt_review_ease": "very_easy",
                        "backend_preference": "no_preference",
                        "preference_reason": "Both felt about the same to review.",
                        "final_comment": "",
                        **trust_payload,
                    },
                )
                self.assertEqual(response.status_code, 200)

            with db.db_connect() as conn:
                stored = json.loads(
                    conn.execute(
                        "SELECT post_session_response FROM poia_participant_sessions WHERE session_id = ?",
                        (session_id,),
                    ).fetchone()[0]
                )
            for key, expected in trust_payload.items():
                self.assertEqual(stored[key], expected)
            # Every item the questionnaire asks about is exactly TRUST_SCALE_ITEMS --
            # nothing dropped, nothing extra silently added.
            self.assertEqual(set(trust_payload), set(TRUST_SCALE_ITEMS))

    def test_debrief_route_rejects_a_missing_trust_item(self) -> None:
        from app import db
        from app.main import app
        from app.human_study import create_participant_session
        from app.settings import SESSION_SECRET

        with tempfile.TemporaryDirectory() as directory:
            db.DB_PATH = Path(directory) / "bank.db"
            db.init_db()
            with db.db_connect() as conn:
                user_id = conn.execute(
                    "INSERT INTO users (email, password_hash, is_admin, created_at) "
                    "VALUES ('trust-scale-missing@example.invalid', 'unused', 0, ?)",
                    (int(time.time()),),
                ).lastrowid

            session = create_participant_session(user_id)
            session_id = session["session_id"]
            with db.db_connect() as conn:
                conn.execute(
                    "UPDATE poia_participant_sessions SET status = 'complete' WHERE session_id = ?",
                    (session_id,),
                )

            session_data = base64.b64encode(json.dumps({"user_id": user_id}).encode())
            session_cookie = TimestampSigner(str(SESSION_SECRET)).sign(session_data).decode()

            with TestClient(app) as client:
                client.cookies.set("session", session_cookie)
                payload = {
                    "session_id": session_id,
                    "phase": "questions",
                    "purpose_guess": "Whether the confirmation screen is trustworthy.",
                    "noticed_unusual": "no",
                    "unusual_detail": "",
                    "semantic_fields": ["amount"],
                    "semantic_other": "",
                    "matching_ease": "easy",
                    "age_band": "35_44",
                    "banking_frequency": "weekly",
                    "passkey_familiarity": "occasional",
                    "authenticator_familiarity": "heard_of",
                    "technical_experience": "general_it",
                    "webauthn_review_ease": "easy",
                    "zt_review_ease": "very_easy",
                    "backend_preference": "no_preference",
                    "preference_reason": "Both felt about the same to review.",
                    "final_comment": "",
                    "trust_confident": "agree",
                    "trust_secure": "somewhat_agree",
                    "trust_integrity": "strongly_agree",
                    "trust_dependable": "agree",
                    "trust_reliable": "neutral",
                    "trust_overall": "agree",
                    # trust_familiar intentionally omitted
                }
                response = client.post("/api/poia/experiment/participant/debrief", json=payload)
                self.assertEqual(response.status_code, 400)


class TrustCompositeArithmeticTests(unittest.TestCase):
    """Hand-verified correctness check of trust_composite / trust_summary
    against synthetic stored responses, per display_variant arm.

    Likert -> score, per TRUST_SCALE_VALUE_SCORES: strongly_disagree=1,
    disagree=2, somewhat_disagree=3, neutral=4, somewhat_agree=5, agree=6,
    strongly_agree=7.

    legacy arm:
      P1: agree(6), agree(6), somewhat_agree(5), agree(6), neutral(4),
          agree(6), somewhat_agree(5)
          sum = 6+6+5+6+4+6+5 = 38  ->  composite = 38/7 = 5.428571428571429
      P2: neutral(4) on all 7 items -> composite = 28/7 = 4.0
      P3: same as P1 but "prefer_not" on trust_familiar -> composite = None
          (excluded from every mean below, not imputed)

      legacy mean over the 2 complete sessions (P1, P2):
        (38/7 + 4) / 2 = (38/7 + 28/7) / 2 = (66/7) / 2 = 33/7
                        = 4.714285714285714

    redesigned arm:
      P4: strongly_agree(7) on all 7 items -> composite = 49/7 = 7.0
      P5: agree(6), strongly_agree(7), agree(6), strongly_agree(7), agree(6),
          strongly_agree(7), agree(6)
          sum = 6+7+6+7+6+7+6 = 45  ->  composite = 45/7 = 6.428571428571429
      P6: somewhat_agree(5) on all 7 items -> composite = 35/7 = 5.0

      redesigned mean over all 3 sessions (P4, P5, P6):
        (7 + 45/7 + 5) / 3 = (49/7 + 45/7 + 35/7) / 3 = (129/7) / 3 = 43/7
                            = 6.142857142857143

    overall mean over all 5 complete sessions (P1, P2, P4, P5, P6):
      (38/7 + 28/7 + 49/7 + 45/7 + 35/7) / 5 = (195/7) / 5 = 39/7
                                              = 5.571428571428571
    """

    def _session(self, participant_id, display_variant, values, missing=None):
        row = {"participant_id": participant_id, "display_variant": display_variant}
        for item, value in zip(TRUST_SCALE_ITEMS, values):
            row[item] = value
        if missing is not None:
            row[missing] = "prefer_not"
        return row

    def setUp(self) -> None:
        self.p1 = self._session(
            "P1", "legacy",
            ["agree", "agree", "somewhat_agree", "agree", "neutral", "agree", "somewhat_agree"],
        )
        self.p2 = self._session("P2", "legacy", ["neutral"] * 7)
        self.p3 = self._session(
            "P3", "legacy",
            ["agree", "agree", "somewhat_agree", "agree", "neutral", "agree", "somewhat_agree"],
            missing="trust_familiar",
        )
        self.p4 = self._session("P4", "redesigned", ["strongly_agree"] * 7)
        self.p5 = self._session(
            "P5", "redesigned",
            ["agree", "strongly_agree", "agree", "strongly_agree", "agree", "strongly_agree", "agree"],
        )
        self.p6 = self._session("P6", "redesigned", ["somewhat_agree"] * 7)
        self.sessions = [self.p1, self.p2, self.p3, self.p4, self.p5, self.p6]

    def test_value_score_map_matches_a_1_to_7_agreement_scale(self) -> None:
        self.assertEqual(
            TRUST_SCALE_VALUE_SCORES,
            {
                "strongly_disagree": 1, "disagree": 2, "somewhat_disagree": 3,
                "neutral": 4, "somewhat_agree": 5, "agree": 6, "strongly_agree": 7,
            },
        )

    def test_per_session_composite_matches_hand_calculation(self) -> None:
        self.assertAlmostEqual(trust_composite(self.p1), 38 / 7, places=9)
        self.assertAlmostEqual(trust_composite(self.p2), 4.0, places=9)
        self.assertIsNone(trust_composite(self.p3))  # one item "prefer_not" -> excluded, not imputed
        self.assertAlmostEqual(trust_composite(self.p4), 7.0, places=9)
        self.assertAlmostEqual(trust_composite(self.p5), 45 / 7, places=9)
        self.assertAlmostEqual(trust_composite(self.p6), 5.0, places=9)

    def test_summary_means_and_counts_match_hand_calculation_overall_and_by_variant(self) -> None:
        result = trust_summary(self.sessions)

        overall = result["overall"]
        self.assertEqual(overall["sessions"], 6)
        self.assertEqual(overall["sessions_with_complete_trust_scale"], 5)  # P3 excluded
        self.assertAlmostEqual(overall["mean"], 39 / 7, places=9)
        self.assertIsNotNone(overall["participant_bootstrap_95"])
        lo, hi = overall["participant_bootstrap_95"]
        self.assertLessEqual(lo, overall["mean"])
        self.assertGreaterEqual(hi, overall["mean"])

        legacy = result["by_display_variant"]["legacy"]
        self.assertEqual(legacy["sessions"], 3)
        self.assertEqual(legacy["sessions_with_complete_trust_scale"], 2)
        self.assertAlmostEqual(legacy["mean"], 33 / 7, places=9)

        redesigned = result["by_display_variant"]["redesigned"]
        self.assertEqual(redesigned["sessions"], 3)
        self.assertEqual(redesigned["sessions_with_complete_trust_scale"], 3)
        self.assertAlmostEqual(redesigned["mean"], 43 / 7, places=9)

        # legacy vs redesigned in this synthetic set: redesigned trusted more.
        self.assertGreater(redesigned["mean"], legacy["mean"])

    def test_summary_over_no_sessions_reports_no_mean_and_no_interval(self) -> None:
        empty = trust_summary([])
        self.assertEqual(empty["overall"]["sessions"], 0)
        self.assertIsNone(empty["overall"]["mean"])
        self.assertIsNone(empty["overall"]["participant_bootstrap_95"])
        self.assertEqual(empty["by_display_variant"], {})


if __name__ == "__main__":
    unittest.main()
