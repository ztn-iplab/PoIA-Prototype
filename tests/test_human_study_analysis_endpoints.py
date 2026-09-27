import hashlib
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.analyze_human_study import enforcement_summary, participant_outcomes, summarize


def trial(identifier, participant="P1", stage="session_repurpose", decision="refuse", step=1, **extra):
    return {
        "trial_id": identifier, "participant_id": participant, "participant_session_id": participant,
        "study_mode": "spontaneous", "mutation_stage": stage, "step_index": step, "created_at": step,
        "participant_decision": decision, "expected_participant_decision": "refuse" if stage in {"pre_display", "session_repurpose"} else "sign",
        "signing_backend": "webauthn", "mutation_type": "amount", "decision_time_ms": 1000,
        **extra,
    }


def session(participant, status="complete", **extra):
    return {"session_id": participant, "participant_id": participant, "user_id": participant,
            "status": status, "completed_at": 20 if status == "complete" else None, "created_at": 0, **extra}


class HumanStudyEndpointTests(unittest.TestCase):
    def test_one_first_visible_response_per_completed_participant(self):
        rows = [trial("first", decision="sign"), trial("later", step=2),
                trial("invisible", stage="post_signature", decision="refuse", step=0),
                trial("other", participant="P2"), trial("unfinished", participant="P3")]
        result = participant_outcomes(rows, [session("P1"), session("P2"), session("P3", "active")])
        self.assertEqual(result["primary_first_visible_mismatch"]["participants"], 2)
        self.assertEqual(result["primary_first_visible_mismatch"]["refusals"], 1)
        self.assertEqual(result["incomplete_first_sessions"], 1)
        self.assertEqual(result["secondary_participant_means"]["detection_accuracy"]["mean"], 0.75)
        self.assertNotIn("detection_accuracy_wilson_95", summarize(rows))

    def test_missing_first_response_is_not_replaced_by_later_success(self):
        result = participant_outcomes([trial("first", decision=None), trial("later", step=2)], [session("P1")])
        self.assertEqual(result["primary_first_visible_mismatch"]["participants"], 0)
        self.assertEqual(result["primary_first_visible_mismatch"]["missing_first_response"], 1)

    def test_instructed_and_repeat_sessions_are_not_primary(self):
        rows = [trial("instructed", study_mode="instructed"), trial("repeat", participant="P2")]
        sessions = [session("P1", "active"), session("P2", user_id="P1", created_at=30)]
        result = participant_outcomes(rows, sessions)
        self.assertEqual(result["repeat_sessions_excluded"], 1)
        self.assertEqual(result["completed_first_sessions"], 0)
        self.assertEqual(result["primary_first_visible_mismatch"]["participants"], 0)
        earlier_day = participant_outcomes([trial("repeat")], [session("P1", is_first_account_session=0)])
        self.assertEqual(earlier_day["repeat_sessions_excluded"], 1)

    def test_post_signature_trials_do_not_enter_control_denominator(self):
        result = summarize([trial("control", stage="none", decision="sign"),
                            trial("post", stage="post_signature", decision="refuse")])
        self.assertEqual(result["trials_completed"], 1)
        self.assertEqual(result["false_rejection_rate"], 0)

    def test_display_variant_breakdown_isolates_the_ux_comparison(self):
        # Dataset 2: does the redesigned confirmation display change whether
        # participants catch a mismatch, relative to the legacy layout, with
        # the underlying signed-intent data held identical across arms.
        rows = [
            trial("legacy-hit", participant="P1", decision="refuse"),
            trial("legacy-miss", participant="P2", decision="sign"),
            trial("redesigned-hit-1", participant="P3", decision="refuse"),
            trial("redesigned-hit-2", participant="P4", decision="refuse"),
        ]
        sessions = [
            session("P1", display_variant="legacy"),
            session("P2", display_variant="legacy"),
            session("P3", display_variant="redesigned"),
            session("P4", display_variant="redesigned"),
        ]
        result = participant_outcomes(rows, sessions)
        by_variant = result["primary_first_visible_mismatch_by_display_variant"]
        self.assertEqual(by_variant["legacy"]["participants"], 2)
        self.assertEqual(by_variant["legacy"]["refusals"], 1)
        self.assertAlmostEqual(by_variant["legacy"]["refusal_proportion"], 0.5)
        self.assertEqual(by_variant["redesigned"]["participants"], 2)
        self.assertEqual(by_variant["redesigned"]["refusals"], 2)
        self.assertAlmostEqual(by_variant["redesigned"]["refusal_proportion"], 1.0)
        # Pooled primary metric is unaffected by the new breakdown existing.
        self.assertEqual(result["primary_first_visible_mismatch"]["participants"], 4)
        self.assertEqual(result["primary_first_visible_mismatch"]["refusals"], 3)
        # Per-outcome rows carry their own arm for any custom downstream slicing.
        variants = {row["participant_id"]: row["display_variant"] for row in result["participant_outcomes"]}
        self.assertEqual(variants, {"P1": "legacy", "P2": "legacy", "P3": "redesigned", "P4": "redesigned"})
        self.assertIn("legacy", result["secondary_by_display_variant"])
        self.assertIn("redesigned", result["secondary_by_display_variant"])

    def test_display_variant_breakdown_absent_when_no_sessions_carry_it(self):
        # Older DBs / non-study callers: display_variant is None everywhere,
        # so the by-variant breakdown must be empty rather than raising or
        # inventing a bogus "None" bucket.
        rows = [trial("only", decision="refuse")]
        result = participant_outcomes(rows, [session("P1")])
        self.assertEqual(result["primary_first_visible_mismatch_by_display_variant"], {})
        self.assertEqual(result["secondary_by_display_variant"], {})

    def test_enforcement_uses_hashes_not_scenario_expected_labels(self):
        trials = [trial("core", decision="sign", original_sha256="a", displayed_sha256="a"),
                  trial("extra", decision="sign", original_sha256="a", displayed_sha256="b"),
                  trial("unknown", decision="sign"), trial("refused")]
        events = [{"event_id": i, "trial_id": key, "event_type": "execution_exact",
                   "execution_sha256": "b", "system_decision": "reject", "state_changed": 0}
                  for i, key in enumerate(["core", "extra", "unknown", "refused"])]
        events[0]["state_changed"] = 1
        result = enforcement_summary(trials, events)
        self.assertEqual(result["events"], 3)
        self.assertEqual(result["incorrect_events"], 1)
        self.assertEqual(result["by_binding"]["core_signed_execution_mismatch"]["events"], 1)
        self.assertEqual(result["by_binding"]["additional_original_task_mismatch"]["events"], 1)
        self.assertEqual(result["by_binding"]["unclassified_missing_hashes"]["events"], 1)

    def test_empty_analysis_has_no_fabricated_rates(self):
        result = participant_outcomes([], [])
        self.assertIsNone(result["primary_first_visible_mismatch"]["wilson_95"])
        self.assertIsNone(result["secondary_participant_means"]["detection_accuracy"]["mean"])

    def test_cli_combines_days_without_counting_repeat_accounts_or_writing_database(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "study.db"
            with sqlite3.connect(database) as connection:
                connection.executescript("""
                    CREATE TABLE poia_human_study_trials (
                        trial_id TEXT, study_run_id TEXT, participant_id TEXT, signing_backend TEXT,
                        mutation_stage TEXT, mutation_type TEXT, participant_decision TEXT,
                        expected_participant_decision TEXT, decision_time_ms REAL, created_at REAL,
                        study_mode TEXT, participant_session_id TEXT, step_index INTEGER
                    );
                    CREATE TABLE poia_human_study_events (
                        event_id INTEGER, trial_id TEXT, event_type TEXT, system_decision TEXT,
                        state_changed INTEGER
                    );
                    CREATE TABLE poia_participant_sessions (
                        session_id TEXT, participant_id TEXT, user_id INTEGER, study_run_id TEXT,
                        cohort TEXT, current_step INTEGER, status TEXT, created_at REAL,
                        completed_at REAL, post_session_response TEXT, debrief_shown_at REAL, debriefed_at REAL
                    );
                """)
                for sid, uid, run, status, created in [("P1", 1, "day1", "active", 1),
                                                      ("P2", 1, "day2", "complete", 2),
                                                      ("P3", 2, "day2", "complete", 3)]:
                    connection.execute("INSERT INTO poia_participant_sessions VALUES (?, ?, ?, ?, 'webauthn_first', 18, ?, ?, ?, '{}', NULL, NULL)",
                                       (sid, sid, uid, run, status, created, 10 if status == "complete" else None))
                    connection.execute("INSERT INTO poia_human_study_trials VALUES (?, ?, ?, 'webauthn', 'session_repurpose', 'amount', 'refuse', 'refuse', 1000, ?, 'spontaneous', ?, 1)",
                                       (sid, run, sid, created, sid))
            connection.close()
            before = hashlib.sha256(database.read_bytes()).hexdigest()
            for runs in (("day1", "day2"), ("day2",)):
                command = [sys.executable, "scripts/analyze_human_study.py", "--db", str(database), "--out-dir", str(root / "out")]
                for run in runs:
                    command.extend(["--run-id", run])
                subprocess.run(command, check=True, capture_output=True, text=True)
                result = json.loads((root / "out/human_study_summary.json").read_text())
                self.assertEqual(result["participants"], 1)
                self.assertEqual(result["participant_analysis"]["primary_first_visible_mismatch"]["participants"], 1)
                self.assertEqual(result["participant_analysis"]["repeat_sessions_excluded"], 1)
                self.assertNotIn("user_id", (root / "out/human_study_sessions.csv").read_text())
            self.assertEqual(before, hashlib.sha256(database.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
