import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class HumanStudyAnalysisFilterTests(unittest.TestCase):
    def test_shared_run_can_exclude_rehearsal_participant(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "study.db"
            output = root / "analysis"
            connection = sqlite3.connect(database)
            connection.executescript(
                """
                CREATE TABLE poia_human_study_trials (
                    trial_id TEXT PRIMARY KEY,
                    study_run_id TEXT NOT NULL,
                    participant_id TEXT NOT NULL,
                    signing_backend TEXT NOT NULL,
                    mutation_stage TEXT NOT NULL,
                    mutation_type TEXT NOT NULL,
                    participant_decision TEXT,
                    expected_participant_decision TEXT NOT NULL,
                    decision_time_ms REAL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE poia_human_study_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    trial_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    system_decision TEXT,
                    state_changed INTEGER
                );
                """
            )
            rows = [
                ("SELFTEST-W-U01", "human-study-main-01", "SELFTEST"),
                ("P01-W-U01", "human-study-main-01", "P01"),
            ]
            for trial_id, run_id, participant_id in rows:
                connection.execute(
                    "INSERT INTO poia_human_study_trials VALUES "
                    "(?, ?, ?, 'webauthn', 'none', 'none', 'sign', 'sign', 1000, 1)",
                    (trial_id, run_id, participant_id),
                )
            connection.commit()
            connection.close()

            completed = subprocess.run(
                [
                    sys.executable,
                    "scripts/analyze_human_study.py",
                    "--db",
                    str(database),
                    "--out-dir",
                    str(output),
                    "--run-id",
                    "human-study-main-01",
                    "--exclude-participant-id",
                    "SELFTEST",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 1)
            summary = json.loads((output / "human_study_summary.json").read_text())

            self.assertEqual(summary["participants"], 0)
            self.assertEqual(summary["participant_ids_observed"], 1)
            self.assertEqual(summary["overall"]["trials_created"], 1)
            self.assertEqual(summary["excluded_participant_ids"], ["SELFTEST"])
            self.assertGreater(summary["enforcement"]["evidence_issues"], 0)


if __name__ == "__main__":
    unittest.main()
