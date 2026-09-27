import sqlite3
import tempfile
import unittest
from pathlib import Path


class HumanStudyMigrationTests(unittest.TestCase):
    def test_existing_trial_rows_gain_timing_columns_without_data_loss(self) -> None:
        from app import db

        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "bank.db"
            connection = sqlite3.connect(database)
            connection.execute(
                "CREATE TABLE poia_human_study_trials ("
                "trial_id TEXT PRIMARY KEY, participant_id TEXT NOT NULL, "
                "decided_at REAL)"
            )
            connection.execute(
                "INSERT INTO poia_human_study_trials "
                "(trial_id, participant_id, decided_at) VALUES (?, ?, ?)",
                ("SELFTEST-LEGACY-01", "SELFTEST", 123.0),
            )
            connection.commit()
            connection.close()

            previous_path = db.DB_PATH
            try:
                db.DB_PATH = database
                db.init_db()
            finally:
                db.DB_PATH = previous_path

            connection = sqlite3.connect(database)
            columns = {
                row[1] for row in connection.execute(
                    "PRAGMA table_info(poia_human_study_trials)"
                )
            }
            row = connection.execute(
                "SELECT trial_id, participant_id, decided_at "
                "FROM poia_human_study_trials WHERE trial_id = ?",
                ("SELFTEST-LEGACY-01",),
            ).fetchone()
            connection.close()

            self.assertIn("prompt_displayed_at", columns)
            self.assertIn("decision_time_ms", columns)
            self.assertIn("study_run_id", columns)
            self.assertEqual(row, ("SELFTEST-LEGACY-01", "SELFTEST", 123.0))


if __name__ == "__main__":
    unittest.main()
