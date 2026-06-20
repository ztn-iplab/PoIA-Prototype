import json
import tempfile
import unittest
from pathlib import Path

from scripts.track_a_run_status import status


class TrackARunStatusTests(unittest.TestCase):
    def test_reports_progress_and_complete_evidence_bundles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            (run_dir / "decisions").mkdir()
            (run_dir / "state_snapshots").mkdir()
            (run_dir / "requests").mkdir()
            (run_dir / "timings").mkdir()
            (run_dir / "manifest.json").write_text(json.dumps({
                "run_id": "manual-1",
                "configuration": "poia_webauthn",
                "sample_size_per_scenario": 200,
                "rp_repository": {"dirty": False},
                "authenticator_repository": None,
            }))
            row = {
                "attempt_n": 1,
                "request_id": "request-1",
                "decision": "accept",
                "rejection_reason": None,
                "scenario_id": "exact_legitimate_match",
                "state_changed": True,
            }
            (run_dir / "decisions" / "decisions.jsonl").write_text(json.dumps(row) + "\n")
            linked = json.dumps({"attempt_n": 1, "request_id": "request-1"})
            (run_dir / "state_snapshots" / "0001-request-1.json").write_text(linked)
            (run_dir / "requests" / "0001-request-1.json").write_text(linked)
            (run_dir / "timings" / "0001-request-1.json").write_text(linked)

            report = status(run_dir)

            self.assertEqual(report["recorded_attempts"], 1)
            self.assertEqual(report["remaining_attempts"], 199)
            self.assertTrue(report["evidence_bundles_complete"])
            self.assertFalse(report["complete"])


if __name__ == "__main__":
    unittest.main()
