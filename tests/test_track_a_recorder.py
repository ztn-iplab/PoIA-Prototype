import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from app.track_a_recorder import TrackARecorder, _safe_scope


class Headers(dict):
    def get(self, key, default=None):
        return super().get(key.lower(), default)


def write_manifest(root: Path, configuration: str = "poia_webauthn") -> Path:
    run_dir = root / "run-1"
    run_dir.mkdir()
    manifest = {
        "run_id": "run-1",
        "batch_id": "batch-1",
        "configuration": configuration,
        "random_seed": 42,
        "rp_repository": {"commit": "a" * 40},
        "authenticator_repository": None,
    }
    path = run_dir / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


class TrackARecorderTests(unittest.TestCase):
    def test_sensitive_scope_values_are_pseudonymized(self) -> None:
        safe = _safe_scope({"amount": 50, "account_number": "12345678"})
        self.assertEqual(safe["amount"], 50)
        self.assertNotIn("12345678", safe["account_number"])

    def test_record_writes_linked_decision_and_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            recorder = TrackARecorder(write_manifest(Path(directory)), "exact_legitimate_match")
            request = SimpleNamespace(headers=Headers({"x-poia-request-id": "request-1"}))
            before = {"digest": "before", "counts": {"transactions": 1}}
            after = {"digest": "after", "counts": {"transactions": 2}}
            recorder.record(
                request=request,
                intent_id="intent-1",
                intent_body={
                    "action": "transfer",
                    "scope": {"amount": 50, "external_account": "secret-value"},
                    "context": {"user_id": 9, "rp_id": "poia.local"},
                },
                nonce="raw-nonce",
                expected_decision="accept",
                decision="accept",
                rejection_reason=None,
                http_status=200,
                started_ns=0,
                before=before,
                after=after,
            )
            run_dir = Path(directory) / "run-1"
            record = json.loads((run_dir / "decisions" / "decisions.jsonl").read_text())
            self.assertEqual(record["request_id"], "request-1")
            self.assertTrue(record["state_changed"])
            self.assertNotIn("raw-nonce", json.dumps(record))
            self.assertNotIn("secret-value", json.dumps(record))
            snapshots = list((run_dir / "state_snapshots").glob("*.json"))
            self.assertEqual(len(snapshots), 1)
            self.assertEqual(json.loads(snapshots[0].read_text())["request_id"], "request-1")

    def test_manifest_directory_must_match_run_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_manifest(Path(directory))
            manifest = json.loads(path.read_text())
            manifest["run_id"] = "different-run"
            path.write_text(json.dumps(manifest))
            with self.assertRaises(RuntimeError):
                TrackARecorder(path, "replay")

    def test_expected_decision_must_be_explicit(self) -> None:
        recorder = TrackARecorder(None)
        request = SimpleNamespace(headers=Headers())
        with self.assertRaises(RuntimeError):
            recorder.expected_decision_for(request)


if __name__ == "__main__":
    unittest.main()
