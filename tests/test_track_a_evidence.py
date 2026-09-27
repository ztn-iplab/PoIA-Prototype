import json
import tempfile
import unittest
from pathlib import Path

from scripts.track_a_evidence import (
    DECISION_FIELDS,
    append_decision,
    create_manifest,
    load_scenarios,
    state_digest,
    validate_safe_id,
)


class TrackAEvidenceTests(unittest.TestCase):
    def test_scenario_set_matches_preregistration(self) -> None:
        document = load_scenarios()
        self.assertEqual(len(document["scenarios"]), 7)

    def test_ids_reject_path_traversal(self) -> None:
        with self.assertRaises(ValueError):
            validate_safe_id("run_id", "../outside")

    def test_state_digest_is_order_independent(self) -> None:
        self.assertEqual(state_digest({"a": 1, "b": 2}), state_digest({"b": 2, "a": 1}))

    def test_manifest_freezes_confirmatory_sample_size(self) -> None:
        manifest = create_manifest(
            run_id="session-only-test",
            batch_id="batch-01",
            configuration="session_only",
            random_seed=42,
        )
        self.assertEqual(manifest["sample_size_per_scenario"], 200)
        self.assertEqual(manifest["configuration"], "session_only")

    def test_zt_manifest_requires_authenticator_repository(self) -> None:
        with self.assertRaises(ValueError):
            create_manifest(
                run_id="zt-test",
                batch_id="batch-01",
                configuration="poia_zt_authenticator",
                random_seed=42,
            )

    def test_decision_writer_rejects_secret_fields(self) -> None:
        record = {field: None for field in DECISION_FIELDS}
        record["context"] = {"token": "do-not-write"}
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                append_decision(Path(directory) / "decisions.jsonl", record)

    def test_decision_writer_emits_one_json_object(self) -> None:
        record = {field: None for field in DECISION_FIELDS}
        record.update({"run_id": "run-1", "request_id": "request-1", "scope": {}, "context": {}})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "decisions.jsonl"
            append_decision(path, record)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), record)


class FreshEvaluationCleanupTests(unittest.TestCase):
    def test_cleanup_selects_outputs_but_preserves_inputs_and_human_evidence(self):
        from scripts.prepare_fresh_evaluation import generated_files
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = ["experiments/track_a/raw/old.jsonl",
                     "experiments/track_a/scenarios/security.json",
                     "experiments/human_study/exports/trials.csv",
                     "experiments/protocol_vectors/vector.json",
                     "experiments/manuscript_20260824/figures/tamarin_lemma_map.pdf",
                     "formal-models/proofs/certificate.spthy"]
            for name in paths:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture")
            self.assertEqual(list(generated_files(root)), [root / paths[0]])
            self.assertTrue(all((root / name).exists() for name in paths))


if __name__ == "__main__":
    unittest.main()
