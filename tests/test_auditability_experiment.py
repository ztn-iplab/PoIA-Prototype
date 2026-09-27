import unittest

from scripts.run_auditability_experiment import (
    FIELDS,
    baseline_log,
    ground_truth,
    poia_log,
    reconstruct_and_score,
)


class AuditabilityExperimentTests(unittest.TestCase):
    def test_paired_logs_score_against_independent_truth(self) -> None:
        truth = ground_truth(6)
        baseline_rows, _ = reconstruct_and_score(baseline_log(truth), truth)
        poia_rows, _ = reconstruct_and_score(poia_log(truth), truth)

        self.assertEqual(len(baseline_rows), len(FIELDS))
        self.assertEqual(
            [row["score"] for row in baseline_rows],
            ["exact", "exact", "missing", "exact", "ambiguous", "missing", "ambiguous"],
        )
        self.assertTrue(all(row["score"] == "exact" for row in poia_rows))

    def test_corpus_rotates_domains_and_reasons(self) -> None:
        truths = [ground_truth(index) for index in range(28)]
        self.assertEqual(len({truth["domain"] for truth in truths}), 4)
        self.assertEqual(len({truth["rationale"] for truth in truths}), 7)


if __name__ == "__main__":
    unittest.main()
