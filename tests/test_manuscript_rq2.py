import random
import unittest

from scripts.run_manuscript_rq2 import run_attack_outcomes, run_robustness, summarize


class ManuscriptRQ2Tests(unittest.TestCase):
    def test_rq2_attacks_have_baseline_success_and_poia_rejection(self) -> None:
        rng = random.Random(20260824)
        attack_rows = run_attack_outcomes(1, rng)
        robustness_rows = run_robustness(1, rng)
        summary = summarize(attack_rows, robustness_rows)
        self.assertEqual(summary["attack_outcomes"]["baseline_asr"], 1.0)
        self.assertEqual(summary["attack_outcomes"]["poia_asr"], 0.0)
        self.assertEqual(summary["robustness"]["asr"], 0.0)


if __name__ == "__main__":
    unittest.main()
