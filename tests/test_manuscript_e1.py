import random
import unittest

from scripts.run_manuscript_e1 import execute, load_scenarios, summarize


class ManuscriptE1Tests(unittest.TestCase):
    def test_scenarios_match_expected_decisions(self) -> None:
        rng = random.Random(20260824)
        rows = []
        for scenario in load_scenarios():
            row = execute(scenario, 1, rng)
            with self.subTest(scenario=scenario["id"]):
                self.assertTrue(row["correct"], row)
            rows.append(row)
        summary = summarize(rows)
        self.assertEqual(summary["far"], 0.0)
        self.assertEqual(summary["frr"], 0.0)


if __name__ == "__main__":
    unittest.main()
