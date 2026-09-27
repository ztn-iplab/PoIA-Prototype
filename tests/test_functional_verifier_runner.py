import random
import unittest

from scripts.run_track_a_functional_verifier import execute_case, load_scenarios


class FunctionalVerifierRunnerTests(unittest.TestCase):
    def test_every_declarative_case_matches_expected_decision(self) -> None:
        rng = random.Random(42)
        for scenario in load_scenarios():
            with self.subTest(scenario=scenario["id"]):
                row = execute_case(scenario, 1, rng)
                self.assertTrue(row["correct"], row)


if __name__ == "__main__":
    unittest.main()
