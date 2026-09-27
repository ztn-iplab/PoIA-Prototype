import random
import unittest

from scripts.run_manuscript_rq3 import document, execute, summarize


class ManuscriptRQ3Tests(unittest.TestCase):
    def test_cross_domain_valid_and_mutation_decisions(self) -> None:
        rng = random.Random(20260824)
        rows = []
        for domain in [item["id"] for item in document()["domains"]]:
            rows.append(execute(domain, "valid", 1, rng))
            for mutation in document()["mutations"]:
                rows.append(execute(domain, mutation, 1, rng))
        summary = summarize(rows)
        self.assertEqual(summary["cross_domain_frr"], 0.0)
        self.assertEqual(summary["cross_domain_far"], 0.0)


if __name__ == "__main__":
    unittest.main()
