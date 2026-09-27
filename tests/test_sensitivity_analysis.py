import unittest

from scripts.run_sensitivity_analysis import DELAYS, TTLS, build_intent, expiry_matrix, percentile


class SensitivityAnalysisTests(unittest.TestCase):
    def test_expiry_policy_accepts_boundary_and_rejects_only_after(self) -> None:
        rows = expiry_matrix()
        self.assertEqual(len(rows), len(TTLS) * len(DELAYS))
        self.assertFalse(any(row["false_rejection"] for row in rows))
        for row in rows:
            self.assertEqual(bool(row["accepted"]), row["modeled_arrival_delay_s"] <= row["ttl_s"])

    def test_intent_shapes_use_production_canonicalizable_values(self) -> None:
        for count in (5, 20, 50, 100):
            flat = build_intent(count, "flat")
            nested = build_intent(count, "nested")
            self.assertEqual(len(flat["scope"]), count)
            nested_count = sum(len(group["values"]) for group in nested["scope"]["groups"])
            self.assertEqual(nested_count, count)

    def test_percentile_uses_nearest_rank(self) -> None:
        self.assertEqual(percentile([1, 2, 3, 4, 5], 0.95), 5)


if __name__ == "__main__":
    unittest.main()
