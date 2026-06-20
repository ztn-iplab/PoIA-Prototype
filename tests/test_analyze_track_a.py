import unittest

from scripts.analyze_track_a import percentile, wilson_interval


class TrackAAnalysisTests(unittest.TestCase):
    def test_zero_of_two_hundred_has_nonzero_upper_bound(self) -> None:
        low, high = wilson_interval(0, 200)
        self.assertEqual(low, 0.0)
        self.assertGreater(high, 0.0)
        self.assertLess(high, 0.02)

    def test_two_hundred_of_two_hundred_has_subunit_lower_bound(self) -> None:
        low, high = wilson_interval(200, 200)
        self.assertGreater(low, 0.98)
        self.assertEqual(high, 1.0)

    def test_interpolated_percentile(self) -> None:
        self.assertEqual(percentile([1.0, 2.0, 3.0, 4.0], 0.5), 2.5)


if __name__ == "__main__":
    unittest.main()
