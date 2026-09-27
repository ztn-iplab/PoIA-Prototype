import unittest

from scripts.run_manuscript_rq4 import load_profiles, summarize


class ManuscriptRQ4Tests(unittest.TestCase):
    def test_profiles_are_not_reported_as_empirical_rankings(self) -> None:
        profiles = load_profiles()
        summary = summarize(profiles)
        self.assertEqual(summary["mechanism_count"], 7)
        self.assertEqual(summary["evidence_class"], "declared_representative_property_profiles")
        self.assertNotIn("native_complete_one_time_count", summary)
        self.assertNotIn("additional_binding_count", summary)


if __name__ == "__main__":
    unittest.main()
