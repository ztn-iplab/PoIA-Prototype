import unittest

from scripts.run_usability_structured_analysis import analyze


class StructuredPromptAnalysisTests(unittest.TestCase):
    def test_analysis_reports_content_without_ranking_backends(self) -> None:
        _, _, summaries = analyze()
        by_backend = {item["backend"]: item for item in summaries}
        self.assertEqual(by_backend["webauthn"]["mutation_visibility_percent"], 100.0)
        self.assertEqual(by_backend["zt_authenticator"]["mutation_visibility_percent"], 100.0)
        self.assertEqual(by_backend["zt_authenticator"]["field_coverage_percent"], 100.0)
        self.assertTrue(by_backend["zt_authenticator"]["full_intent_at_application_signing_surface"])
        self.assertFalse(by_backend["webauthn"]["full_intent_at_application_signing_surface"])
        self.assertFalse(by_backend["zt_authenticator"]["browser_intent_modal_shown"])
        self.assertTrue(by_backend["webauthn"]["browser_intent_modal_shown"])
        self.assertEqual(by_backend["zt_authenticator"]["vague_only_prompts"], 0)


if __name__ == "__main__":
    unittest.main()
