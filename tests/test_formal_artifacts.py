import unittest

from scripts.generate_formal_verification_artifacts import parse_lemma_results


class FormalArtifactParserTests(unittest.TestCase):
    def test_parses_safety_and_executability_results(self) -> None:
        output = """
          protocol_executable (exists-trace): verified (9 steps)
          no_execution_without_matching_intent (all-traces): verified (7 steps)
        """

        results = parse_lemma_results(output)

        self.assertEqual(results["protocol_executable"], "verified (9 steps)")
        self.assertEqual(results["no_execution_without_matching_intent"], "verified (7 steps)")


if __name__ == "__main__":
    unittest.main()
