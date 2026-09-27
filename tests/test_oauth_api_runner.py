import unittest

from scripts.run_oauth_api_integration import requested_operation


class OAuthAPIRunnerTests(unittest.TestCase):
    def test_scenario_mutations_and_reasons(self) -> None:
        approved = {"object_id": "config-1", "environment": "production", "version": "v1"}
        exact = requested_operation(approved, "exact_request")
        action = requested_operation(approved, "cross_action_substitution")
        target = requested_operation(approved, "target_object_substitution")
        scope = requested_operation(approved, "scope_parameter_substitution")

        self.assertEqual(exact, ("deploy_config", approved, "approved"))
        self.assertEqual(action[0], "api_key_rotate")
        self.assertEqual(action[2], "action_mismatch")
        self.assertNotEqual(target[1]["object_id"], approved["object_id"])
        self.assertEqual(target[2], "scope_mismatch")
        self.assertEqual(scope[1]["version"], "v2")
        self.assertEqual(scope[2], "scope_mismatch")
        self.assertEqual(approved["version"], "v1")


if __name__ == "__main__":
    unittest.main()
