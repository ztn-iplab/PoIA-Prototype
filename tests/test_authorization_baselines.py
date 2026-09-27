import unittest

from app.authorization_baselines import (
    AuthorizationRequest,
    MFAConfirmationGate,
    PoIAExactIntentGate,
    TransactionConfirmationGate,
)


def request() -> AuthorizationRequest:
    return AuthorizationRequest(
        principal="user-1",
        action="transfer",
        scope={"amount": 100, "currency": "USD", "beneficiary_id": "beneficiary-1"},
        context={"rp_id": "poia.local", "workflow_id": "workflow-1"},
    )


class AuthorizationBaselineTests(unittest.TestCase):
    def test_confirmation_binds_external_payee_and_currency(self):
        for field, value in (("external_account", "7781"), ("currency", "EUR")):
            original = request()
            original.scope.pop("beneficiary_id")
            original.scope["external_account"] = "9007"
            changed = AuthorizationRequest(original.principal, original.action, dict(original.scope), dict(original.context))
            changed.scope[field] = value
            gate = TransactionConfirmationGate()
            gate.approve(original)
            self.assertEqual(gate.authorize(changed, 1001)[1], "displayed_field_mismatch")

    def test_generic_mfa_does_not_bind_operation_semantics(self) -> None:
        gate = MFAConfirmationGate()
        original = request()
        changed = request()
        changed.scope["amount"] = 900
        gate.approve(original.principal, 1000)
        self.assertEqual(gate.authorize(changed, 1001), (True, None))

    def test_transaction_confirmation_binds_displayed_fields_only(self) -> None:
        gate = TransactionConfirmationGate()
        original = request()
        gate.approve(original)
        context_changed = request()
        context_changed.context["workflow_id"] = "attacker-workflow"
        self.assertEqual(gate.authorize(context_changed, 1001), (True, None))

        gate.approve(original)
        amount_changed = request()
        amount_changed.scope["amount"] = 900
        self.assertEqual(gate.authorize(amount_changed, 1001)[1], "displayed_field_mismatch")

    def test_transaction_confirmation_and_poia_are_single_use(self) -> None:
        original = request()
        transaction = TransactionConfirmationGate()
        transaction.approve(original)
        self.assertTrue(transaction.authorize(original, 1001)[0])
        self.assertEqual(transaction.authorize(original, 1002)[1], "transaction_confirmation_consumed")

        poia = PoIAExactIntentGate()
        poia.approve(original)
        self.assertTrue(poia.authorize(original, 1001)[0])
        self.assertEqual(poia.authorize(original, 1002)[1], "proof_consumed")

    def test_poia_rejects_context_not_shown_by_transaction_confirmation(self) -> None:
        original = request()
        changed = request()
        changed.context["workflow_id"] = "attacker-workflow"
        gate = PoIAExactIntentGate()
        gate.approve(original)
        self.assertEqual(gate.authorize(changed, 1001)[1], "semantic_mismatch")

    def test_every_gate_accepts_its_exact_legitimate_control(self) -> None:
        import random

        from scripts.run_track_b_comparative import CONFIGURATIONS, run_control

        for configuration in CONFIGURATIONS:
            row = run_control(configuration, 1, random.Random(42))
            self.assertTrue(row["correct_acceptance"], configuration)


if __name__ == "__main__":
    unittest.main()
