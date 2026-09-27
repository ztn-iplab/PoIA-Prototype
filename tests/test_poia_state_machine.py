import unittest
from concurrent.futures import ThreadPoolExecutor

from app.model import (
    ChallengeRecord,
    InMemoryPoIA,
    IntentRecord,
    ProofRecord,
    intent_mismatch_reason,
)


def populated_store(expires_at: float = 2_000_000_000.0) -> InMemoryPoIA:
    store = InMemoryPoIA()
    store.intents["intent-1"] = IntentRecord(
        intent_id="intent-1",
        intent_body={
            "action": "transfer",
            "scope": {"amount": 100},
            "context": {"user_id": 7, "rp_id": "poia-demo-bank"},
        },
        created_at=1_900_000_000.0,
    )
    store.challenges["intent-1"] = ChallengeRecord(
        intent_id="intent-1", nonce="nonce-1", expires_at=expires_at
    )
    store.proofs["intent-1"] = ProofRecord(
        intent_id="intent-1",
        signature_b64="opaque-test-value",
        status="pending",
        message="Pending",
        latency_ms=0,
    )
    return store


class PoIAStateMachineTests(unittest.TestCase):
    def test_only_one_concurrent_execution_reservation_succeeds(self) -> None:
        store = populated_store()
        approved, _ = store.approve_proof(
            ProofRecord("intent-1", "opaque", "approved", "Approved", 1),
            1_900_000_001.0,
        )
        self.assertTrue(approved)

        with ThreadPoolExecutor(max_workers=32) as executor:
            results = list(
                executor.map(
                    lambda _: store.reserve_execution("intent-1", 7, 1_900_000_002.0),
                    range(200),
                )
            )

        accepted = [result for result in results if result[0]]
        rejected_reasons = [result[1] for result in results if not result[0]]
        self.assertEqual(len(accepted), 1)
        self.assertEqual(rejected_reasons, ["proof_consumed"] * 199)

    def test_expired_proof_cannot_be_approved(self) -> None:
        store = populated_store(expires_at=100.0)
        approved, reason = store.approve_proof(
            ProofRecord("intent-1", "opaque", "approved", "Approved", 1), 100.001
        )
        self.assertFalse(approved)
        self.assertEqual(reason, "expired")

    def test_wrong_principal_does_not_consume_proof(self) -> None:
        store = populated_store()
        store.approve_proof(
            ProofRecord("intent-1", "opaque", "approved", "Approved", 1),
            1_900_000_001.0,
        )
        accepted, reason, _, _ = store.reserve_execution(
            "intent-1", 8, 1_900_000_002.0
        )
        self.assertFalse(accepted)
        self.assertEqual(reason, "principal_mismatch")
        self.assertEqual(store.proofs["intent-1"].status, "approved")

    def test_replay_is_rejected_after_consumption(self) -> None:
        store = populated_store()
        store.approve_proof(
            ProofRecord("intent-1", "opaque", "approved", "Approved", 1),
            1_900_000_001.0,
        )
        first = store.reserve_execution("intent-1", 7, 1_900_000_002.0)
        second = store.reserve_execution("intent-1", 7, 1_900_000_003.0)
        self.assertTrue(first[0])
        self.assertEqual(second[:2], (False, "proof_consumed"))

    def test_semantic_mismatch_does_not_consume_proof(self) -> None:
        store = populated_store()
        store.approve_proof(
            ProofRecord("intent-1", "opaque", "approved", "Approved", 1),
            1_900_000_001.0,
        )
        requested = {
            **store.intents["intent-1"].intent_body,
            "scope": {"amount": 1000},
        }
        accepted, reason, _, _ = store.reserve_execution(
            "intent-1", 7, 1_900_000_002.0, requested
        )
        self.assertFalse(accepted)
        self.assertEqual(reason, "scope_mismatch")
        self.assertEqual(store.proofs["intent-1"].status, "approved")

    def test_mismatch_taxonomy_covers_protocol_bindings(self) -> None:
        approved = {
            "action": "ledger_post",
            "scope": {"amount": 100},
            "context": {
                "user_id": 7,
                "rp_id": "ledger.local",
                "workflow_id": "workflow-1",
                "on_behalf_of": "principal-7",
            },
            "constraints": {"expires_in_seconds": 60},
        }
        cases = (
            ({**approved, "action": "api_key_rotate"}, "action_mismatch"),
            (
                {**approved, "context": {**approved["context"], "workflow_id": "workflow-2"}},
                "workflow_mismatch",
            ),
            (
                {**approved, "context": {**approved["context"], "on_behalf_of": "principal-8"}},
                "delegation_mismatch",
            ),
            (
                {**approved, "context": {**approved["context"], "rp_id": "attacker.local"}},
                "rp_mismatch",
            ),
            ({**approved, "scope": {"amount": 101}}, "scope_mismatch"),
        )
        for requested, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(intent_mismatch_reason(approved, requested), expected)


if __name__ == "__main__":
    unittest.main()
