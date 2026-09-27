import hashlib
import json
import math
from pathlib import Path
import unittest

from app.core import build_proof_payload, intent_hash
from app.intent_codec import canonical_json
from app.model import intent_mismatch_reason


class IntentCodecTests(unittest.TestCase):
    def test_field_order_does_not_change_canonical_bytes(self) -> None:
        self.assertEqual(canonical_json({"b": 2, "a": 1}), canonical_json({"a": 1, "b": 2}))

    def test_nfc_and_nfd_strings_have_one_encoding(self) -> None:
        self.assertEqual(canonical_json({"value": "caf\u00e9"}), canonical_json({"value": "cafe\u0301"}))

    def test_integer_equivalent_float_has_one_encoding(self) -> None:
        self.assertEqual(canonical_json({"amount": 100}), canonical_json({"amount": 100.0}))
        self.assertEqual(canonical_json({"amount": 0}), canonical_json({"amount": -0.0}))

    def test_non_finite_numbers_are_rejected(self) -> None:
        for value in (math.nan, math.inf, -math.inf):
            with self.subTest(value=value), self.assertRaises(ValueError):
                canonical_json({"amount": value})

    def test_unicode_key_collision_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            canonical_json({"caf\u00e9": 1, "cafe\u0301": 2})

    def test_matcher_uses_canonical_semantics(self) -> None:
        approved = {
            "action": "transfer",
            "scope": {"label": "caf\u00e9", "amount": 100},
            "context": {"user_id": 1, "rp_id": "poia.local"},
            "constraints": {"expires_in_seconds": 60},
        }
        requested = {
            "constraints": {"expires_in_seconds": 60.0},
            "context": {"rp_id": "poia.local", "user_id": 1},
            "scope": {"amount": 100.0, "label": "cafe\u0301"},
            "action": "transfer",
        }
        self.assertIsNone(intent_mismatch_reason(approved, requested))

    def test_zt_cross_client_hash_vector(self) -> None:
        vector_path = (
            Path(__file__).parents[1]
            / "experiments"
            / "protocol_vectors"
            / "zt_intent_hash_v1.json"
        )
        vector = json.loads(vector_path.read_text(encoding="utf-8"))
        intent = vector["intent_as_transmitted"]
        payload = build_proof_payload(intent, vector["nonce"], vector["expires_at"])

        self.assertEqual(canonical_json(intent).decode(), vector["canonical_intent_utf8"])
        self.assertEqual(intent_hash(intent), vector["intent_body_hash_base64url"])
        self.assertEqual(payload.decode(), vector["canonical_proof_payload_utf8"])
        self.assertEqual(hashlib.sha256(payload).hexdigest(), vector["proof_hash_sha256_hex"])


if __name__ == "__main__":
    unittest.main()
