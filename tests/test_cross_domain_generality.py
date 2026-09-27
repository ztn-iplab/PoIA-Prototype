import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from app.intent_codec import canonical_json
from scripts.run_cross_domain_generality import (
    CASES,
    domain_schema,
    requested_case,
    verify,
)


class CrossDomainGeneralityTests(unittest.TestCase):
    def test_every_case_uses_the_shared_verifier(self) -> None:
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        for domain in ("banking", "enterprise", "healthcare", "cloud_api"):
            approved = domain_schema(domain, trial=1)
            signature = private_key.sign(
                canonical_json(approved), ec.ECDSA(hashes.SHA256())
            )
            for case in CASES:
                requested, expected_reason = requested_case(
                    domain, approved, case
                )
                accepted, reason, _ = verify(
                    approved, requested, signature, public_key
                )
                self.assertEqual(accepted, case == "exact_match")
                self.assertEqual(reason, expected_reason)


if __name__ == "__main__":
    unittest.main()
