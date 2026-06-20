import json
import tempfile
import time
import unittest
from pathlib import Path


try:
    from fastapi.testclient import TestClient

    HTTP_DEPS_AVAILABLE = True
except ModuleNotFoundError:
    HTTP_DEPS_AVAILABLE = False


@unittest.skipUnless(HTTP_DEPS_AVAILABLE, "FastAPI HTTP test dependencies are not installed")
class DownstreamLedgerHTTPTests(unittest.TestCase):
    def test_attestation_confinement_and_replay(self) -> None:
        from downstream import main
        from downstream.security import sign_attestation, sign_service_request

        with tempfile.TemporaryDirectory() as directory:
            main.DATA_DIR = Path(directory)
            main.DB_PATH = main.DATA_DIR / "ledger.db"
            main.SHARED_SECRET = "temporary-test-secret"
            main.SERVICE_ID = "poia-bank"
            main.REQUIRE_POIA = True
            main.init_db()

            claims = {
                "request_id": "request-1",
                "action": "ledger_post",
                "scope": {"object_id": "record-1", "amount": 20.0},
                "context": {"on_behalf_of": "principal-1", "rp_id": "poia-ledger"},
                "intent_hash": "intent-hash-1",
                "proof_id": "proof-1",
            }
            body = {
                "request_id": claims["request_id"],
                "action": claims["action"],
                "scope": claims["scope"],
                "context": claims["context"],
                "poia_attestation": {
                    "claims": claims,
                    "signature": sign_attestation(main.SHARED_SECRET, claims),
                },
            }

            def headers(value):
                timestamp = str(int(time.time()))
                return {
                    "X-PoIA-Service-Id": main.SERVICE_ID,
                    "X-PoIA-Service-Timestamp": timestamp,
                    "X-PoIA-Service-Signature": sign_service_request(
                        main.SHARED_SECRET, timestamp, value
                    ),
                }

            with TestClient(main.app) as client:
                accepted = client.post("/ledger/entries", json=body, headers=headers(body))
                replayed = client.post("/ledger/entries", json=body, headers=headers(body))
                wrong_action = json.loads(json.dumps(body))
                wrong_action["action"] = "ledger_delete"
                substituted = client.post(
                    "/ledger/entries", json=wrong_action, headers=headers(wrong_action)
                )
                missing = {key: value for key, value in body.items() if key != "poia_attestation"}
                missing["request_id"] = "request-2"
                no_attestation = client.post(
                    "/ledger/entries", json=missing, headers=headers(missing)
                )

            self.assertEqual(accepted.status_code, 201)
            self.assertEqual(replayed.status_code, 409)
            self.assertEqual(replayed.json()["reason"], "downstream_replay")
            self.assertEqual(substituted.status_code, 403)
            self.assertEqual(substituted.json()["reason"], "attested_action_mismatch")
            self.assertEqual(no_attestation.status_code, 403)
            self.assertEqual(no_attestation.json()["reason"], "poia_attestation_missing")
            self.assertEqual(main.state_for("principal-1")["entry_count"], 1)


if __name__ == "__main__":
    unittest.main()
