from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class IntentRecord:
    intent_id: str
    intent_body: Dict[str, Any]
    created_at: float


@dataclass
class ChallengeRecord:
    intent_id: str
    nonce: str
    expires_at: float


@dataclass
class ProofRecord:
    intent_id: str
    signature_b64: str
    status: str
    message: str
    latency_ms: int


class InMemoryPoIA:
    def __init__(self) -> None:
        self.intents: Dict[str, IntentRecord] = {}
        self.challenges: Dict[str, ChallengeRecord] = {}
        self.proofs: Dict[str, ProofRecord] = {}
