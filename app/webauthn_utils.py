import base64
import time
from typing import Any, Dict, List, Tuple

from fido2 import cbor
from fido2.cose import CoseKey
from fido2.server import Fido2Server
from fido2.utils import websafe_decode
from fido2.webauthn import (
    Aaguid,
    AttestedCredentialData,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRpEntity,
)

from .db import db_connect
from .settings import WEB_ORIGIN, WEB_RP_ID


def get_webauthn_server() -> Fido2Server:
    rp_id = WEB_RP_ID or "poia.local"
    rp = PublicKeyCredentialRpEntity(id=rp_id, name="PoIA Bank")
    return Fido2Server(rp, [WEB_ORIGIN])


def b64encode(data: bytes) -> str:
    if isinstance(data, str):
        return data
    if isinstance(data, (bytearray, memoryview)):
        data = bytes(data)
    if not isinstance(data, bytes):
        return str(data)
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64decode(data: str) -> bytes:
    if isinstance(data, bytes):
        return data
    if data is None:
        return b""
    if not isinstance(data, str):
        data = str(data)
    pad_len = (-len(data)) % 4
    padded = data + ("=" * pad_len)
    return base64.urlsafe_b64decode(padded)


def webauthn_jsonify(obj: Any) -> Any:
    def convert(value: Any) -> Any:
        if isinstance(value, bytes):
            return b64encode(value)
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            return {key: convert(val) for key, val in value.items() if key != "_field_keys"}
        if isinstance(value, (list, tuple)):
            return [convert(item) for item in value]
        if hasattr(value, "__dict__"):
            return convert({key: val for key, val in vars(value).items() if not key.startswith("_")})
        return value

    return convert(obj)


def attested_from_row(row) -> AttestedCredentialData:
    cred_id = b64decode(row["credential_id"])
    public_key = cbor.decode(base64.b64decode(row["public_key"]))
    attested = AttestedCredentialData.create(Aaguid.NONE, cred_id, CoseKey.parse(public_key))
    return attested


def load_credentials(user_id: int) -> Tuple[List[AttestedCredentialData], List[PublicKeyCredentialDescriptor]]:
    credentials: List[AttestedCredentialData] = []
    descriptors: List[PublicKeyCredentialDescriptor] = []
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT credential_id, public_key, sign_count FROM webauthn_credentials WHERE user_id = ?",
            (user_id,),
        ).fetchall()
    for row in rows:
        cred_id = b64decode(row["credential_id"])
        credentials.append(attested_from_row(row))
        descriptors.append(PublicKeyCredentialDescriptor(id=cred_id, type="public-key"))
    return credentials, descriptors


def user_has_webauthn(user_id: int) -> bool:
    with db_connect() as conn:
        return (
            conn.execute(
                "SELECT id FROM webauthn_credentials WHERE user_id = ? LIMIT 1",
                (user_id,),
            ).fetchone()
            is not None
        )


def encode_state(state: Any) -> str:
    return base64.b64encode(cbor.encode(state)).decode("ascii")


def decode_state(state: str) -> Any:
    return cbor.decode(base64.b64decode(state.encode("ascii")))


class WebAuthnStateStore:
    def __init__(self, ttl_seconds: int = 600) -> None:
        self._ttl = ttl_seconds
        self._items: Dict[str, Tuple[float, Any]] = {}

    def set(self, token: str, state: Any) -> None:
        self._items[token] = (time.time() + self._ttl, state)

    def get(self, token: str) -> Any:
        item = self._items.get(token)
        if not item:
            return None
        expires_at, state = item
        if time.time() > expires_at:
            self._items.pop(token, None)
            return None
        return state

    def clear(self, token: str) -> None:
        self._items.pop(token, None)


webauthn_state_store = WebAuthnStateStore()
