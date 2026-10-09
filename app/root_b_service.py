"""Root B as its own process: an independent commitment root.

Run this as a separate OS process with read-only access to the referent journal
and no handle on the primary database:

    POIA_REFERENT_JOURNAL_ENABLED=true \
    POIA_REFERENT_JOURNAL_PATH=/var/lib/poia/referent_journal.db \
    python -m app.root_b_service --port 8613

It answers one question: given an action and scope, what is the canonical
commitment for it, sourced from this root's own data path? The relying party's
commitment gate asks both roots and signs only if their answers agree.

Two properties matter and are enforced here rather than assumed.

First, this module must never reach the primary store. It does not import
``app.db``, and ``--source primary`` -- which does read it -- exists only so the
experiment can demonstrate the shared-dependency failure mode, and refuses to
start unless the harness explicitly sets POIA_ROOT_B_ALLOW_PRIMARY.

The experiments run this process under the same user as the relying party, so
process, data path and derivation logic are separated but the credential and the
host are not; isolating those is a deployment step, not a code change.

Second, a root that cannot source a value must say so rather than return a
plausible one. Unknown referents produce an error, which the gate treats as
disagreement, so an attacker who deletes journal history causes refusal, not
acceptance.
"""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .intent_codec import canonical_json  # pure codec; no database access
from .referent_journal import reconstruct

SOURCE = os.getenv("POIA_ROOT_B_SOURCE", "journal")

# Root B answers under a key of its own. The gate holds only the public half,
# so it can tell that a reply came from this root and belongs to the request it
# just made, but cannot produce one. Where the two roots run under separate
# accounts, that makes a relying party which has been taken over unable to
# forge Root B's answer; under the single account the evaluation uses, the key
# file is readable by both, so the binding is to the request, not against that
# adversary.
_SIGNING_KEY = None


def load_signing_key():
    global _SIGNING_KEY
    path = os.getenv("POIA_ROOT_B_SIGNING_KEY", "")
    if not path:
        raise SystemExit("POIA_ROOT_B_SIGNING_KEY must name this root's private key")
    with open(path, "rb") as handle:
        _SIGNING_KEY = serialization.load_pem_private_key(handle.read(), password=None)
    if not isinstance(_SIGNING_KEY, ec.EllipticCurvePrivateKey):
        raise SystemExit("Root B's signing key must be an EC private key")


def sign_reply(nonce: str, canonical: Dict[str, Any]) -> str:
    """Sign the nonce together with the value, so neither can be swapped."""
    message = canonical_json({"nonce": nonce, "canonical": canonical})
    return _SIGNING_KEY.sign(message, ec.ECDSA(hashes.SHA256())).hex()

_MAX_BODY_BYTES = 64 * 1024


def _normalize_amount(amount: Any) -> str:
    """Byte-identical to Root A's formatting. Request-supplied values are shared
    between roots by design -- independently reinventing decimal formatting
    would produce only trivial agreement. What is independently sourced is the
    referenced record below."""
    try:
        return f"{float(amount):.2f}"
    except (TypeError, ValueError):
        return str(amount)


def _read_referent(referent_type: str, referent_id: int) -> Optional[Dict[str, Any]]:
    if SOURCE == "primary":
        # Experiment-only: the shared-upstream arm. Both roots read one store, so
        # a single corrupted row yields agreeing reports and the gate degenerates
        # to a single root. Imported lazily so the default path never loads it.
        from .db import db_connect  # noqa: PLC0415

        table = {"beneficiary": "beneficiaries", "account": "accounts"}.get(referent_type)
        if table is None:
            return None
        with db_connect() as conn:
            row = conn.execute(f"SELECT * FROM {table} WHERE id = ?", (referent_id,)).fetchone()
        return dict(row) if row is not None else None
    return reconstruct(referent_type, referent_id)


def derive(action: str, scope: Dict[str, Any], context: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Return (canonical, error). Exactly one is not None."""
    canonical: Dict[str, Any] = {"action": action, "rp_id": context.get("rp_id")}

    if action == "transfer":
        canonical["amount"] = _normalize_amount(scope.get("amount"))
        canonical["currency"] = scope.get("currency")
        canonical["from_account"] = scope.get("from_account")
        beneficiary_id = scope.get("beneficiary_id")
        if beneficiary_id:
            record = _read_referent("beneficiary", beneficiary_id)
            if record is None:
                return None, "root_b_cannot_source_referent"
            canonical["to"] = {
                "name": record.get("name"),
                "bank": record.get("bank"),
                "account_number": record.get("account_number"),
            }
        else:
            canonical["to"] = {"external_account": scope.get("external_account")}

    elif action in {"beneficiary_add", "beneficiary_edit"}:
        canonical["name"] = scope.get("name")
        canonical["bank"] = scope.get("bank")
        canonical["account_number"] = scope.get("account_number")

    elif action in {"withdrawal", "deposit"}:
        canonical["amount"] = _normalize_amount(scope.get("amount"))
        canonical["currency"] = scope.get("currency")
        canonical["account_id"] = scope.get("account_id")

    elif action == "limit_change":
        canonical["account_id"] = scope.get("account_id")
        canonical["new_daily_limit"] = _normalize_amount(scope.get("new_daily_limit"))
        account_id = scope.get("account_id")
        if account_id:
            record = _read_referent("account", account_id)
            if record is None:
                return None, "root_b_cannot_source_referent"
            canonical["owner_user_id"] = record.get("user_id")

    elif action == "account_recovery":
        canonical["account_id"] = scope.get("account_id")
        account_id = scope.get("account_id")
        if account_id:
            record = _read_referent("account", account_id)
            if record is None:
                return None, "root_b_cannot_source_referent"
            canonical["owner_user_id"] = record.get("user_id")
            canonical["current_status"] = record.get("status")

    else:
        canonical["scope"] = scope

    return canonical, None


class RootBHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:  # keep the harness output clean
        return

    def _send(self, status: int, payload: Dict[str, Any]) -> None:
        body = canonical_json(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send(200, {"status": "ok", "source": SOURCE})
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path != "/derive":
            self._send(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._send(400, {"error": "bad_length"})
            return
        if length <= 0 or length > _MAX_BODY_BYTES:
            self._send(400, {"error": "bad_length"})
            return
        try:
            request = json.loads(self.rfile.read(length))
            action = request["action"]
            nonce = request["nonce"]
            scope = request.get("scope") or {}
            context = request.get("context") or {}
            if (not isinstance(action, str) or not isinstance(scope, dict)
                    or not isinstance(context, dict) or not isinstance(nonce, str) or not nonce):
                raise TypeError("malformed derive request")
        except (ValueError, KeyError, TypeError):
            self._send(400, {"error": "bad_request"})
            return

        try:
            canonical, error = derive(action, scope, context)
        except Exception:
            # A root that fails must say so. Dropping the connection would reach
            # the gate as an unreachable root, which is still a refusal, but it
            # hides the cause from the operator and from the experiment record.
            self._send(500, {"error": "root_b_derivation_failed"})
            return
        if error is not None:
            self._send(409, {"error": error})
            return
        self._send(200, {"canonical": canonical, "nonce": nonce, "signature": sign_reply(nonce, canonical)})


def main() -> None:
    global SOURCE
    parser = argparse.ArgumentParser(description="Independent commitment root (Root B).")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8613)
    parser.add_argument(
        "--source",
        choices=("journal", "primary"),
        default=SOURCE,
        help="journal: this root's own append-only store. primary: experiment-only "
        "shared-upstream arm, requires POIA_ROOT_B_ALLOW_PRIMARY=true.",
    )
    args = parser.parse_args()

    SOURCE = args.source
    if SOURCE == "primary" and os.getenv("POIA_ROOT_B_ALLOW_PRIMARY", "false").lower() != "true":
        raise SystemExit(
            "--source primary makes both roots read one store and is only valid as the "
            "experiment's shared-dependency control; set POIA_ROOT_B_ALLOW_PRIMARY=true."
        )

    load_signing_key()
    server = ThreadingHTTPServer((args.host, args.port), RootBHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
