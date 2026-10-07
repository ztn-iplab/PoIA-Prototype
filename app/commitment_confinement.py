"""The 2-of-2 commitment gate, in either of two root configurations.

``inprocess`` (default, unchanged): both roots are functions in this process,
reading the same database over separate connections and separate queries. They
share inputs, a store, normalization, and a process, so agreement is a check on
read-path defects -- divergent queries, parser differences, stale or corrupted
reads, single-path coding errors -- and not evidence of independent trust roots.
Experiment hooks in this mode inject function outputs, not source compromises.

``service``: Root B is a separate OS process (``app.root_b_service``) reading
its own append-only referent journal, reached over a loopback request. Rewriting
a row in the primary store changes what Root A reports and leaves Root B's
answer intact, so the gate refuses to commit. This is the configuration the
k-of-n property actually assumes, and the one whose compromise behaviour can be
measured rather than asserted. It is still one host under one administrator;
separate hosts and separate administrative control remain deployment concerns.

Either way the gate is conjunctive and fails closed: a root that cannot be
reached, or cannot source its value, counts as disagreement. Only 2-of-2 is
implemented.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple

from .db import db_connect
from .intent_codec import canonical_json
from .settings import (
    KOFN_ENABLED,
    KOFN_ROOT_B_MODE,
    KOFN_ROOT_B_TIMEOUT_S,
    KOFN_ROOT_B_URL,
    POIA_EXPERIMENT_MODE,
)


def _digest(canonical: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(canonical)).hexdigest()


def _normalize_amount(amount: Any) -> str:
    """Shared formatting only -- not a security-relevant derivation. The amount
    is attacker-supplied request data already present identically in both
    roots' input (`scope`); the property this module checks is whether a
    referenced DB row (e.g. a beneficiary) has been re-read consistently, not
    whether two roots can independently reinvent decimal formatting."""
    try:
        return f"{float(amount):.2f}"
    except (TypeError, ValueError):
        return str(amount)


def _root_a_canonical(action: str, scope: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Primary root. Opens its own connection and reads referents column-by-column
    via `SELECT name, bank, account_number, version ...`."""
    canonical: Dict[str, Any] = {"action": action, "rp_id": context.get("rp_id")}
    if action == "transfer":
        canonical["amount"] = _normalize_amount(scope.get("amount"))
        canonical["currency"] = scope.get("currency")
        canonical["from_account"] = scope.get("from_account")
        beneficiary_id = scope.get("beneficiary_id")
        if beneficiary_id:
            with db_connect() as conn:
                row = conn.execute(
                    "SELECT name, bank, account_number FROM beneficiaries WHERE id = ?",
                    (beneficiary_id,),
                ).fetchone()
            canonical["to"] = (
                {"name": row["name"], "bank": row["bank"], "account_number": row["account_number"]}
                if row is not None
                else None
            )
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
            with db_connect() as conn:
                row = conn.execute(
                    "SELECT user_id FROM accounts WHERE id = ?", (account_id,)
                ).fetchone()
            canonical["owner_user_id"] = row["user_id"] if row is not None else None
    elif action == "account_recovery":
        canonical["account_id"] = scope.get("account_id")
        account_id = scope.get("account_id")
        if account_id:
            with db_connect() as conn:
                row = conn.execute(
                    "SELECT user_id, status FROM accounts WHERE id = ?", (account_id,)
                ).fetchone()
            canonical["owner_user_id"] = row["user_id"] if row is not None else None
            canonical["current_status"] = row["status"] if row is not None else None
    else:
        canonical["scope"] = scope
    return canonical


def _root_b_canonical(action: str, scope: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Independent re-derivation. Deliberately does not import or call anything in
    Root A -- it opens its own connection and issues its own query (`SELECT *`,
    indexed by column name, rather than Root A's explicit column list), so a bug
    or compromise confined to Root A's query does not also corrupt this root."""
    canonical: Dict[str, Any] = {"action": action, "rp_id": context.get("rp_id")}
    if action == "transfer":
        canonical["amount"] = _normalize_amount(scope.get("amount"))
        canonical["currency"] = scope.get("currency")
        canonical["from_account"] = scope.get("from_account")
        beneficiary_id = scope.get("beneficiary_id")
        if beneficiary_id:
            with db_connect() as conn:
                row = conn.execute(
                    "SELECT * FROM beneficiaries WHERE id = ?", (beneficiary_id,)
                ).fetchone()
            canonical["to"] = (
                {"name": row["name"], "bank": row["bank"], "account_number": row["account_number"]}
                if row is not None
                else None
            )
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
            with db_connect() as conn:
                row = conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
            canonical["owner_user_id"] = row["user_id"] if row is not None else None
    elif action == "account_recovery":
        canonical["account_id"] = scope.get("account_id")
        account_id = scope.get("account_id")
        if account_id:
            with db_connect() as conn:
                row = conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
            canonical["owner_user_id"] = row["user_id"] if row is not None else None
            canonical["current_status"] = row["status"] if row is not None else None
    else:
        canonical["scope"] = scope
    return canonical


def _experiment_override(root: str, action: str, scope: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Test-only hook so the RQ7 harness can simulate a compromised root and confirm
    the system refuses to commit, mirroring Compromise_RootA / Compromise_RootB in
    the Tamarin model. Only reachable when POIA_EXPERIMENT_MODE is set; never active
    in a normal deployment.

    An explicit ..._VALUE env var (JSON) lets the harness control whether the
    compromised root's report coincides with the honest root's true value for a
    given trial (a compromised-but-accidentally-correct component) or differs
    (a genuine substitution) -- without it, the override always returns a fixed
    marker value that can never coincide, which is fine for a smoke test but not
    for measuring a coincidence rate."""
    if not POIA_EXPERIMENT_MODE:
        return None
    flag = os.getenv(f"POIA_SIMULATE_COMPROMISE_{root.upper()}", "")
    if not flag or flag != action:
        return None
    value_json = os.getenv(f"POIA_SIMULATE_COMPROMISE_{root.upper()}_VALUE", "")
    if value_json:
        try:
            return json.loads(value_json)
        except (TypeError, ValueError):
            pass
    return {"__adversarial_value_injected_by_experiment_harness__": f"{root}:{action}"}


def _root_b_from_service(
    action: str, scope: Dict[str, Any], context: Dict[str, Any]
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Ask the separate Root B process for its own derivation.

    Any failure to obtain an answer is returned as a reason, never as an empty
    or default canonical value: a silent fallback to Root A's value would turn
    the second root off exactly when an attacker wants it off.
    """
    payload = canonical_json({"action": action, "scope": scope, "context": context})
    request = urllib.request.Request(
        f"{KOFN_ROOT_B_URL.rstrip('/')}/derive",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=KOFN_ROOT_B_TIMEOUT_S) as response:
            body = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read()).get("error", "root_b_error")
        except (ValueError, OSError):
            detail = "root_b_error"
        return None, f"commitment_root_b_{detail}"
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None, "commitment_root_b_unavailable"
    canonical = body.get("canonical")
    if not isinstance(canonical, dict):
        return None, "commitment_root_b_malformed"
    return canonical, None


def confine_commitment(*, action: str, scope: Dict[str, Any], context: Dict[str, Any]) -> Optional[str]:
    """Returns None if the roots agree (including when KOFN is disabled), otherwise
    a rejection reason. Called once, at intent-commit time, before anything is ever
    presented for signing."""
    if not KOFN_ENABLED:
        return None
    root_a = _experiment_override("root_a", action, scope) or _root_a_canonical(action, scope, context)

    if KOFN_ROOT_B_MODE == "service":
        root_b, reason = _root_b_from_service(action, scope, context)
        if reason is not None:
            return reason
    else:
        root_b = _experiment_override("root_b", action, scope) or _root_b_canonical(action, scope, context)

    if _digest(root_a) != _digest(root_b):
        return "commitment_root_disagreement"
    return None
