"""Controlled, auditable mutations for the live PoIA participant study."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import math
import secrets
import time
from typing import Any, Dict, Iterable, Mapping, Optional

from .core import canonical_sha256
from .db import db_connect
from .intent_codec import canonical_json
from .settings import APP_RP_ID


ALLOWED_MUTATION_PATHS = {
    "action",
    "scope",
    "scope.account_id",
    "scope.amount",
    "scope.account_number",
    "scope.beneficiary_id",
    "scope.currency",
    "scope.date_from",
    "scope.date_to",
    "scope.external_account",
    "scope.txn_type",
    "context.rp_id",
}

MUTATION_STAGES = {"none", "pre_display", "post_signature", "session_repurpose"}
SIGNING_BACKENDS = {"webauthn", "zt_authenticator"}

STUDY_ACTIONS = {
    "transfer",
    "beneficiary_add",
    "withdrawal",
    "statement_export",
    "cloud_file_view",
    "cloud_file_download",
    "cloud_file_delete",
    "cloud_file_share_public",
    "cloud_file_overwrite",
}

CLOUD_ACTIONS = {
    "cloud_file_view",
    "cloud_file_download",
    "cloud_file_delete",
    "cloud_file_share_public",
    "cloud_file_overwrite",
}

CLOUD_RESOURCE_SEEDS = (
    ("quarterly-financial-report", "Quarterly financial report.pdf", "confidential"),
    ("production-recovery-backup", "Production recovery backup.tar", "critical"),
    ("identity-access-policy", "Identity and access policy.json", "restricted"),
)

PARTICIPANT_RECIPIENTS = (
    ("9007", "Northwind Supplies"),
    ("2148", "Cedar Office Services"),
    ("6732", "Metro Utilities"),
    ("4815", "Harbor Logistics"),
    ("315902", "Aster Research Services"),
    ("684217", "Beacon Lab Supplies"),
    ("927461", "Summit Data Hosting"),
    ("146805", "Greenfield Energy"),
    ("502739", "Keystone Communications"),
    ("758314", "Meridian Facilities"),
    ("836250", "Redwood Professional Services"),
    ("490176", "Silverline Equipment"),
)

# These definitions never leave the server. Controls are interleaved with the
# complete condition matrix so the participant-facing page remains an ordinary
# sequence of work tasks.
PARTICIPANT_SCENARIOS = (
    {"key": "transfer_control", "family": "transfer", "stage": "none", "type": "none"},
    {"key": "transfer_target", "family": "transfer", "stage": "session_repurpose", "type": "target"},
    {"key": "statement_control", "family": "statement", "stage": "none", "type": "statement_export_control"},
    {"key": "beneficiary_control", "family": "beneficiary", "stage": "none", "type": "beneficiary_control"},
    {"key": "cloud_view_control", "family": "cloud", "operation": "cloud_file_view", "stage": "none", "type": "cloud_view_control"},
    {"key": "withdrawal_control", "family": "withdrawal", "stage": "none", "type": "withdrawal_control"},
    {"key": "transfer_subtle", "family": "transfer", "stage": "session_repurpose", "type": "subtle_parameter"},
    {"key": "cloud_view_delete", "family": "cloud", "operation": "cloud_file_view", "stage": "session_repurpose", "type": "cross_operation_cloud_delete"},
    {"key": "beneficiary_target", "family": "beneficiary", "stage": "session_repurpose", "type": "beneficiary_target"},
    {"key": "withdrawal_pre_amount", "family": "withdrawal", "stage": "pre_display", "type": "scope"},
    {"key": "statement_repurpose", "family": "transfer", "stage": "session_repurpose", "type": "cross_operation_statement_export"},
    {"key": "statement_pre_context", "family": "statement", "stage": "pre_display", "type": "context"},
    {"key": "cloud_download_share", "family": "cloud", "operation": "cloud_file_download", "stage": "session_repurpose", "type": "cross_operation_public_share"},
    {"key": "withdrawal_post_amount", "family": "withdrawal", "stage": "post_signature", "type": "scope"},
    {"key": "cloud_view_overwrite", "family": "cloud", "operation": "cloud_file_view", "stage": "session_repurpose", "type": "cross_operation_overwrite"},
    {"key": "transfer_multiple", "family": "transfer", "stage": "post_signature", "type": "multiple_field"},
    {"key": "cloud_post_delete", "family": "cloud", "operation": "cloud_file_view", "stage": "post_signature", "type": "post_signature_cloud_delete"},
    {"key": "cloud_delete_control", "family": "cloud", "operation": "cloud_file_delete", "stage": "none", "type": "cloud_delete_control"},
)


STUDY_DESIGN_VERSION = "2026-09-04-participant-beneficiaries-v4"

# Dataset 2 (see spontaneous_semantic_inspection_protocol.md, "Dataset 2:
# display-variant comparison"): an independent between-subjects factor asking
# whether the redesigned confirmation layout (grouped fields, sender/
# recipient avatars for transfers, a dedicated amount card) helps
# participants validate what they sign, relative to the plain, one-field-
# per-row layout that preceded it. Both variants render the identical
# verified field set from the identical signed intent -- only the layout is
# manipulated, so a difference in outcome cannot be attributed to showing
# more or less information in one arm than the other.
DISPLAY_VARIANTS = {"legacy", "redesigned"}


# Human-Computer Trust in Automation short scale (Jian, Bisantz & Drury,
# 2000, "Foundations for an Empirically Determined Scale of Trust in
# Automated Systems", International Journal of Cognitive Ergonomics 4(1)).
# Jian et al.'s 12-item scale factors into a "distrust" component (deceptive,
# underhanded, suspicious, wary, harmful) and a "trust" component (confident,
# secure, has integrity, dependable, reliable, trusted overall, familiar).
# The post-session questionnaire below asks only the 7 positively-worded
# "trust" component items, reworded plainly for this study's "confirmation
# screen" (the PoIA authorization prompt shown before signing) -- this is the
# closest published, validated fit to what the study actually wants to know:
# did participants come to trust that the confirmation screen correctly
# showed what signing would do. These 7 items are the ONLY items in this
# questionnaire drawn from a validated psychometric instrument; every other
# post-session question (purpose guess, confusion, matching ease,
# demographics, backend preference, etc.) remains descriptive self-report,
# not a validated scale -- see the "interpretation" labels in
# scripts/analyze_human_study.py for the same distinction applied there.
#
# Field name -> the Jian et al. (2000) trust-component item it reworks:
#   trust_confident  -> "I am confident in the system."
#   trust_secure     -> "The system provides security."
#   trust_integrity  -> "The system has integrity."
#   trust_dependable -> "The system is dependable."
#   trust_reliable   -> "The system is reliable."
#   trust_overall    -> "I can trust the system."
#   trust_familiar   -> "I am familiar with the system."
TRUST_SCALE_ITEMS = (
    "trust_confident",
    "trust_secure",
    "trust_integrity",
    "trust_dependable",
    "trust_reliable",
    "trust_overall",
    "trust_familiar",
)

# 7-point agreement scale used for each TRUST_SCALE_ITEMS field, plus a
# "prefer not to answer" opt-out (consistent with the confusion/frustration
# items above). "prefer_not" carries no numeric score and is excluded from
# the composite computed in scripts/analyze_human_study.py, not imputed.
TRUST_SCALE_VALUES = {
    "strongly_disagree", "disagree", "somewhat_disagree", "neutral",
    "somewhat_agree", "agree", "strongly_agree", "prefer_not",
}


def _next_display_variant(conn) -> str:
    """Assign the arm with fewer participants so far (ties broken randomly).

    This is minimization / adaptive-biased-coin balancing (Pocock & Simon,
    1975), a standard alternative to permuted-block randomization for small
    samples: it keeps the two arms within one participant of each other at
    every point in recruitment -- important given this study's likely small
    N -- while still drawing an unpredictable outcome whenever the arms are
    tied, rather than deterministically alternating (the fixed-parity
    approach already used for backend order, and flagged in the design
    audit as not independently randomized).
    """
    rows = conn.execute(
        "SELECT display_variant, COUNT(*) FROM poia_participant_sessions "
        "WHERE display_variant IN ('legacy', 'redesigned') GROUP BY display_variant"
    ).fetchall()
    tally = {"legacy": 0, "redesigned": 0}
    for row in rows:
        tally[row[0]] = row[1]
    if tally["legacy"] == tally["redesigned"]:
        return secrets.choice(("legacy", "redesigned"))
    return "legacy" if tally["legacy"] < tally["redesigned"] else "redesigned"


def select_alternate_account(
    candidate_accounts: Iterable[Any], selected_account: Any, seed: str
) -> str:
    """Select a reproducible mutation target that differs from the original."""
    selected = str(selected_account or "").strip()
    eligible = sorted(
        {
            str(account or "").strip()
            for account in candidate_accounts
            if str(account or "").strip().isdigit()
            and 4 <= len(str(account or "").strip()) <= 34
            and str(account or "").strip() != selected
        }
    )
    if not eligible:
        raise ValueError("no alternate study account is available")
    offset = int.from_bytes(hashlib.sha256(seed.encode("utf-8")).digest()[:8], "big")
    return eligible[offset % len(eligible)]


def create_participant_session(
    user_id: int,
    orientation: Optional[dict] = None,
    display_variant: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a pseudonymous, server-scheduled spontaneous study session.

    ``display_variant`` lets a caller force an arm (used by tests and by the
    instructed console for diagnostic sessions); live participant
    recruitment should leave it unset so the balancing assignment in
    ``_next_display_variant`` applies.
    """
    if display_variant is not None and display_variant not in DISPLAY_VARIANTS:
        raise ValueError("unsupported display variant")
    now = time.time()
    session_id = secrets.token_urlsafe(24)
    participant_id = f"P-{secrets.token_hex(4).upper()}"
    study_run_id = f"spontaneous-{time.strftime('%Y%m%d')}"
    with db_connect() as conn:
        cohort_index = int(
            conn.execute("SELECT COUNT(*) FROM poia_participant_sessions").fetchone()[0]
        )
        cohort = "webauthn_first" if cohort_index % 2 == 0 else "zt_authenticator_first"
        variant = display_variant or _next_display_variant(conn)
        schedule = [dict(item) for item in PARTICIPANT_SCENARIOS]
        for index, item in enumerate(schedule):
            item["backend"] = (
                "webauthn" if (index + cohort_index) % 2 == 0 else "zt_authenticator"
            )
        conn.execute(
            "INSERT INTO poia_participant_sessions "
            "(session_id, participant_id, study_run_id, cohort, user_id, schedule_json, created_at, design_version, orientation_response, display_variant) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (session_id, participant_id, study_run_id, cohort, user_id, json.dumps(schedule), now,
             STUDY_DESIGN_VERSION if orientation else "legacy-unversioned",
             json.dumps(orientation, sort_keys=True) if orientation else None,
             variant),
        )
    return load_participant_session(session_id) or {}


def load_participant_session(session_id: str, user_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
    with db_connect() as conn:
        if user_id is None:
            row = conn.execute(
                "SELECT * FROM poia_participant_sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM poia_participant_sessions WHERE session_id = ? AND user_id = ?",
                (session_id, user_id),
            ).fetchone()
    return dict(row) if row is not None else None


def participant_step(session: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    schedule = json.loads(str(session["schedule_json"]))
    index = int(session["current_step"])
    return dict(schedule[index]) if 0 <= index < len(schedule) else None


def advance_participant_session(session_id: str, expected_step: int) -> bool:
    with db_connect() as conn:
        session = conn.execute(
            "SELECT schedule_json, current_step FROM poia_participant_sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if session is None or int(session["current_step"]) != expected_step:
            return False
        next_step = expected_step + 1
        complete = next_step >= len(json.loads(session["schedule_json"]))
        conn.execute(
            "UPDATE poia_participant_sessions SET current_step = ?, status = ?, completed_at = ? "
            "WHERE session_id = ? AND current_step = ?",
            (next_step, "complete" if complete else "active", time.time() if complete else None, session_id, expected_step),
        )
    return True

MUTATION_PLANS = {
    "none": ({"none"}, set()),
    "statement_export_control": ({"none"}, set()),
    "cloud_view_control": ({"none"}, set()),
    "cloud_delete_control": ({"none"}, set()),
    "beneficiary_control": ({"none"}, set()),
    "withdrawal_control": ({"none"}, set()),
    "beneficiary_target": ({"session_repurpose"}, {"scope.account_number"}),
    "target": ({"session_repurpose"}, {"scope.external_account"}),
    "scope": ({"pre_display", "post_signature", "session_repurpose"}, {"scope.amount"}),
    "subtle_parameter": ({"session_repurpose"}, {"scope.amount"}),
    "context": ({"pre_display", "session_repurpose"}, {"context.rp_id"}),
    "multiple_field": (
        {"post_signature", "session_repurpose"},
        {"scope.amount", "scope.external_account"},
    ),
    "cross_operation_statement_export": (
        {"session_repurpose"},
        {"action", "scope"},
    ),
    "cross_operation_cloud_delete": ({"session_repurpose"}, {"action"}),
    "cross_operation_public_share": ({"session_repurpose"}, {"action"}),
    "cross_operation_overwrite": ({"session_repurpose"}, {"action"}),
    "post_signature_cloud_delete": ({"post_signature"}, {"action"}),
}


def study_account_readiness(user_id: int) -> Dict[str, Any]:
    """Return the prerequisites required for a live participant trial."""
    with db_connect() as conn:
        user = conn.execute(
            "SELECT id, email, poia_zt_enabled FROM users WHERE id = ? AND is_admin = 0",
            (user_id,),
        ).fetchone()
        account_count = conn.execute(
            "SELECT COUNT(*) FROM accounts WHERE user_id = ?", (user_id,)
        ).fetchone()[0]
        passkey_count = conn.execute(
            "SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?", (user_id,)
        ).fetchone()[0]
        zt_device_count = conn.execute(
            "SELECT COUNT(*) FROM devices "
            "JOIN device_keys ON device_keys.device_id = devices.id "
            "WHERE devices.user_id = ? AND device_keys.rp_id = ?",
            (user_id, APP_RP_ID),
        ).fetchone()[0]
    checks = {
        "active_user": user is not None,
        "active_account": account_count > 0,
        "webauthn_registered": passkey_count > 0,
        "zt_authenticator_enabled": bool(user and user["poia_zt_enabled"]),
        "zt_authenticator_registered": zt_device_count > 0,
    }
    return {
        "ready": all(checks.values()),
        "email": user["email"] if user else "",
        "account_count": account_count,
        "passkey_count": passkey_count,
        "zt_device_count": zt_device_count,
        "checks": checks,
    }


def validate_study_ownership(user_id: int, action: str, scope: Mapping[str, Any]) -> None:
    """Ensure every study object belongs to the signed-in participant."""
    with db_connect() as conn:
        if action == "transfer":
            account_id = scope.get("from_account")
            owned = conn.execute(
                "SELECT 1 FROM accounts WHERE id = ? AND user_id = ?", (account_id, user_id)
            ).fetchone()
            if owned is None:
                raise ValueError("source account does not belong to the participant")
        elif action == "withdrawal":
            account_id = scope.get("account_id")
            owned = conn.execute(
                "SELECT 1 FROM accounts WHERE id = ? AND user_id = ?", (account_id, user_id)
            ).fetchone()
            if owned is None:
                raise ValueError("withdrawal account does not belong to the participant")
        elif action == "statement_export":
            account_id = scope.get("account_id")
            owned = conn.execute(
                "SELECT 1 FROM accounts WHERE id = ? AND user_id = ?", (account_id, user_id)
            ).fetchone()
            if owned is None:
                raise ValueError("statement account does not belong to the participant")
        elif action in CLOUD_ACTIONS:
            owned = conn.execute(
                "SELECT resource_name, classification FROM experiment_cloud_resources "
                "WHERE user_id = ? AND resource_id = ?",
                (user_id, str(scope.get("resource_id") or "")),
            ).fetchone()
            if owned is None:
                raise ValueError("cloud resource does not belong to the participant")
            if scope.get("resource_name") != owned["resource_name"]:
                raise ValueError("cloud resource name does not match the protected object")
            if scope.get("classification") != owned["classification"]:
                raise ValueError("cloud classification does not match the protected object")


def canonical_copy(body: Mapping[str, Any]) -> Dict[str, Any]:
    return json.loads(canonical_json(body))


def ensure_cloud_resources(user_id: int) -> None:
    now = int(time.time())
    with db_connect() as conn:
        for resource_id, resource_name, classification in CLOUD_RESOURCE_SEEDS:
            conn.execute(
                "INSERT OR IGNORE INTO experiment_cloud_resources "
                "(user_id, resource_id, resource_name, classification, status, "
                "public_access, version, updated_at) VALUES (?, ?, ?, ?, 'active', 0, 1, ?)",
                (user_id, resource_id, resource_name, classification, now),
            )


def reset_cloud_resources(user_id: int) -> None:
    ensure_cloud_resources(user_id)
    with db_connect() as conn:
        conn.execute(
            "UPDATE experiment_cloud_resources SET status = 'active', public_access = 0, "
            "version = 1, updated_at = ? WHERE user_id = ?",
            (int(time.time()), user_id),
        )


def list_cloud_resources(user_id: int) -> list[Dict[str, Any]]:
    ensure_cloud_resources(user_id)
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT resource_id, resource_name, classification, status, public_access, version "
            "FROM experiment_cloud_resources WHERE user_id = ? ORDER BY resource_id",
            (user_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def execute_cloud_study_action(
    user_id: int, action: str, scope: Mapping[str, Any]
) -> tuple[bool, Optional[str]]:
    if action not in CLOUD_ACTIONS:
        return False, "unsupported_study_action"
    resource_id = str(scope.get("resource_id") or "").strip()
    if not resource_id:
        return False, "cloud_resource_missing"
    with db_connect() as conn:
        resource = conn.execute(
            "SELECT * FROM experiment_cloud_resources WHERE user_id = ? AND resource_id = ?",
            (user_id, resource_id),
        ).fetchone()
        if resource is None:
            return False, "cloud_resource_missing"
        if resource["status"] != "active":
            return False, "cloud_resource_deleted"
        now = int(time.time())
        if action == "cloud_file_delete":
            conn.execute(
                "UPDATE experiment_cloud_resources SET status = 'deleted', updated_at = ? "
                "WHERE id = ?",
                (now, resource["id"]),
            )
        elif action == "cloud_file_share_public":
            conn.execute(
                "UPDATE experiment_cloud_resources SET public_access = 1, updated_at = ? "
                "WHERE id = ?",
                (now, resource["id"]),
            )
        elif action == "cloud_file_overwrite":
            conn.execute(
                "UPDATE experiment_cloud_resources SET version = version + 1, updated_at = ? "
                "WHERE id = ?",
                (now, resource["id"]),
            )
        if action not in {"cloud_file_view", "cloud_file_download"}:
            conn.execute(
                "INSERT INTO experiment_api_operations (user_id, action, object_id, created_at) "
                "VALUES (?, ?, ?, ?)",
                (user_id, action, resource_id, now),
            )
    return True, None


def validate_study_operation(action: str, scope: Mapping[str, Any]) -> None:
    if action not in STUDY_ACTIONS:
        raise ValueError("unsupported study action")
    if action == "transfer":
        allowed = {"from_account", "amount", "currency", "external_account"}
        if set(scope) != allowed:
            raise ValueError("invalid transfer scope")
        try:
            from_account = int(scope.get("from_account"))
            amount = float(scope.get("amount"))
        except (TypeError, ValueError):
            raise ValueError("invalid transfer scope") from None
        if from_account <= 0 or not math.isfinite(amount) or amount <= 0 or amount > 1_000_000_000:
            raise ValueError("invalid transfer scope")
        target = str(scope.get("external_account") or "")
        if not target.isdigit() or not 4 <= len(target) <= 34:
            raise ValueError("invalid transfer target")
        if scope.get("currency") != "USD":
            raise ValueError("invalid transfer currency")
    elif action == "withdrawal":
        if set(scope) != {"account_id", "amount", "currency"}:
            raise ValueError("invalid withdrawal scope")
        try:
            account_id = int(scope.get("account_id"))
            amount = float(scope.get("amount"))
        except (TypeError, ValueError):
            raise ValueError("invalid withdrawal scope") from None
        if account_id <= 0 or not math.isfinite(amount) or amount <= 0 or amount > 1_000_000_000:
            raise ValueError("invalid withdrawal scope")
        if scope.get("currency") != "USD":
            raise ValueError("invalid withdrawal currency")
    elif action == "beneficiary_add":
        if set(scope) != {"name", "bank", "account_number"}:
            raise ValueError("invalid beneficiary scope")
        name = str(scope.get("name") or "")
        bank = str(scope.get("bank") or "")
        if not 1 <= len(name) <= 100 or not name.isprintable():
            raise ValueError("invalid beneficiary name")
        if not 1 <= len(bank) <= 100 or not bank.isprintable():
            raise ValueError("invalid beneficiary bank")
        account_number = str(scope.get("account_number") or "")
        if not account_number.isdigit() or not 4 <= len(account_number) <= 34:
            raise ValueError("invalid beneficiary account")
    elif action == "statement_export":
        allowed = {"account_id", "txn_type", "date_from", "date_to"}
        if set(scope) != allowed:
            raise ValueError("invalid statement export scope")
        try:
            if int(scope.get("account_id")) <= 0:
                raise ValueError
            date_from = dt.date.fromisoformat(str(scope.get("date_from") or ""))
            date_to = dt.date.fromisoformat(str(scope.get("date_to") or ""))
        except (TypeError, ValueError):
            raise ValueError("invalid statement export scope") from None
        if date_from > date_to:
            raise ValueError("statement date range is reversed")
        txn_type = str(scope.get("txn_type") or "")
        if len(txn_type) > 32 or txn_type not in {"", "transfer", "deposit", "withdrawal"}:
            raise ValueError("invalid statement transaction type")
    elif action in CLOUD_ACTIONS:
        resource_id = str(scope.get("resource_id") or "")
        if not resource_id or len(resource_id) > 96:
            raise ValueError("invalid cloud resource scope")
        if set(scope) - {"resource_id", "resource_name", "classification"}:
            raise ValueError("invalid cloud resource scope")
        if len(str(scope.get("resource_name") or "")) > 160:
            raise ValueError("invalid cloud resource scope")
        if len(str(scope.get("classification") or "")) > 32:
            raise ValueError("invalid cloud resource scope")


def validate_study_mutation_plan(
    mutation_stage: str,
    mutation_type: str,
    mutations: Iterable[Mapping[str, Any]],
) -> None:
    plan = MUTATION_PLANS.get(mutation_type)
    if plan is None:
        raise ValueError("unsupported study mutation type")
    allowed_stages, expected_paths = plan
    if mutation_stage not in allowed_stages:
        raise ValueError("mutation type does not match its attack stage")
    mutation_list = list(mutations)
    if len(mutation_list) > 4:
        raise ValueError("too many study mutations")
    paths = [str(item.get("path") or "") for item in mutation_list]
    if len(paths) != len(set(paths)) or set(paths) != expected_paths:
        raise ValueError("mutation fields do not match the declared condition")


def apply_mutations(
    body: Mapping[str, Any], mutations: Iterable[Mapping[str, Any]]
) -> Dict[str, Any]:
    changed = copy.deepcopy(dict(body))
    for mutation in mutations:
        path = str(mutation.get("path") or "")
        if path not in ALLOWED_MUTATION_PATHS:
            raise ValueError(f"unsupported study mutation path: {path}")
        parts = path.split(".")
        target: Dict[str, Any] = changed
        for part in parts[:-1]:
            child = target.get(part)
            if not isinstance(child, dict):
                raise ValueError(f"study mutation path does not address an object: {path}")
            target = child
        target[parts[-1]] = mutation.get("value")
    return canonical_copy(changed)


def create_trial_record(
    *,
    trial_id: str,
    study_run_id: str,
    participant_id: str,
    cohort: Optional[str] = None,
    signing_backend: str,
    mutation_stage: str,
    mutation_type: str,
    original_request_id: str,
    intent_id: str,
    task_body: Mapping[str, Any],
    displayed_body: Mapping[str, Any],
    mutations: Iterable[Mapping[str, Any]],
    expected_participant_decision: str,
    study_mode: str = "instructed",
    participant_session_id: Optional[str] = None,
    step_index: Optional[int] = None,
    scenario_key: Optional[str] = None,
) -> None:
    if signing_backend not in SIGNING_BACKENDS:
        raise ValueError("unsupported study signing backend")
    if mutation_stage not in MUTATION_STAGES:
        raise ValueError("unsupported study mutation stage")
    canonical_task = canonical_copy(task_body)
    canonical_displayed = canonical_copy(displayed_body)
    mutation_list = [dict(item) for item in mutations]
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO poia_human_study_trials "
            "(trial_id, study_run_id, participant_id, cohort, signing_backend, mutation_stage, mutation_type, "
            "original_request_id, intent_id, original_sha256, displayed_sha256, "
            "expected_participant_decision, task_body, displayed_body, mutation_spec, created_at, "
            "study_mode, participant_session_id, step_index, scenario_key, proof_status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                trial_id,
                study_run_id,
                participant_id,
                cohort,
                signing_backend,
                mutation_stage,
                mutation_type,
                original_request_id,
                intent_id,
                canonical_sha256(canonical_task),
                canonical_sha256(canonical_displayed),
                expected_participant_decision,
                canonical_json(canonical_task).decode("utf-8"),
                canonical_json(canonical_displayed).decode("utf-8"),
                json.dumps(mutation_list, sort_keys=True, separators=(",", ":")),
                time.time(),
                study_mode,
                participant_session_id,
                step_index,
                scenario_key,
                "pending",
            ),
        )


def record_participant_decision(
    intent_id: str,
    decision: str,
    *,
    system_decision: Optional[str] = None,
    rejection_reason: Optional[str] = None,
    proof_status: Optional[str] = None,
) -> None:
    if decision not in {"sign", "refuse"}:
        raise ValueError("participant decision must be sign or refuse")
    decided_at = time.time()
    with db_connect() as conn:
        conn.execute(
            "UPDATE poia_human_study_trials SET participant_decision = ?, "
            "system_decision = COALESCE(?, system_decision), "
            "rejection_reason = COALESCE(?, rejection_reason), decided_at = ?, "
            "proof_status = COALESCE(?, proof_status), "
            "decision_time_ms = CASE WHEN prompt_displayed_at IS NULL THEN NULL "
            "ELSE (? - prompt_displayed_at) * 1000.0 END "
            "WHERE intent_id = ?",
            (
                decision,
                system_decision,
                rejection_reason,
                decided_at,
                proof_status,
                decided_at,
                intent_id,
            ),
        )


def record_prompt_displayed(intent_id: str, displayed_at: Optional[float] = None) -> None:
    observed_at = displayed_at or time.time()
    with db_connect() as conn:
        conn.execute(
            "UPDATE poia_human_study_trials SET prompt_displayed_at = COALESCE(prompt_displayed_at, ?) "
            "WHERE intent_id = ?",
            (observed_at, intent_id),
        )


def record_system_decision(
    trial_id: str,
    execution_body: Mapping[str, Any],
    decision: str,
    rejection_reason: Optional[str],
    proof_status: Optional[str] = None,
) -> None:
    with db_connect() as conn:
        conn.execute(
            "UPDATE poia_human_study_trials SET execution_body = ?, system_decision = ?, "
            "rejection_reason = ?, proof_status = COALESCE(?, proof_status), decided_at = ? "
            "WHERE trial_id = ?",
            (
                canonical_json(execution_body).decode("utf-8"),
                decision,
                rejection_reason,
                proof_status,
                time.time(),
                trial_id,
            ),
        )


def load_trial(trial_id: str) -> Optional[Dict[str, Any]]:
    with db_connect() as conn:
        row = conn.execute(
            "SELECT * FROM poia_human_study_trials WHERE trial_id = ?", (trial_id,)
        ).fetchone()
    return dict(row) if row is not None else None


def load_trial_for_intent(intent_id: str) -> Optional[Dict[str, Any]]:
    with db_connect() as conn:
        row = conn.execute(
            "SELECT * FROM poia_human_study_trials WHERE intent_id = ?", (intent_id,)
        ).fetchone()
    return dict(row) if row is not None else None


def append_system_event(
    *,
    trial_id: str,
    event_type: str,
    execution_body: Optional[Mapping[str, Any]],
    decision: str,
    rejection_reason: Optional[str],
    proof_status: Optional[str],
    state_before_sha256: Optional[str],
    state_after_sha256: Optional[str],
) -> None:
    execution_sha256 = (
        canonical_sha256(canonical_copy(execution_body)) if execution_body is not None else None
    )
    state_changed = (
        state_before_sha256 != state_after_sha256
        if state_before_sha256 is not None and state_after_sha256 is not None
        else None
    )
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO poia_human_study_events "
            "(trial_id, event_type, execution_sha256, system_decision, rejection_reason, "
            "proof_status, state_before_sha256, state_after_sha256, state_changed, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                trial_id,
                event_type,
                execution_sha256,
                decision,
                rejection_reason,
                proof_status,
                state_before_sha256,
                state_after_sha256,
                int(state_changed) if state_changed is not None else None,
                time.time(),
            ),
        )
