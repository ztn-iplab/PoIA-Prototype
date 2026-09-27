from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response, JSONResponse

from datetime import datetime, timezone
import csv
import json
import secrets
import time

from ..experiment_export import build_experiment_export

from ..core import create_poia_intent, get_current_user, log_audit, render, require_login, poia_required
from ..db import db_connect
from ..execution_grants import consume_grant

router = APIRouter()


def _utc_display(value) -> str:
    if value is None:
        return "-"
    return datetime.fromtimestamp(float(value), timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


@router.get("/admin/dashboard", response_class=HTMLResponse)
def admin_dashboard(request: Request) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    if not user["is_admin"]:
        return RedirectResponse(url="/dashboard", status_code=302)

    with db_connect() as conn:
        totals = conn.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM users) AS user_count,
                (SELECT COUNT(*) FROM users WHERE is_admin = 0) AS customer_count,
                (SELECT COUNT(*) FROM accounts) AS account_count,
                (SELECT COALESCE(SUM(balance), 0) FROM accounts) AS total_balance,
                (SELECT COUNT(*) FROM transactions) AS transaction_count,
                (SELECT COUNT(*) FROM mfa_events) AS mfa_events
            """
        ).fetchone()
        recent_audit_rows = conn.execute(
            "SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 10"
        ).fetchall()
        study_totals = conn.execute(
            "SELECT COUNT(*) AS sessions, SUM(status = 'complete') AS completed, "
            "SUM(status = 'active') AS active, "
            "(SELECT COUNT(*) FROM poia_human_study_trials) AS trials "
            "FROM poia_participant_sessions"
        ).fetchone()
        recent_session_rows = conn.execute(
            "SELECT participant_id, cohort, current_step, status, created_at, completed_at, schedule_json "
            "FROM poia_participant_sessions ORDER BY created_at DESC LIMIT 8"
        ).fetchall()
        questionnaire_rows = conn.execute(
            "SELECT participant_id, cohort, design_version, completed_at, post_session_response "
            "FROM poia_participant_sessions WHERE post_session_response IS NOT NULL "
            "ORDER BY completed_at DESC, created_at DESC"
        ).fetchall()
        account_rows = conn.execute(
            """
            SELECT accounts.id, accounts.account_type, accounts.status,
                   accounts.daily_transfer_limit, accounts.balance, users.email
            FROM accounts
            JOIN users ON users.id = accounts.user_id
            ORDER BY accounts.id DESC
            LIMIT 20
            """
        ).fetchall()
        user_rows = conn.execute(
            """
            SELECT id, email, is_admin, mfa_enrolled, disabled, signup_pending, created_at
            FROM users
            ORDER BY id DESC
            LIMIT 50
            """
        ).fetchall()

    recent_audit = [
        {**dict(row), "created_display": _utc_display(row["created_at"])}
        for row in recent_audit_rows
    ]
    recent_sessions = []
    for row in recent_session_rows:
        session = dict(row)
        try:
            total_steps = len(json.loads(session.pop("schedule_json")))
        except (TypeError, ValueError):
            total_steps = 0
        session["progress_display"] = f"{min(int(session['current_step']), total_steps)} / {total_steps}"
        session["created_display"] = _utc_display(session["created_at"])
        recent_sessions.append(session)
    questionnaire_responses = []
    for row in questionnaire_rows:
        try:
            answers = json.loads(row["post_session_response"])
        except (TypeError, ValueError):
            answers = {}
        questionnaire_responses.append(
            {
                "participant_id": row["participant_id"],
                "cohort": row["cohort"] or "-",
                "design_version": row["design_version"],
                "completed_display": _utc_display(row["completed_at"]),
                "answers": answers,
            }
        )

    return render(
        request,
        "admin_dashboard.html",
        {
            "totals": totals,
            "recent_audit": recent_audit,
            "study_totals": study_totals,
            "recent_sessions": recent_sessions,
            "questionnaire_responses": questionnaire_responses,
            "accounts": account_rows,
            "users": [
                {
                    **dict(row),
                    "started_display": _utc_display(row["created_at"]),
                }
                for row in user_rows
            ],
        },
    )


@router.post("/admin/accounts/{account_id}/status")
def admin_set_account_status(request: Request, account_id: int, status: str = Form(...)) -> RedirectResponse:
    """Operations/fraud-desk style control used to put an account into a
    non-active state (or restore it) for testing and human-study setup. This
    mutates the account the same way a bank's back-office system would before
    a customer ever sees it -- it is not itself a PoIA-protected customer
    action; `account_recovery` (app.routes.banking) is the customer-facing,
    PoIA-protected action that reverses it."""
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    if not user["is_admin"]:
        return RedirectResponse(url="/dashboard", status_code=302)
    if status not in {"active", "frozen", "dormant"}:
        return RedirectResponse(url="/admin/dashboard#accounts", status_code=302)

    with db_connect() as conn:
        conn.execute(
            "UPDATE accounts SET status = ?, version = version + 1, updated_at = ? WHERE id = ?",
            (status, int(time.time()), account_id),
        )

    request.session["flash_message"] = f"Account #{account_id} set to {status}."
    return RedirectResponse(url="/admin/dashboard#accounts", status_code=302)


@router.post("/admin/users/{user_id}/reset")
def admin_reset_user(request: Request, user_id: int) -> RedirectResponse:
    """Admin-initiated equivalent of the user's own self-service TOTP reset
    (reset_totp_submit in app.routes.auth): wipes the current TOTP secret and
    every enrolled device/pending-enrollment row, and clears any outstanding
    recovery codes, so the account is forced back into first-time TOTP setup
    at the user's next login. Does not touch the password or the account's
    admin/customer role."""
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    if not user["is_admin"]:
        return RedirectResponse(url="/dashboard", status_code=302)

    with db_connect() as conn:
        target = conn.execute("SELECT id, email FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            request.session["flash_message"] = "Account not found."
            return RedirectResponse(url="/admin/dashboard#users", status_code=302)
        device_ids = [
            row["id"] for row in conn.execute("SELECT id FROM devices WHERE user_id = ?", (user_id,)).fetchall()
        ]
        if device_ids:
            placeholders = ",".join("?" for _ in device_ids)
            # placeholders contains one literal '?' per database-derived device id.
            conn.execute(f"DELETE FROM device_keys WHERE device_id IN ({placeholders})", device_ids)  # nosec B608
        conn.execute("DELETE FROM devices WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM pending_totp WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM totp_recovery_codes WHERE user_id = ?", (user_id,))
        conn.execute(
            "UPDATE users SET otp_secret = NULL, otp_email_label = NULL, otp_rp_id = NULL, mfa_enrolled = 0 WHERE id = ?",
            (user_id,),
        )

    log_audit(user["id"], "admin_account_reset", f"Reset MFA enrollment for user #{user_id} ({target['email']})")
    request.session["flash_message"] = f"Account #{user_id} reset. The user must set up TOTP again at next login."
    return RedirectResponse(url="/admin/dashboard#users", status_code=302)


@router.post("/admin/users/{user_id}/delete")
def admin_delete_user(request: Request, user_id: int) -> RedirectResponse:
    """Deletes a user's ability to authenticate as themselves: disables the
    account, replaces the password hash with an unusable random value, and
    revokes every credential (TOTP, devices, WebAuthn, recovery codes).
    Implemented as an irreversible disable rather than a hard `DELETE FROM
    users` row removal, because `poia_original_requests` is deliberately
    append-only (its own BEFORE DELETE/UPDATE triggers enforce this, since
    that table is this system's audit non-repudiation evidence) -- a cascading
    hard delete would either violate that invariant or silently orphan rows
    depending on how it were written. Retaining the historical audit trail
    while cutting off all access is the safer choice for a system whose whole
    thesis is auditable, non-repudiable history."""
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    if not user["is_admin"]:
        return RedirectResponse(url="/dashboard", status_code=302)
    if user_id == user["id"]:
        request.session["flash_message"] = "You cannot delete your own account."
        return RedirectResponse(url="/admin/dashboard#users", status_code=302)

    with db_connect() as conn:
        target = conn.execute("SELECT id, email FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            request.session["flash_message"] = "Account not found."
            return RedirectResponse(url="/admin/dashboard#users", status_code=302)
        device_ids = [
            row["id"] for row in conn.execute("SELECT id FROM devices WHERE user_id = ?", (user_id,)).fetchall()
        ]
        if device_ids:
            placeholders = ",".join("?" for _ in device_ids)
            # placeholders contains one literal '?' per database-derived device id.
            conn.execute(f"DELETE FROM device_keys WHERE device_id IN ({placeholders})", device_ids)  # nosec B608
        conn.execute("DELETE FROM devices WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM pending_totp WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM totp_recovery_codes WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM webauthn_credentials WHERE user_id = ?", (user_id,))
        conn.execute(
            "UPDATE users SET otp_secret = NULL, otp_email_label = NULL, otp_rp_id = NULL, "
            "mfa_enrolled = 0, disabled = 1, password_hash = ? WHERE id = ?",
            (f"disabled${secrets.token_hex(32)}", user_id),
        )

    log_audit(
        user["id"],
        "admin_account_deleted",
        f"Disabled account and revoked all credentials for user #{user_id} ({target['email']})",
    )
    request.session["flash_message"] = f"Account #{user_id} deleted. Its audit history is retained; no one can sign in as this user again."
    return RedirectResponse(url="/admin/dashboard#users", status_code=302)


@router.get("/admin/experiments/export")
def export_experiments(request: Request) -> Response:
    user = get_current_user(request)
    headers = {"Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"}
    if not require_login(user):
        return JSONResponse({"error": "authentication_required"}, status_code=401, headers=headers)
    if not user["is_admin"]:
        return JSONResponse({"error": "admin_required"}, status_code=403, headers=headers)
    # A download is read-only, but disallow cross-site embedding or navigation.
    if request.headers.get("sec-fetch-site") == "cross-site":
        return JSONResponse({"error": "same_origin_required"}, status_code=403, headers=headers)
    try:
        data = build_experiment_export()
    except (RuntimeError, csv.Error, UnicodeError):
        return JSONResponse({"error": "export_not_ready", "message": "The research data could not be captured completely. Please retry or contact the researcher."}, status_code=409, headers=headers)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    headers["Content-Disposition"] = f'attachment; filename="poia-experimental-data-{stamp}.zip"'
    return Response(data, media_type="application/zip", headers=headers)


@router.get("/admin/audit", response_class=HTMLResponse)
def audit_log(request: Request) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)

    if not user["is_admin"]:
        return RedirectResponse(url="/dashboard", status_code=302)
    if (
        poia_required("admin_audit_view")
        and not consume_grant(request.query_params.get("grant", ""), user["id"], "admin_audit_view", {"resource": "audit_logs"})
    ):
        if request.query_params.get("poia_intent"):
            return render(request, "audit.html", {"logs": []})
        intent_id = create_poia_intent(
            action="admin_audit_view",
            scope={"resource": "audit_logs"},
            context={"rp_id": "poia-demo-bank", "user_id": user["id"]},
        )
        return RedirectResponse(url=f"/admin/audit?poia_intent={intent_id}", status_code=303)

    with db_connect() as conn:
        logs = conn.execute(
            "SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 100"
        ).fetchall()

    return render(request, "audit.html", {"logs": logs})


@router.get("/admin/mfa", response_class=HTMLResponse)
def mfa_metrics(request: Request) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)

    if not user["is_admin"]:
        return RedirectResponse(url="/dashboard", status_code=302)
    if (
        poia_required("admin_mfa_view")
        and not consume_grant(request.query_params.get("grant", ""), user["id"], "admin_mfa_view", {"resource": "mfa_events"})
    ):
        if request.query_params.get("poia_intent"):
            return render(request, "mfa_admin.html", {"summary": {"ok": 0, "denied": 0, "pending": 0}, "events": []})
        intent_id = create_poia_intent(
            action="admin_mfa_view",
            scope={"resource": "mfa_events"},
            context={"rp_id": "poia-demo-bank", "user_id": user["id"]},
        )
        return RedirectResponse(url=f"/admin/mfa?poia_intent={intent_id}", status_code=303)

    summary = {"ok": 0, "denied": 0, "pending": 0}
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT status, COUNT(*) as count FROM mfa_events GROUP BY status"
        ).fetchall()
        for row in rows:
            summary[row["status"]] = row["count"]
        events = conn.execute(
            "SELECT * FROM mfa_events ORDER BY created_at DESC LIMIT 100"
        ).fetchall()

    return render(request, "mfa_admin.html", {"summary": summary, "events": events})
