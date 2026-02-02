from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..core import create_poia_intent, get_current_user, render, require_login, poia_required
from ..db import db_connect

router = APIRouter()


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
        recent_audit = conn.execute(
            "SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 10"
        ).fetchall()

    return render(
        request,
        "admin_dashboard.html",
        {"totals": totals, "recent_audit": recent_audit},
    )


@router.get("/admin/audit", response_class=HTMLResponse)
def audit_log(request: Request) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)

    if not user["is_admin"]:
        return RedirectResponse(url="/dashboard", status_code=302)
    if (
        poia_required("admin_audit_view")
        and request.query_params.get("poia") != "1"
        and request.query_params.get("poia_intent") is None
    ):
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
        and request.query_params.get("poia") != "1"
        and request.query_params.get("poia_intent") is None
    ):
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
