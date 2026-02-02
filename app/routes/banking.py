import csv
import io
import secrets
import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from ..core import (
    build_intent,
    create_poia_intent,
    log_audit,
    poia_required,
    render,
    require_login,
    get_current_user,
)
from ..db import db_connect
from ..mfa_utils import build_statement_filters, parse_date_to_epoch
from ..model import ChallengeRecord, IntentRecord

router = APIRouter()


def admin_guard(user: Dict[str, Any]) -> Optional[RedirectResponse]:
    if user and user["is_admin"]:
        return RedirectResponse(url="/admin/dashboard", status_code=302)
    return None


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    admin_redirect = admin_guard(user)
    if admin_redirect:
        return admin_redirect

    with db_connect() as conn:
        accounts = conn.execute("SELECT * FROM accounts WHERE user_id = ?", (user["id"],)).fetchall()
    return render(request, "dashboard.html", {"accounts": accounts})


@router.get("/accounts/{account_id}", response_class=HTMLResponse)
def account_detail(request: Request, account_id: int) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    admin_redirect = admin_guard(user)
    if admin_redirect:
        return admin_redirect

    with db_connect() as conn:
        account = conn.execute(
            "SELECT * FROM accounts WHERE id = ? AND user_id = ?",
            (account_id, user["id"]),
        ).fetchone()
        transactions = conn.execute(
            "SELECT * FROM transactions WHERE account_id = ? ORDER BY created_at DESC LIMIT 25",
            (account_id,),
        ).fetchall()

    if not account:
        return RedirectResponse(url="/dashboard", status_code=302)

    return render(request, "account.html", {"account": account, "transactions": transactions})


@router.get("/beneficiaries", response_class=HTMLResponse)
def beneficiaries(request: Request) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    admin_redirect = admin_guard(user)
    if admin_redirect:
        return admin_redirect

    with db_connect() as conn:
        rows = conn.execute("SELECT * FROM beneficiaries WHERE user_id = ?", (user["id"],)).fetchall()

    return render(request, "beneficiaries.html", {"beneficiaries": rows})


@router.get("/beneficiaries/add", response_class=HTMLResponse)
def beneficiary_add_form(request: Request) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    admin_redirect = admin_guard(user)
    if admin_redirect:
        return admin_redirect

    return render(request, "beneficiary_add.html", {"error": ""})


@router.post("/beneficiaries/add", response_class=HTMLResponse)
def beneficiary_add_submit(
    request: Request,
    name: str = Form(""),
    bank: str = Form(""),
    account_number: str = Form(""),
) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    admin_redirect = admin_guard(user)
    if admin_redirect:
        return admin_redirect

    if not name or not bank or not account_number:
        return render(request, "beneficiary_add.html", {"error": "All fields are required."})

    if poia_required("beneficiary_add"):
        intent_id = create_poia_intent(
            action="beneficiary_add",
            scope={"name": name, "bank": bank, "account_number": account_number},
            context={"rp_id": "poia-demo-bank", "user_id": user["id"]},
        )
        return RedirectResponse(url=f"/beneficiaries/add?poia_intent={intent_id}", status_code=303)

    intent_body = build_intent(
        action="beneficiary_add",
        scope={"name": name, "bank": bank, "account_number": account_number},
        context={"rp_id": "poia-demo-bank", "user_id": user["id"]},
    )
    return execute_beneficiary_add(request, user, intent_body)


@router.get("/transfer", response_class=HTMLResponse)
def transfer_form(request: Request) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    admin_redirect = admin_guard(user)
    if admin_redirect:
        return admin_redirect

    with db_connect() as conn:
        accounts = conn.execute("SELECT * FROM accounts WHERE user_id = ?", (user["id"],)).fetchall()
        beneficiaries = conn.execute("SELECT * FROM beneficiaries WHERE user_id = ?", (user["id"],)).fetchall()

    return render(request, "transfer.html", {"accounts": accounts, "beneficiaries": beneficiaries, "error": ""})


@router.post("/transfer", response_class=HTMLResponse)
def transfer_submit(
    request: Request,
    from_account: int = Form(...),
    amount: float = Form(...),
    to_type: str = Form("beneficiary"),
    beneficiary_id: Optional[str] = Form(None),
    external_account: Optional[str] = Form(None),
    currency: str = Form("USD"),
) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    admin_redirect = admin_guard(user)
    if admin_redirect:
        return admin_redirect

    if amount <= 0:
        return render_transfer_form(request, user, "Amount must be greater than 0.")

    beneficiary_value = (beneficiary_id or "").strip()
    beneficiary_int = int(beneficiary_value) if beneficiary_value.isdigit() else None
    external_value = (external_account or "").strip()
    if to_type == "beneficiary":
        if not beneficiary_int:
            return render_transfer_form(request, user, "Add a beneficiary before continuing.")
    else:
        if not external_value:
            return render_transfer_form(request, user, "Enter an external account to continue.")

    scope = {"from_account": from_account, "amount": amount, "currency": currency}
    if to_type == "beneficiary":
        scope.update({"beneficiary_id": beneficiary_int})
    else:
        scope.update({"external_account": external_value})

    if poia_required("transfer", amount):
        intent_id = create_poia_intent(
            action="transfer",
            scope=scope,
            context={"rp_id": "poia-demo-bank", "user_id": user["id"]},
        )
        return RedirectResponse(url=f"/transfer?poia_intent={intent_id}", status_code=303)

    intent_body = build_intent(
        action="transfer",
        scope=scope,
        context={"rp_id": "poia-demo-bank", "user_id": user["id"]},
    )
    return execute_transfer(request, user, intent_body)


@router.get("/cash", response_class=HTMLResponse)
def cash_form(request: Request) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    admin_redirect = admin_guard(user)
    if admin_redirect:
        return admin_redirect

    with db_connect() as conn:
        accounts = conn.execute("SELECT * FROM accounts WHERE user_id = ?", (user["id"],)).fetchall()

    return render(request, "cash.html", {"accounts": accounts, "error": ""})


@router.post("/cash", response_class=HTMLResponse)
def cash_submit(
    request: Request,
    account_id: int = Form(...),
    amount: float = Form(...),
    operation: str = Form(...),
) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    admin_redirect = admin_guard(user)
    if admin_redirect:
        return admin_redirect

    if amount <= 0:
        return render(request, "cash.html", {"error": "Amount must be greater than 0."})

    if poia_required(operation, amount):
        intent_id = create_poia_intent(
            action=operation,
            scope={"account_id": account_id, "amount": amount, "currency": "USD"},
            context={"rp_id": "poia-demo-bank", "user_id": user["id"]},
        )
        return RedirectResponse(url=f"/cash?poia_intent={intent_id}", status_code=303)

    intent_body = build_intent(
        action=operation,
        scope={"account_id": account_id, "amount": amount, "currency": "USD"},
        context={"rp_id": "poia-demo-bank", "user_id": user["id"]},
    )
    return execute_cash(request, user, intent_body)


@router.get("/statements", response_class=HTMLResponse)
def statements(request: Request) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    admin_redirect = admin_guard(user)
    if admin_redirect:
        return admin_redirect

    page = int(request.query_params.get("page", "1") or "1")
    page_size = min(max(int(request.query_params.get("page_size", "20") or "20"), 5), 50)
    offset = (page - 1) * page_size

    where_sql, params, filters = build_statement_filters(request, user["id"])

    with db_connect() as conn:
        accounts = conn.execute("SELECT * FROM accounts WHERE user_id = ?", (user["id"],)).fetchall()
        total = conn.execute(
            f"""
            SELECT COUNT(*)
            FROM transactions
            JOIN accounts ON transactions.account_id = accounts.id
            WHERE {where_sql}
            """,
            params,
        ).fetchone()[0]
        transactions = conn.execute(
            f"""
            SELECT transactions.*, accounts.account_type
            FROM transactions
            JOIN accounts ON transactions.account_id = accounts.id
            WHERE {where_sql}
            ORDER BY transactions.created_at DESC
            LIMIT ? OFFSET ?
            """,
            (*params, page_size, offset),
        ).fetchall()

    total_pages = max(1, (total + page_size - 1) // page_size)
    filters.update({"page": page, "page_size": page_size, "total_pages": total_pages})
    return render(
        request,
        "statements.html",
        {"accounts": accounts, "transactions": transactions, "filters": filters},
    )


@router.get("/statements.csv")
def export_statements(request: Request) -> Response:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    admin_redirect = admin_guard(user)
    if admin_redirect:
        return admin_redirect

    scope = {
        "account_id": request.query_params.get("account_id", ""),
        "txn_type": request.query_params.get("txn_type", ""),
        "date_from": request.query_params.get("date_from", ""),
        "date_to": request.query_params.get("date_to", ""),
    }
    if poia_required("statement_export") and request.query_params.get("poia") != "1":
        intent_id = create_poia_intent(
            action="statement_export",
            scope=scope,
            context={"rp_id": "poia-demo-bank", "user_id": user["id"]},
        )
        return RedirectResponse(url=f"/statements?poia_intent={intent_id}", status_code=303)

    intent_body = build_intent(
        action="statement_export",
        scope=scope,
        context={"rp_id": "poia-demo-bank", "user_id": user["id"]},
    )
    return execute_statements_export(request, user, intent_body)


def statement_filters_from_scope(scope: Dict[str, Any], user_id: int) -> tuple[str, list[Any]]:
    account_id = scope.get("account_id", "")
    txn_type = scope.get("txn_type", "")
    date_from = scope.get("date_from", "")
    date_to = scope.get("date_to", "")

    where_clauses = ["accounts.user_id = ?"]
    params: list[Any] = [user_id]
    account_id_value: Optional[int] = None
    if account_id:
        try:
            account_id_value = int(account_id)
        except ValueError:
            account_id_value = None
    if account_id_value is not None:
        where_clauses.append("accounts.id = ?")
        params.append(account_id_value)
    if txn_type:
        where_clauses.append("transactions.txn_type = ?")
        params.append(txn_type)
    from_epoch = parse_date_to_epoch(date_from)
    if from_epoch is not None:
        where_clauses.append("transactions.created_at >= ?")
        params.append(from_epoch)
    to_epoch = parse_date_to_epoch(date_to, end_of_day=True)
    if to_epoch is not None:
        where_clauses.append("transactions.created_at <= ?")
        params.append(to_epoch)

    return " AND ".join(where_clauses), params


def execute_statements_export(request: Request, user, intent_body: Dict[str, Any]) -> Response:
    scope = intent_body["scope"]
    where_sql, params = statement_filters_from_scope(scope, user["id"])

    with db_connect() as conn:
        rows = conn.execute(
            """
            SELECT accounts.account_type, transactions.txn_type, transactions.amount, transactions.currency,
                   transactions.counterparty, transactions.reference, transactions.created_at, transactions.status
            FROM transactions
            JOIN accounts ON transactions.account_id = accounts.id
            WHERE {}
            ORDER BY transactions.created_at DESC
            """.format(where_sql),
            params,
        ).fetchall()

    output = []
    header = ["account_type", "txn_type", "amount", "currency", "counterparty", "reference", "created_at", "status"]
    output.append(header)
    for row in rows:
        output.append([row[col] for col in header])

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    for row in output:
        writer.writerow(row)
    csv_data = buffer.getvalue()

    headers = {"Content-Disposition": "attachment; filename=statements.csv"}
    return Response(content=csv_data, media_type="text/csv", headers=headers)


def render_transfer_form(request: Request, user, error: str) -> HTMLResponse:
    with db_connect() as conn:
        accounts = conn.execute("SELECT * FROM accounts WHERE user_id = ?", (user["id"],)).fetchall()
        beneficiaries = conn.execute("SELECT * FROM beneficiaries WHERE user_id = ?", (user["id"],)).fetchall()
    return render(
        request,
        "transfer.html",
        {"accounts": accounts, "beneficiaries": beneficiaries, "error": error},
    )


def execute_transfer(request: Request, user, intent_body: Dict[str, Any]) -> HTMLResponse:
    scope = intent_body["scope"]
    from_account = scope["from_account"]
    amount = float(scope["amount"])
    currency = scope["currency"]
    beneficiary_id = scope.get("beneficiary_id")
    external_account = scope.get("external_account")

    with db_connect() as conn:
        account = conn.execute(
            "SELECT * FROM accounts WHERE id = ? AND user_id = ?",
            (from_account, user["id"]),
        ).fetchone()
        if not account or account["balance"] < amount:
            return render(request, "result.html", {"status": "Rejected", "message": "Insufficient funds or invalid account."})

        if beneficiary_id:
            beneficiary = conn.execute(
                "SELECT * FROM beneficiaries WHERE id = ? AND user_id = ?",
                (beneficiary_id, user["id"]),
            ).fetchone()
            if not beneficiary:
                return render(request, "result.html", {"status": "Rejected", "message": "Unknown beneficiary."})
            counterparty = beneficiary["name"]
            reference = f"{beneficiary['bank']} {beneficiary['account_number']}"
        else:
            counterparty = "External"
            reference = external_account or "External account"

        new_balance = account["balance"] - amount
        conn.execute("UPDATE accounts SET balance = ? WHERE id = ?", (new_balance, from_account))
        conn.execute(
            """
            INSERT INTO transactions (account_id, txn_type, amount, currency, counterparty, reference, created_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (from_account, "transfer", amount, currency, counterparty, reference, int(time.time()), "completed"),
        )

    log_audit(user["id"], "transfer", f"Transfer {amount} {currency} to {counterparty}")
    return render(request, "result.html", {"status": "Approved", "message": "Transfer completed.", "intent": intent_body})


def execute_beneficiary_add(request: Request, user, intent_body: Dict[str, Any]) -> HTMLResponse:
    scope = intent_body["scope"]
    with db_connect() as conn:
        conn.execute(
            """
            INSERT INTO beneficiaries (user_id, name, bank, account_number, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user["id"], scope["name"], scope["bank"], scope["account_number"], int(time.time())),
        )

    log_audit(user["id"], "beneficiary_add", f"Added {scope['name']} at {scope['bank']}")
    return render(request, "result.html", {"status": "Approved", "message": "Beneficiary added.", "intent": intent_body})


def execute_cash(request: Request, user, intent_body: Dict[str, Any]) -> HTMLResponse:
    scope = intent_body["scope"]
    account_id = scope["account_id"]
    amount = float(scope["amount"])
    currency = scope["currency"]
    action = intent_body["action"]

    with db_connect() as conn:
        account = conn.execute(
            "SELECT * FROM accounts WHERE id = ? AND user_id = ?",
            (account_id, user["id"]),
        ).fetchone()
        if not account:
            return render(request, "result.html", {"status": "Rejected", "message": "Unknown account."})

        if action == "withdrawal" and account["balance"] < amount:
            return render(request, "result.html", {"status": "Rejected", "message": "Insufficient funds."})

        new_balance = account["balance"] + amount if action == "deposit" else account["balance"] - amount
        conn.execute("UPDATE accounts SET balance = ? WHERE id = ?", (new_balance, account_id))
        conn.execute(
            """
            INSERT INTO transactions (account_id, txn_type, amount, currency, counterparty, reference, created_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (account_id, action, amount, currency, "Cash", "Cash operation", int(time.time()), "completed"),
        )

    log_audit(user["id"], action, f"{action.title()} {amount} {currency}")
    return render(request, "result.html", {"status": "Approved", "message": f"{action.title()} completed.", "intent": intent_body})
