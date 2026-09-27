import csv
import io
import math
import re
import secrets
import time
from typing import Any, Dict, Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from ..core import (
    PoIACommitmentError,
    build_intent,
    create_poia_intent,
    log_audit,
    poia_required,
    render,
    require_login,
    get_current_user,
    verify_referent_commitments,
)
from ..db import db_connect, begin_immediate
from ..execution_grants import consume_grant
from ..mfa_utils import build_statement_filters, parse_date_to_epoch
from ..model import ChallengeRecord, IntentRecord

router = APIRouter()


def admin_guard(user: Dict[str, Any]) -> Optional[RedirectResponse]:
    if user and user["is_admin"]:
        return RedirectResponse(url="/admin/dashboard", status_code=302)
    return None


def _start_poia_or_none(
    *, action: str, scope: Dict[str, Any], user_id: int
) -> tuple[Optional[str], Optional[str]]:
    """Start a PoIA intent, translating a Commitment Confinement refusal into a
    plain-language reason instead of a 500. A refusal here should be rare -- it
    only fires on a genuine bug or an active compromise attempt (see
    app.commitment_confinement) -- but it must fail closed and visibly, not crash."""
    try:
        intent_id = create_poia_intent(
            action=action,
            scope=scope,
            context={"rp_id": "poia-demo-bank", "user_id": user_id},
        )
        return intent_id, None
    except PoIACommitmentError:
        return None, (
            "This request could not be safely confirmed for signing (the system's "
            "independent checks disagreed on the details). Nothing was changed. "
            "Please try again, and contact support if this persists."
        )


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


_ACCOUNT_NUMBER_RE = re.compile(r"^[0-9]{4,34}$")


def _validate_beneficiary_fields(
    *,
    name: str,
    bank: str,
    account_number: str,
    confirm_account_number: str,
    user_id: int,
    exclude_beneficiary_id: Optional[int] = None,
) -> Optional[str]:
    """Standard banking safeguards for adding/editing a beneficiary's bank details:
    require a confirmation field to match (the same guard rail every real bank
    applies to a field that misdirects money if mistyped), reject anything that
    isn't a plausible account number, and refuse a second beneficiary pointing at
    an account you already have saved so PoIA approvals aren't wasted on
    duplicates."""
    if not name.strip() or not bank.strip() or not account_number:
        return "All fields are required."
    if account_number != confirm_account_number:
        return "Account number and confirmation do not match. Please re-enter both."
    if not _ACCOUNT_NUMBER_RE.match(account_number):
        return "Account number must be 4-34 digits, with no letters, spaces, or punctuation."
    with db_connect() as conn:
        query = "SELECT id FROM beneficiaries WHERE user_id = ? AND account_number = ?"
        params: tuple[Any, ...] = (user_id, account_number)
        if exclude_beneficiary_id is not None:
            query += " AND id != ?"
            params += (exclude_beneficiary_id,)
        existing = conn.execute(query, params).fetchone()
    if existing:
        return "You already have a beneficiary saved with this account number."
    return None


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
    confirm_account_number: str = Form(""),
) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    admin_redirect = admin_guard(user)
    if admin_redirect:
        return admin_redirect

    validation_error = _validate_beneficiary_fields(
        name=name,
        bank=bank,
        account_number=account_number,
        confirm_account_number=confirm_account_number,
        user_id=user["id"],
    )
    if validation_error:
        return render(request, "beneficiary_add.html", {"error": validation_error})

    if poia_required("beneficiary_add"):
        intent_id, error = _start_poia_or_none(
            action="beneficiary_add",
            scope={"name": name, "bank": bank, "account_number": account_number},
            user_id=user["id"],
        )
        if error:
            return render(request, "beneficiary_add.html", {"error": error})
        return RedirectResponse(url=f"/beneficiaries/add?poia_intent={intent_id}", status_code=303)

    intent_body = build_intent(
        action="beneficiary_add",
        scope={"name": name, "bank": bank, "account_number": account_number},
        context={"rp_id": "poia-demo-bank", "user_id": user["id"]},
    )
    return execute_beneficiary_add(request, user, intent_body)


@router.get("/beneficiaries/{beneficiary_id}/edit", response_class=HTMLResponse)
def beneficiary_edit_form(request: Request, beneficiary_id: int) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    admin_redirect = admin_guard(user)
    if admin_redirect:
        return admin_redirect

    with db_connect() as conn:
        beneficiary = conn.execute(
            "SELECT * FROM beneficiaries WHERE id = ? AND user_id = ?",
            (beneficiary_id, user["id"]),
        ).fetchone()
    if not beneficiary:
        return RedirectResponse(url="/beneficiaries", status_code=302)

    return render(request, "beneficiary_edit.html", {"beneficiary": beneficiary, "error": ""})


@router.post("/beneficiaries/{beneficiary_id}/edit", response_class=HTMLResponse)
def beneficiary_edit_submit(
    request: Request,
    beneficiary_id: int,
    name: str = Form(""),
    bank: str = Form(""),
    account_number: str = Form(""),
    confirm_account_number: str = Form(""),
) -> HTMLResponse:
    user = get_current_user(request)
    if not require_login(user):
        return RedirectResponse(url="/login", status_code=302)
    admin_redirect = admin_guard(user)
    if admin_redirect:
        return admin_redirect

    with db_connect() as conn:
        beneficiary = conn.execute(
            "SELECT * FROM beneficiaries WHERE id = ? AND user_id = ?",
            (beneficiary_id, user["id"]),
        ).fetchone()
    if not beneficiary:
        return RedirectResponse(url="/beneficiaries", status_code=302)

    validation_error = _validate_beneficiary_fields(
        name=name,
        bank=bank,
        account_number=account_number,
        confirm_account_number=confirm_account_number,
        user_id=user["id"],
        exclude_beneficiary_id=beneficiary_id,
    )
    if validation_error:
        return render(
            request,
            "beneficiary_edit.html",
            {"beneficiary": beneficiary, "error": validation_error},
        )

    scope = {
        "beneficiary_id": beneficiary_id,
        "name": name,
        "bank": bank,
        "account_number": account_number,
    }

    if poia_required("beneficiary_edit"):
        intent_id, error = _start_poia_or_none(action="beneficiary_edit", scope=scope, user_id=user["id"])
        if error:
            return render(request, "beneficiary_edit.html", {"beneficiary": beneficiary, "error": error})
        return RedirectResponse(url=f"/beneficiaries/{beneficiary_id}/edit?poia_intent={intent_id}", status_code=303)

    intent_body = build_intent(
        action="beneficiary_edit",
        scope=scope,
        context={"rp_id": "poia-demo-bank", "user_id": user["id"]},
    )
    return execute_beneficiary_edit(request, user, intent_body)


@router.get("/accounts/{account_id}/limit", response_class=HTMLResponse)
def account_limit_form(request: Request, account_id: int) -> HTMLResponse:
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
    if not account:
        return RedirectResponse(url="/dashboard", status_code=302)

    return render(request, "account_limit.html", {"account": account, "error": ""})


@router.post("/accounts/{account_id}/limit", response_class=HTMLResponse)
def account_limit_submit(
    request: Request,
    account_id: int,
    new_daily_limit: float = Form(...),
) -> HTMLResponse:
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
    if not account:
        return RedirectResponse(url="/dashboard", status_code=302)

    if not math.isfinite(new_daily_limit) or new_daily_limit <= 0:
        return render(
            request,
            "account_limit.html",
            {"account": account, "error": "Enter a limit greater than 0."},
        )

    scope = {"account_id": account_id, "new_daily_limit": new_daily_limit}

    if poia_required("limit_change"):
        intent_id, error = _start_poia_or_none(action="limit_change", scope=scope, user_id=user["id"])
        if error:
            return render(request, "account_limit.html", {"account": account, "error": error})
        return RedirectResponse(url=f"/accounts/{account_id}/limit?poia_intent={intent_id}", status_code=303)

    intent_body = build_intent(
        action="limit_change",
        scope=scope,
        context={"rp_id": "poia-demo-bank", "user_id": user["id"]},
    )
    return execute_limit_change(request, user, intent_body, verify_referents=False)


@router.get("/accounts/{account_id}/recover", response_class=HTMLResponse)
def account_recovery_form(request: Request, account_id: int) -> HTMLResponse:
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
    if not account:
        return RedirectResponse(url="/dashboard", status_code=302)
    if account["status"] == "active":
        return RedirectResponse(url=f"/accounts/{account_id}", status_code=302)

    return render(request, "account_recovery.html", {"account": account, "error": ""})


@router.post("/accounts/{account_id}/recover", response_class=HTMLResponse)
def account_recovery_submit(request: Request, account_id: int) -> HTMLResponse:
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
    if not account:
        return RedirectResponse(url="/dashboard", status_code=302)
    if account["status"] == "active":
        return RedirectResponse(url=f"/accounts/{account_id}", status_code=302)

    scope = {"account_id": account_id}

    if poia_required("account_recovery"):
        intent_id, error = _start_poia_or_none(action="account_recovery", scope=scope, user_id=user["id"])
        if error:
            return render(request, "account_recovery.html", {"account": account, "error": error})
        return RedirectResponse(url=f"/accounts/{account_id}/recover?poia_intent={intent_id}", status_code=303)

    intent_body = build_intent(
        action="account_recovery",
        scope=scope,
        context={"rp_id": "poia-demo-bank", "user_id": user["id"]},
    )
    return execute_account_recovery(request, user, intent_body, verify_referents=False)


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

    if not math.isfinite(amount) or amount <= 0:
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
        if not external_value.isdigit():
            return render_transfer_form(request, user, "External account must contain numbers only.")

    scope = {"from_account": from_account, "amount": amount, "currency": currency}
    if to_type == "beneficiary":
        # Look up the beneficiary's display name now, scoped to this user,
        # and bind it into the scope that gets canonicalized/hashed/signed
        # below -- so the approver's device shows a real name instead of a
        # bare id, without introducing a separate, unverified display path.
        # This also catches a beneficiary_id that doesn't belong to this
        # user before an intent is ever created for it.
        with db_connect() as conn:
            beneficiary = conn.execute(
                "SELECT * FROM beneficiaries WHERE id = ? AND user_id = ?",
                (beneficiary_int, user["id"]),
            ).fetchone()
        if not beneficiary:
            return render_transfer_form(request, user, "Unknown beneficiary.")
        scope.update({
            "beneficiary_id": beneficiary_int,
            "beneficiary_name": beneficiary["name"],
        })
    else:
        scope.update({"external_account": external_value})

    if poia_required("transfer", amount):
        intent_id, error = _start_poia_or_none(action="transfer", scope=scope, user_id=user["id"])
        if error:
            return render_transfer_form(request, user, error)
        return RedirectResponse(url=f"/transfer?poia_intent={intent_id}", status_code=303)

    intent_body = build_intent(
        action="transfer",
        scope=scope,
        context={"rp_id": "poia-demo-bank", "user_id": user["id"]},
    )
    return execute_transfer(request, user, intent_body, verify_referents=False)


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

    if not math.isfinite(amount) or amount <= 0:
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
        # where_sql contains only fixed clauses; all values remain bound parameters.
        count_query = """
            SELECT COUNT(*)
            FROM transactions
            JOIN accounts ON transactions.account_id = accounts.id
            WHERE {}
            """.format(where_sql)  # nosec B608
        total = conn.execute(
            count_query,
            params,
        ).fetchone()[0]
        transaction_query = """
            SELECT transactions.*, accounts.account_type
            FROM transactions
            JOIN accounts ON transactions.account_id = accounts.id
            WHERE {}
            ORDER BY transactions.created_at DESC
            LIMIT ? OFFSET ?
            """.format(where_sql)  # nosec B608
        transactions = conn.execute(
            transaction_query,
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
    if poia_required("statement_export") and not consume_grant(
        request.query_params.get("grant", ""), user["id"], "statement_export", scope
    ):
        intent_id = create_poia_intent(
            action="statement_export",
            scope=scope,
            context={"rp_id": "poia-demo-bank", "user_id": user["id"]},
        )
        redirect_query = urlencode(
            {
                "account_id": scope["account_id"],
                "txn_type": scope["txn_type"],
                "date_from": scope["date_from"],
                "date_to": scope["date_to"],
                "poia_intent": intent_id,
            }
        )
        return RedirectResponse(url=f"/statements?{redirect_query}", status_code=303)

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
            """.format(where_sql),  # nosec B608
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


def execute_transfer(request: Request, user, intent_body: Dict[str, Any], *, verify_referents: bool = True) -> HTMLResponse:
    scope = intent_body["scope"]
    from_account = scope["from_account"]
    amount = float(scope["amount"])
    currency = scope["currency"]
    beneficiary_id = scope.get("beneficiary_id")
    external_account = scope.get("external_account")

    if not math.isfinite(amount) or amount <= 0:
        return render(request, "result.html", {"status": "Rejected", "message": "Invalid transfer amount."})

    with db_connect() as conn:
        begin_immediate(conn)
        reason = verify_referent_commitments(intent_body, conn=conn) if verify_referents else None
        if reason:
            return referent_rejection(request, reason)
        account = conn.execute(
            "SELECT * FROM accounts WHERE id = ? AND user_id = ?",
            (from_account, user["id"]),
        ).fetchone()
        if not account or account["balance"] < amount:
            return render(request, "result.html", {"status": "Rejected", "message": "Insufficient funds or invalid account."})

        if account["status"] != "active":
            return render(
                request,
                "result.html",
                {
                    "status": "Rejected",
                    "message": (
                        f"Account #{from_account} is {account['status']} and cannot send funds. "
                        f"Recover it first from the account page before transferring."
                    ),
                },
            )

        if amount > account["daily_transfer_limit"]:
            return render(
                request,
                "result.html",
                {
                    "status": "Rejected",
                    "message": (
                        f"This transfer of {amount:,.2f} {currency} exceeds account #{from_account}'s "
                        f"daily transfer limit of {account['daily_transfer_limit']:,.2f}. "
                        f"Raise the limit from the account page before retrying."
                    ),
                },
            )

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
            INSERT INTO beneficiaries (user_id, name, bank, account_number, version, updated_at, created_at)
            VALUES (?, ?, ?, ?, 1, ?, ?)
            """,
            (user["id"], scope["name"], scope["bank"], scope["account_number"], int(time.time()), int(time.time())),
        )

    log_audit(user["id"], "beneficiary_add", f"Added {scope['name']} at {scope['bank']}")
    return render(request, "result.html", {"status": "Approved", "message": "Beneficiary added.", "intent": intent_body})


def execute_beneficiary_edit(request: Request, user, intent_body: Dict[str, Any]) -> HTMLResponse:
    scope = intent_body["scope"]
    beneficiary_id = scope["beneficiary_id"]
    with db_connect() as conn:
        beneficiary = conn.execute(
            "SELECT * FROM beneficiaries WHERE id = ? AND user_id = ?",
            (beneficiary_id, user["id"]),
        ).fetchone()
        if not beneficiary:
            return render(request, "result.html", {"status": "Rejected", "message": "Unknown beneficiary."})
        conn.execute(
            """
            UPDATE beneficiaries
            SET name = ?, bank = ?, account_number = ?, version = version + 1, updated_at = ?
            WHERE id = ?
            """,
            (scope["name"], scope["bank"], scope["account_number"], int(time.time()), beneficiary_id),
        )

    log_audit(
        user["id"],
        "beneficiary_edit",
        f"Updated beneficiary #{beneficiary_id} ({beneficiary['name']} -> {scope['name']})",
    )
    return render(
        request,
        "result.html",
        {"status": "Approved", "message": "Beneficiary details updated.", "intent": intent_body},
    )


def execute_cash(request: Request, user, intent_body: Dict[str, Any]) -> HTMLResponse:
    scope = intent_body["scope"]
    account_id = scope["account_id"]
    amount = float(scope["amount"])
    currency = scope["currency"]
    action = intent_body["action"]

    if action not in {"deposit", "withdrawal"} or not math.isfinite(amount) or amount <= 0:
        return render(request, "result.html", {"status": "Rejected", "message": "Invalid cash operation."})

    with db_connect() as conn:
        begin_immediate(conn)
        account = conn.execute(
            "SELECT * FROM accounts WHERE id = ? AND user_id = ?",
            (account_id, user["id"]),
        ).fetchone()
        if not account:
            return render(request, "result.html", {"status": "Rejected", "message": "Unknown account."})

        if account["status"] != "active":
            return render(
                request,
                "result.html",
                {
                    "status": "Rejected",
                    "message": (
                        f"Account #{account_id} is {account['status']} and cannot process {action}s. "
                        f"Recover it first from the account page before retrying."
                    ),
                },
            )

        if action == "withdrawal" and account["balance"] < amount:
            return render(request, "result.html", {"status": "Rejected", "message": "Insufficient funds."})

        if action == "withdrawal" and amount > account["daily_transfer_limit"]:
            return render(
                request,
                "result.html",
                {
                    "status": "Rejected",
                    "message": (
                        f"This withdrawal of {amount:,.2f} {currency} exceeds account #{account_id}'s "
                        f"daily transfer limit of {account['daily_transfer_limit']:,.2f}. "
                        f"Raise the limit from the account page before retrying."
                    ),
                },
            )

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


def execute_limit_change(request: Request, user, intent_body: Dict[str, Any], *, verify_referents: bool = True) -> HTMLResponse:
    scope = intent_body["scope"]
    account_id = scope["account_id"]
    new_limit = float(scope["new_daily_limit"])

    if not math.isfinite(new_limit) or new_limit <= 0:
        return render(request, "result.html", {"status": "Rejected", "message": "Invalid limit."})

    with db_connect() as conn:
        begin_immediate(conn)
        reason = verify_referent_commitments(intent_body, conn=conn) if verify_referents else None
        if reason:
            return referent_rejection(request, reason)
        account = conn.execute(
            "SELECT * FROM accounts WHERE id = ? AND user_id = ?",
            (account_id, user["id"]),
        ).fetchone()
        if not account:
            return render(request, "result.html", {"status": "Rejected", "message": "Unknown account."})
        conn.execute(
            "UPDATE accounts SET daily_transfer_limit = ?, version = version + 1, updated_at = ? WHERE id = ?",
            (new_limit, int(time.time()), account_id),
        )

    log_audit(user["id"], "limit_change", f"Account #{account_id} daily limit -> {new_limit}")
    return render(
        request,
        "result.html",
        {"status": "Approved", "message": "Daily transfer limit updated.", "intent": intent_body},
    )


def execute_account_recovery(request: Request, user, intent_body: Dict[str, Any], *, verify_referents: bool = True) -> HTMLResponse:
    scope = intent_body["scope"]
    account_id = scope["account_id"]

    with db_connect() as conn:
        begin_immediate(conn)
        reason = verify_referent_commitments(intent_body, conn=conn) if verify_referents else None
        if reason:
            return referent_rejection(request, reason)
        account = conn.execute(
            "SELECT * FROM accounts WHERE id = ? AND user_id = ?",
            (account_id, user["id"]),
        ).fetchone()
        if not account:
            return render(request, "result.html", {"status": "Rejected", "message": "Unknown account."})
        if account["status"] == "active":
            return render(
                request,
                "result.html",
                {"status": "Rejected", "message": "This account is already active."},
            )
        previous_status = account["status"]
        conn.execute(
            "UPDATE accounts SET status = 'active', version = version + 1, updated_at = ? WHERE id = ?",
            (int(time.time()), account_id),
        )

    log_audit(user["id"], "account_recovery", f"Account #{account_id} recovered from {previous_status}")
    return render(
        request,
        "result.html",
        {"status": "Approved", "message": "Account access restored.", "intent": intent_body},
    )


def referent_rejection(request: Request, reason: str) -> HTMLResponse:
    response = render(request, "result.html", {
        "status": "Rejected", "message": "The referenced state changed. Review a new authorization request.",
    })
    response.status_code = 409
    response.headers["X-PoIA-Rejection-Reason"] = reason
    return response
