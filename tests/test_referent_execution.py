import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.responses import HTMLResponse

from app import core, db
from app.routes import banking
from app.presentation import render_intent_fields


@pytest.fixture
def transfer():
    with tempfile.TemporaryDirectory() as directory, patch.object(db, "DB_PATH", Path(directory) / "bank.db"), patch.object(core, "RSI_ENABLED", True):
        db.init_db()
        with db.db_connect() as conn:
            user = conn.execute("INSERT INTO users (email,password_hash,created_at) VALUES ('rsi@example.invalid','unused',0)").lastrowid
            account = conn.execute("INSERT INTO accounts (user_id,account_type,balance,created_at) VALUES (?,'checking',1000,0)", (user,)).lastrowid
            beneficiary = conn.execute("INSERT INTO beneficiaries (user_id,name,bank,account_number,created_at) VALUES (?,'Recipient','Bank','9007',0)", (user,)).lastrowid
        scope = {"from_account": account, "beneficiary_id": beneficiary, "amount": 10.0, "currency": "USD"}
        intent = {"action": "transfer", "scope": scope, "context": {"user_id": user, "referent_commitments": core.compute_referent_commitments("transfer", scope)}}
        with patch.object(banking, "render", side_effect=lambda *a, **kw: HTMLResponse("result")), patch.object(banking, "log_audit"):
            yield {"id": user}, intent


def test_change_after_early_check_is_rejected_at_execution(transfer):
    user, intent = transfer
    assert core.verify_referent_commitments(intent) is None
    with db.db_connect() as conn:
        conn.execute("UPDATE beneficiaries SET account_number='7781', version=version+1")
    response = banking.execute_transfer(None, user, intent)
    assert response.status_code == 409
    with db.db_connect() as conn:
        assert conn.execute("SELECT count(*) FROM transactions").fetchone()[0] == 0
        assert conn.execute("SELECT balance FROM accounts").fetchone()[0] == 1000


def test_restored_content_with_new_version_is_rejected(transfer):
    _, intent = transfer
    with db.db_connect() as conn:
        conn.execute("UPDATE beneficiaries SET version=version+2")
    assert core.verify_referent_commitments(intent) == "referent_version_mismatch"


def test_missing_commitments_fail_closed(transfer):
    user, intent = transfer
    intent["context"].pop("referent_commitments")
    assert banking.execute_transfer(None, user, intent).status_code == 409


def test_display_is_stable_and_excludes_raw_commitment_content(transfer):
    # render_intent_fields() feeds the human-facing approval screen (web
    # modal and ZT-Authenticator mobile app both use the equivalent
    # function). It must be perfectly stable across a mutation of the live
    # row -- there is no "live" value it could pick up, since it only ever
    # reads the already-signed scope/context, never the database.
    #
    # It also must not surface referent_commitments' raw content (e.g. a
    # frozen "Account number") at all: RSI's guarantee -- that execution is
    # refused if the committed resource has changed since signing -- is
    # enforced server-side in verify_referent_commitments()/execute_transfer()
    # regardless of what is rendered here, so nothing about that guarantee
    # depends on a human re-reading commitment content on this screen, and
    # showing it was pure duplication of the recipient/account fields
    # already present in scope. See verifiedDisplayFields() in
    # ZT-Authenticator/mobile/lib/main.dart, which excludes the same key
    # for the same reason.
    _, intent = transfer
    before = render_intent_fields(intent["action"], intent["scope"], intent["context"])
    with db.db_connect() as conn:
        conn.execute("UPDATE beneficiaries SET account_number='7781', version=version+1")
    after = render_intent_fields(intent["action"], intent["scope"], intent["context"])
    assert after == before
    labels = [label for label, _ in after]
    assert "Committed resource" not in labels
    assert "Account number" not in labels


def test_all_scope_and_context_fields_are_rendered():
    scope = {"account_id": "17", "txn_type": "transfer", "date_from": "2026-01-01", "date_to": "2026-09-01"}
    context = {"user_id": "owner", "workflow_id": "workflow-1", "rp_id": "poia-demo-bank"}
    fields = dict(render_intent_fields("statement_export", scope, context))
    for key, value in {**scope, **context}.items():
        assert fields[key.replace("_", " ").capitalize()] == value


def test_writer_cannot_change_referent_during_execution(transfer):
    user, intent = transfer
    attempted = threading.Event()
    finished = threading.Event()
    errors = []

    def writer():
        try:
            with db.db_connect() as conn:
                attempted.set()
                conn.execute("UPDATE beneficiaries SET account_number='7781', version=version+1")
            finished.set()
        except Exception as error:
            errors.append(error)

    threads = []
    def checked(body, *, conn):
        result = core.verify_referent_commitments(body, conn=conn)
        thread = threading.Thread(target=writer)
        threads.append(thread)
        thread.start()
        assert attempted.wait(2)
        assert not finished.wait(0.1)
        return result

    with patch.object(banking, "verify_referent_commitments", side_effect=checked):
        assert banking.execute_transfer(None, user, intent).status_code == 200
    for thread in threads:
        thread.join(5)
        assert not thread.is_alive()
    assert not errors
    assert finished.is_set()
    with db.db_connect() as conn:
        assert conn.execute("SELECT reference FROM transactions").fetchone()[0] == "Bank 9007"
