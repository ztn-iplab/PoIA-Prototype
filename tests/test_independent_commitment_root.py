"""Tests for the independent commitment root (Root B in its own process).

The point under test is sourcing, not comparison: when the primary store's row
is rewritten, a root reading its own append-only journal must still report the
approved content, so the gate refuses. The shared-source case must degenerate,
and an unreachable root must fail closed.
"""

from __future__ import annotations

import contextlib

import os
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HOST = "127.0.0.1"


def free_port() -> int:
    with contextlib.closing(socket.socket()) as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


class IndependentCommitmentRootTest(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        self.db_path = tmp / "bank.db"
        self.journal_path = tmp / "referent_journal.db"

        from app import commitment_confinement, db, referent_journal

        self.db = db
        self.journal = referent_journal
        self.gate = commitment_confinement

        # Redirect module globals rather than reloading modules or editing
        # os.environ: other test modules already hold references to these, and a
        # reload would leave them pointing at this test's deleted temp files.
        self._saved = {
            (db, "DB_PATH"): db.DB_PATH,
            (referent_journal, "JOURNAL_ENABLED"): referent_journal.JOURNAL_ENABLED,
            (referent_journal, "JOURNAL_PATH"): referent_journal.JOURNAL_PATH,
            (commitment_confinement, "KOFN_ENABLED"): commitment_confinement.KOFN_ENABLED,
            (commitment_confinement, "KOFN_ROOT_B_MODE"): commitment_confinement.KOFN_ROOT_B_MODE,
            (commitment_confinement, "KOFN_ROOT_B_URL"): commitment_confinement.KOFN_ROOT_B_URL,
        }
        db.DB_PATH = self.db_path
        referent_journal.JOURNAL_ENABLED = True
        referent_journal.JOURNAL_PATH = self.journal_path
        self.db.init_db()
        self.journal.init_journal()

        with self.db.db_connect() as conn:
            self.user_id = conn.execute(
                "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)",
                ("root-b-test@example.invalid", "unused", int(time.time())),
            ).lastrowid
            self.beneficiary_id = conn.execute(
                "INSERT INTO beneficiaries (user_id, name, bank, account_number, version, updated_at, created_at) "
                "VALUES (?, 'Approved Payee', 'Origin Bank', '700001', 1, ?, ?)",
                (self.user_id, int(time.time()), int(time.time())),
            ).lastrowid
            self.journal.record_beneficiary(conn, self.beneficiary_id)

        self.scope = {
            "from_account": 0,
            "amount": 250.0,
            "currency": "USD",
            "beneficiary_id": self.beneficiary_id,
        }
        self.context = {"rp_id": "poia-demo-bank"}

    def tearDown(self) -> None:
        for (module, name), value in self._saved.items():
            setattr(module, name, value)
        self._tmp.cleanup()

    def corrupt_primary(self) -> None:
        with self.db.db_connect() as conn:
            conn.execute(
                "UPDATE beneficiaries SET account_number = 'ATTACKER-1' WHERE id = ?",
                (self.beneficiary_id,),
            )

    @contextlib.contextmanager
    def root_b(self, source: str = "journal"):
        port = free_port()
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO_ROOT)
        env["POIA_DB_PATH"] = str(self.db_path)
        env["POIA_REFERENT_JOURNAL_PATH"] = str(self.journal_path)
        env["POIA_REFERENT_JOURNAL_ENABLED"] = "true"
        if source == "primary":
            env["POIA_ROOT_B_ALLOW_PRIMARY"] = "true"
        proc = subprocess.Popen(
            [sys.executable, "-m", "app.root_b_service", "--host", HOST,
             "--port", str(port), "--source", source],
            cwd=str(REPO_ROOT), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        try:
            deadline = time.time() + 15.0
            while time.time() < deadline:
                if proc.poll() is not None:
                    self.fail(f"Root B exited: {proc.stderr.read().decode(errors='replace')[:400]}")
                try:
                    with contextlib.closing(socket.create_connection((HOST, port), 0.25)):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                self.fail("Root B never became reachable")
            self.gate.KOFN_ENABLED = True
            self.gate.KOFN_ROOT_B_MODE = "service"
            self.gate.KOFN_ROOT_B_URL = f"http://{HOST}:{port}"
            yield port
        finally:
            if proc.poll() is None:
                proc.terminate()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=5)

    def test_journal_reconstructs_highest_version(self) -> None:
        self.journal.append("beneficiary", self.beneficiary_id, 2, {"name": "X", "bank": "Y", "account_number": "999"})
        record = self.journal.reconstruct("beneficiary", self.beneficiary_id)
        self.assertEqual(record["version"], 2)
        self.assertEqual(record["account_number"], "999")

    def test_journal_reports_unknown_referent_as_missing(self) -> None:
        self.assertIsNone(self.journal.reconstruct("beneficiary", 999_999))

    def test_independent_root_refuses_after_primary_compromise(self) -> None:
        with self.root_b("journal"):
            self.assertIsNone(
                self.gate.confine_commitment(action="transfer", scope=self.scope, context=self.context),
                "uncorrupted commitment must be accepted",
            )
            self.corrupt_primary()
            reason = self.gate.confine_commitment(action="transfer", scope=self.scope, context=self.context)
        self.assertEqual(reason, "commitment_root_disagreement")

    def test_shared_source_degenerates_to_single_root(self) -> None:
        """The documented boundary: roots sharing an upstream fail together."""
        with self.root_b("primary"):
            self.corrupt_primary()
            reason = self.gate.confine_commitment(action="transfer", scope=self.scope, context=self.context)
        self.assertIsNone(reason, "shared-source roots are expected to agree on the attacker's value")

    def test_unreachable_root_fails_closed(self) -> None:
        self.gate.KOFN_ENABLED = True
        self.gate.KOFN_ROOT_B_MODE = "service"
        self.gate.KOFN_ROOT_B_URL = f"http://{HOST}:{free_port()}"
        reason = self.gate.confine_commitment(action="transfer", scope=self.scope, context=self.context)
        self.assertEqual(reason, "commitment_root_b_unavailable")

    def test_missing_journal_history_refuses_rather_than_defaults(self) -> None:
        with self.db.db_connect() as conn:
            orphan_id = conn.execute(
                "INSERT INTO beneficiaries (user_id, name, bank, account_number, version, updated_at, created_at) "
                "VALUES (?, 'Unjournalled', 'Bank', '700002', 1, ?, ?)",
                (self.user_id, int(time.time()), int(time.time())),
            ).lastrowid
        with self.root_b("journal"):
            reason = self.gate.confine_commitment(
                action="transfer",
                scope={**self.scope, "beneficiary_id": orphan_id},
                context=self.context,
            )
        self.assertEqual(reason, "commitment_root_b_root_b_cannot_source_referent")

    def test_inprocess_mode_is_unchanged(self) -> None:
        """The default configuration, and the one the earlier evaluation used,
        still agrees with itself when both functions read the same row."""
        self.gate.KOFN_ENABLED = True
        self.gate.KOFN_ROOT_B_MODE = "inprocess"
        self.assertIsNone(
            self.gate.confine_commitment(action="transfer", scope=self.scope, context=self.context)
        )
        self.corrupt_primary()
        self.assertIsNone(
            self.gate.confine_commitment(action="transfer", scope=self.scope, context=self.context),
            "both in-process roots read the corrupted row, so they agree: this is the gap E6b closes",
        )


if __name__ == "__main__":
    unittest.main()
