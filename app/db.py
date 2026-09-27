import sqlite3
import time
from contextlib import contextmanager
from contextvars import ContextVar

from .security import hash_password, verify_password
from .settings import ADMIN_EMAIL, ADMIN_PASSWORD, DB_PATH

_transaction_connection = ContextVar("poia_transaction_connection", default=None)


class BorrowedConnection:
    def __init__(self, connection):
        self.connection = connection

    def __getattr__(self, name):
        return getattr(self.connection, name)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def close(self):
        pass


def begin_immediate(conn):
    if not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")


@contextmanager
def transaction():
    existing = _transaction_connection.get()
    if existing is not None:
        yield existing
        return
    with db_connect() as conn:
        begin_immediate(conn)
        token = _transaction_connection.set(conn)
        try:
            yield conn
        finally:
            _transaction_connection.reset(token)


class ManagedConnection(sqlite3.Connection):
    """Finish the transaction before releasing its connection resources."""

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def db_connect() -> sqlite3.Connection:
    existing = _transaction_connection.get()
    if existing is not None:
        return BorrowedConnection(existing)
    conn = sqlite3.connect(DB_PATH, factory=ManagedConnection)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_admin() -> None:
    with db_connect() as conn:
        admin = conn.execute(
            "SELECT id, password_hash, is_admin FROM users WHERE email = ?",
            (ADMIN_EMAIL,),
        ).fetchone()
        if admin:
            if not admin["is_admin"]:
                raise RuntimeError("Configured administrator email belongs to a non-admin account.")
            if ADMIN_PASSWORD and not verify_password(ADMIN_PASSWORD, admin["password_hash"]):
                conn.execute(
                    "UPDATE users SET password_hash = ? WHERE email = ?",
                    (hash_password(ADMIN_PASSWORD), ADMIN_EMAIL),
                )
            return
        if not ADMIN_PASSWORD:
            return
        conn.execute(
            "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)",
            (ADMIN_EMAIL, hash_password(ADMIN_PASSWORD), 1, int(time.time())),
        )


def init_db() -> None:
    with db_connect() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS device_poll_nonces (
            device_id INTEGER NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL,
            PRIMARY KEY (device_id, nonce))""")
        conn.execute("CREATE INDEX IF NOT EXISTS device_poll_nonce_expiry ON device_poll_nonces(expires_at)")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                signup_pending INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS execution_grants (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                scope_hash TEXT NOT NULL,
                expires_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS poia_records (
                kind TEXT NOT NULL,
                record_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (kind, record_id)
            );

            CREATE TABLE IF NOT EXISTS poia_execution_journal (
                intent_id TEXT PRIMARY KEY,
                batch_id TEXT,
                principal_id INTEGER NOT NULL,
                reserved_at REAL NOT NULL,
                completed_at REAL,
                outcome TEXT NOT NULL,
                reason TEXT
            );
            CREATE TABLE IF NOT EXISTS poia_remote_jobs (
                intent_id TEXT PRIMARY KEY,
                principal_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                status TEXT NOT NULL,
                response TEXT,
                http_status INTEGER
            );

            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                account_type TEXT NOT NULL,
                balance REAL NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS beneficiaries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                bank TEXT NOT NULL,
                account_number TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL,
                txn_type TEXT NOT NULL,
                amount REAL NOT NULL,
                currency TEXT NOT NULL,
                counterparty TEXT NOT NULL,
                reference TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                status TEXT NOT NULL,
                FOREIGN KEY(account_id) REFERENCES accounts(id)
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS mfa_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                status TEXT NOT NULL,
                reason TEXT,
                duration_ms INTEGER,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS pending_totp (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                secret TEXT NOT NULL,
                email TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                device_label TEXT NOT NULL,
                platform TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS device_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                rp_id TEXT NOT NULL,
                key_type TEXT NOT NULL,
                public_key TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(device_id) REFERENCES devices(id)
            );

            CREATE TABLE IF NOT EXISTS login_challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                device_id INTEGER NOT NULL,
                rp_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                otp_hash TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                approved_at INTEGER,
                denied_reason TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(device_id) REFERENCES devices(id)
            );

            CREATE TABLE IF NOT EXISTS webauthn_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                credential_id TEXT NOT NULL,
                public_key TEXT NOT NULL,
                sign_count INTEGER NOT NULL DEFAULT 0,
                transports TEXT,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS poia_workflows (
                workflow_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                scope_hash TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                consumed_at INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS poia_original_requests (
                request_id TEXT PRIMARY KEY,
                intent_id TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                rp_id TEXT NOT NULL,
                canonical_body TEXT NOT NULL,
                canonical_sha256 TEXT NOT NULL,
                created_at REAL NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TRIGGER IF NOT EXISTS poia_original_requests_no_update
            BEFORE UPDATE ON poia_original_requests
            BEGIN
                SELECT RAISE(ABORT, 'poia original requests are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS poia_original_requests_no_delete
            BEFORE DELETE ON poia_original_requests
            BEGIN
                SELECT RAISE(ABORT, 'poia original requests are append-only');
            END;

            CREATE TABLE IF NOT EXISTS poia_human_study_trials (
                trial_id TEXT PRIMARY KEY,
                study_run_id TEXT NOT NULL,
                participant_id TEXT NOT NULL,
                cohort TEXT,
                signing_backend TEXT NOT NULL,
                mutation_stage TEXT NOT NULL,
                mutation_type TEXT NOT NULL,
                original_request_id TEXT NOT NULL,
                intent_id TEXT UNIQUE NOT NULL,
                original_sha256 TEXT NOT NULL,
                displayed_sha256 TEXT NOT NULL,
                expected_participant_decision TEXT NOT NULL,
                task_body TEXT NOT NULL,
                displayed_body TEXT NOT NULL,
                execution_body TEXT,
                mutation_spec TEXT NOT NULL,
                participant_decision TEXT,
                system_decision TEXT,
                rejection_reason TEXT,
                proof_status TEXT,
                created_at REAL NOT NULL,
                prompt_displayed_at REAL,
                decided_at REAL,
                decision_time_ms REAL,
                FOREIGN KEY(original_request_id) REFERENCES poia_original_requests(request_id)
            );

            CREATE TABLE IF NOT EXISTS poia_participant_sessions (
                session_id TEXT PRIMARY KEY,
                participant_id TEXT NOT NULL,
                study_run_id TEXT NOT NULL,
                cohort TEXT,
                user_id INTEGER NOT NULL,
                schedule_json TEXT NOT NULL,
                current_step INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'active',
                created_at REAL NOT NULL,
                completed_at REAL,
                post_session_response TEXT,
                debrief_shown_at REAL,
                debriefed_at REAL,
                UNIQUE(study_run_id, participant_id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS poia_human_study_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                trial_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                execution_sha256 TEXT,
                system_decision TEXT,
                rejection_reason TEXT,
                proof_status TEXT,
                state_before_sha256 TEXT,
                state_after_sha256 TEXT,
                state_changed INTEGER,
                created_at REAL NOT NULL,
                FOREIGN KEY(trial_id) REFERENCES poia_human_study_trials(trial_id)
            );

            CREATE TRIGGER IF NOT EXISTS poia_human_study_events_no_update
            BEFORE UPDATE ON poia_human_study_events
            BEGIN
                SELECT RAISE(ABORT, 'poia human-study events are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS poia_human_study_events_no_delete
            BEFORE DELETE ON poia_human_study_events
            BEGIN
                SELECT RAISE(ABORT, 'poia human-study events are append-only');
            END;

            CREATE TABLE IF NOT EXISTS experiment_bearer_tokens (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                token_scope TEXT NOT NULL,
                intended_action TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS experiment_api_operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                object_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS experiment_cloud_resources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                resource_id TEXT NOT NULL,
                resource_name TEXT NOT NULL,
                classification TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                public_access INTEGER NOT NULL DEFAULT 0,
                version INTEGER NOT NULL DEFAULT 1,
                updated_at INTEGER NOT NULL,
                UNIQUE(user_id, resource_id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS totp_recovery_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                code_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                used_at INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE INDEX IF NOT EXISTS idx_totp_recovery_codes_user
                ON totp_recovery_codes(user_id);
            """
        )
        try:
            conn.execute("ALTER TABLE users ADD COLUMN mfa_enrolled INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE users ADD COLUMN otp_secret TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE users ADD COLUMN otp_email_label TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE users ADD COLUMN otp_rp_id TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE users ADD COLUMN reset_token_hash TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE users ADD COLUMN reset_token_expires INTEGER")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE users ADD COLUMN reset_token_purpose TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE users ADD COLUMN poia_zt_enabled INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE users ADD COLUMN signup_pending INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE beneficiaries ADD COLUMN version INTEGER NOT NULL DEFAULT 1")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE beneficiaries ADD COLUMN updated_at INTEGER")
        except sqlite3.OperationalError:
            pass
        conn.execute(
            "UPDATE beneficiaries SET updated_at = created_at WHERE updated_at IS NULL"
        )
        try:
            conn.execute("ALTER TABLE accounts ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute(
                "ALTER TABLE accounts ADD COLUMN daily_transfer_limit REAL NOT NULL DEFAULT 10000.0"
            )
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE accounts ADD COLUMN version INTEGER NOT NULL DEFAULT 1")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE accounts ADD COLUMN updated_at INTEGER")
        except sqlite3.OperationalError:
            pass
        conn.execute(
            "UPDATE accounts SET updated_at = created_at WHERE updated_at IS NULL"
        )
        try:
            conn.execute("ALTER TABLE poia_human_study_trials ADD COLUMN prompt_displayed_at REAL")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE poia_human_study_trials ADD COLUMN decision_time_ms REAL")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute(
                "ALTER TABLE poia_human_study_trials "
                "ADD COLUMN study_run_id TEXT NOT NULL DEFAULT 'legacy'"
            )
        except sqlite3.OperationalError:
            pass
        for column in (
            "study_mode TEXT NOT NULL DEFAULT 'instructed'",
            "participant_session_id TEXT",
            "step_index INTEGER",
            "scenario_key TEXT",
            "cohort TEXT",
            "proof_status TEXT",
        ):
            try:
                conn.execute(f"ALTER TABLE poia_human_study_trials ADD COLUMN {column}")
            except sqlite3.OperationalError:
                pass
        for column in (
            "post_session_response TEXT",
            "debrief_shown_at REAL",
            "cohort TEXT",
            "design_version TEXT NOT NULL DEFAULT 'legacy-unversioned'",
            "orientation_response TEXT",
            # Independent, minimization-randomized between-subjects factor for
            # the UX-comparison sub-study: which confirmation-screen layout
            # this participant sees (see app/human_study.py
            # _next_display_variant and docs/experiments/
            # spontaneous_semantic_inspection_protocol.md, "Dataset 2"). Not
            # coupled to design_version, which tracks incremental iteration
            # history over time rather than a controlled comparison.
            "display_variant TEXT NOT NULL DEFAULT 'redesigned'",
        ):
            try:
                conn.execute(f"ALTER TABLE poia_participant_sessions ADD COLUMN {column}")
            except sqlite3.OperationalError:
                pass
        try:
            conn.execute("ALTER TABLE poia_human_study_events ADD COLUMN proof_status TEXT")
        except sqlite3.OperationalError:
            pass

    ensure_admin()
