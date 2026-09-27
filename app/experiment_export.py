"""Restricted research export; never export authentication tables or database files."""

import csv
import hashlib
import io
import json
import time
import zipfile
from contextlib import closing
from datetime import datetime, timezone

from . import db, poia_metrics


TABLE_QUERIES = (
    ("poia_execution_journal", "SELECT * FROM poia_execution_journal ORDER BY rowid"),
    ("poia_remote_jobs", "SELECT * FROM poia_remote_jobs ORDER BY rowid"),
    ("poia_participant_sessions", "SELECT * FROM poia_participant_sessions ORDER BY rowid"),
    ("poia_human_study_trials", "SELECT * FROM poia_human_study_trials ORDER BY rowid"),
    ("poia_human_study_events", "SELECT * FROM poia_human_study_events ORDER BY rowid"),
    ("poia_original_requests", "SELECT * FROM poia_original_requests ORDER BY rowid"),
    ("poia_workflows", "SELECT * FROM poia_workflows ORDER BY rowid"),
    ("experiment_api_operations", "SELECT * FROM experiment_api_operations ORDER BY rowid"),
    ("experiment_cloud_resources", "SELECT * FROM experiment_cloud_resources ORDER BY rowid"),
)

QUESTIONNAIRE_FIELDS = (
    "purpose_guess", "noticed_unusual", "unusual_detail", "semantic_fields",
    "semantic_other", "matching_ease", "confusion", "frustration",
    "technical_difficulty", "decision_explanation", "real_world_use_likelihood",
    "improvement_suggestion", "age_band", "banking_frequency",
    "passkey_familiarity", "authenticator_familiarity", "technical_experience",
    "webauthn_review_ease", "zt_review_ease", "backend_preference",
    "preference_reason", "final_comment", "questionnaire_version",
)

SESSION_ANALYSIS_FIELDS = (
    "session_id", "participant_id", "study_run_id", "cohort", "current_step",
    "status", "created_at", "completed_at", "debrief_shown_at", "debriefed_at",
    "design_version", "orientation_response",
)


def spreadsheet_cell(value):
    # Preserve exact values in JSONL; CSV must not execute participant-supplied formulas.
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def csv_bytes(columns, rows):
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    writer.writerows({key: spreadsheet_cell(row.get(key)) for key in columns} for row in rows)
    return output.getvalue().encode("utf-8")


def questionnaire_rows(sessions):
    rows = []
    for session in sessions:
        raw = session.get("post_session_response")
        if not raw:
            continue
        try:
            response = json.loads(raw)
        except (TypeError, ValueError):
            response = {}
        row = {
            "session_id": session.get("session_id"),
            "participant_id": session.get("participant_id"),
            "study_run_id": session.get("study_run_id"),
            "cohort": session.get("cohort"),
            "completed_at": session.get("completed_at"),
            "design_version": session.get("design_version"),
        }
        for field in QUESTIONNAIRE_FIELDS:
            value = response.get(field)
            row[field] = "|".join(value) if isinstance(value, list) else value
        rows.append(row)
    return rows


def build_experiment_export():
    started = time.time()
    files = {}
    counts = {}
    table_rows = {}
    raw_database_records = []
    # One SQLite read transaction includes committed WAL data and holds a stable view.
    with closing(db.db_connect()) as conn:
        conn.execute("PRAGMA query_only = ON")
        conn.execute("BEGIN")
        for table, query in TABLE_QUERIES:
            cursor = conn.execute(query)
            columns = [item[0] for item in cursor.description]
            rows = [dict(row) for row in cursor]
            counts[table] = len(rows)
            table_rows[table] = (columns, rows)
            raw_database_records.extend({"table": table, "row": row} for row in rows)
        conn.rollback()

    session_rows = table_rows["poia_participant_sessions"][1]
    questionnaires = questionnaire_rows(session_rows)
    files["analysis/sessions.csv"] = csv_bytes(
        SESSION_ANALYSIS_FIELDS,
        [{key: row.get(key) for key in SESSION_ANALYSIS_FIELDS} for row in session_rows],
    )
    files["analysis/trials.csv"] = csv_bytes(*table_rows["poia_human_study_trials"])
    files["analysis/enforcement_events.csv"] = csv_bytes(*table_rows["poia_human_study_events"])
    questionnaire_columns = (
        "session_id", "participant_id", "study_run_id", "cohort", "completed_at",
        "design_version", *QUESTIONNAIRE_FIELDS,
    )
    files["analysis/questionnaire_responses.csv"] = csv_bytes(
        questionnaire_columns, questionnaires
    )
    counts["questionnaire_responses"] = len(questionnaires)
    files["raw/database_records.jsonl"] = "".join(
        json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n"
        for record in raw_database_records
    ).encode("utf-8")

    metrics = poia_metrics.METRICS_CSV
    telemetry_status = "not_present"
    if metrics.exists():
        # Reject a changing capture rather than silently emit a partially written event.
        for _ in range(3):
            before = metrics.stat()
            raw = metrics.read_bytes()
            after = metrics.stat()
            if (before.st_ino, before.st_size, before.st_mtime_ns) == (after.st_ino, after.st_size, after.st_mtime_ns):
                break
        else:
            raise RuntimeError("Telemetry is changing; please retry the export.")
        if raw and not raw.endswith(b"\n"):
            raise RuntimeError("Telemetry contains an unfinished record; please retry the export.")
        reader = csv.DictReader(io.StringIO(raw.decode("utf-8"), newline=""), strict=True)
        rows = list(reader)
        if not reader.fieldnames or any(None in row or None in row.values() for row in rows):
            raise RuntimeError("Telemetry has an incomplete schema or row; export stopped.")
        files["analysis/approval_telemetry.csv"] = csv_bytes(reader.fieldnames, rows)
        files["raw/approval_telemetry.jsonl"] = "".join(
            json.dumps(row, sort_keys=True) + "\n" for row in rows
        ).encode()
        counts["approval_telemetry"] = len(rows)
        telemetry_status = "included"

    manifest = {
        "format_version": 2,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "capture_started_unix": started,
        "capture_finished_unix": time.time(),
        "scope": "All retained live records from the listed research tables and approval telemetry, across all dates and study modes. No filtering or analysis exclusions applied.",
        "consistency": "Database tables share one read transaction. The telemetry file is captured separately; there is no atomic cross-store snapshot.",
        "telemetry_status": telemetry_status,
        "row_counts": counts,
        "privacy": "Restricted research data, not a public anonymized dataset. Contains account identifiers, original intent bodies, and questionnaire free text. Review and de-identify before sharing.",
        "excluded": ["users and authentication credentials", "session secrets and bearer tokens", "database backups", "repository-only benchmark datasets and proof artifacts", "general banking and authentication audit tables"],
        "interpretation": "A completed session is not necessarily a distinct participant. Separate versions, instructed/spontaneous modes, repeated accounts, prior exposure, and technical failures during analysis. Null values are missing evidence, not zero.",
        "organization": "analysis/ contains analysis-ready CSV files. raw/ contains exact consolidated records for reproducibility. manifest.json documents the capture.",
        "csv_encoding": "UTF-8; formula-like text cells are prefixed with an apostrophe. JSONL preserves the original database values. Multi-select questionnaire answers use a pipe separator in CSV.",
        "files": {name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)} for name, data in files.items()},
    }
    files["manifest.json"] = json.dumps(manifest, indent=2, sort_keys=True).encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return output.getvalue()
