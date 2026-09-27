#!/usr/bin/env python3
"""Aggregate preregistered PoIA participant and linked enforcement outcomes."""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import sqlite3
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


def wilson(successes: int, total: int, z: float = 1.959963984540054) -> list[float] | None:
    if total == 0:
        return None
    proportion = successes / total
    denominator = 1 + z * z / total
    center = (proportion + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(
        proportion * (1 - proportion) / total + z * z / (4 * total * total)
    ) / denominator
    return [max(0.0, center - margin), min(1.0, center + margin)]


def summarize(rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    selected = [row for row in rows if row.get("mutation_stage") != "post_signature"]
    completed = [row for row in selected if row["participant_decision"] in {"sign", "refuse"}]
    correct = [row for row in completed if row["participant_decision"] == row["expected_participant_decision"]]
    false_verifications = [
        row for row in completed
        if row["expected_participant_decision"] == "refuse" and row["participant_decision"] == "sign"
    ]
    mutation_trials = [row for row in completed if row["expected_participant_decision"] == "refuse"]
    false_rejections = [
        row for row in completed
        if row["expected_participant_decision"] == "sign" and row["participant_decision"] == "refuse"
    ]
    legitimate_trials = [row for row in completed if row["expected_participant_decision"] == "sign"]
    decision_times = [row["decision_time_ms"] / 1000.0 for row in completed if row["decision_time_ms"] is not None]
    return {
        "trials_created": len(selected),
        "trials_completed": len(completed),
        "correct": len(correct),
        "detection_accuracy": len(correct) / len(completed) if completed else None,
        "interpretation": "descriptive trial counts; repeated trials are not independent samples",
        "false_verifications": len(false_verifications),
        "false_verification_rate": len(false_verifications) / len(mutation_trials) if mutation_trials else None,
        "false_rejections": len(false_rejections),
        "false_rejection_rate": len(false_rejections) / len(legitimate_trials) if legitimate_trials else None,
        "median_decision_time_seconds": statistics.median(decision_times) if decision_times else None,
        "timed_trials": len(decision_times),
    }


VISIBLE_STAGES = {"pre_display", "session_repurpose"}


def participant_outcomes(trials: list[dict[str, Any]], sessions: list[dict[str, Any]]) -> dict[str, Any]:
    # Keep the first session per account, including incomplete first sessions:
    # restarting must not turn prior exposure into a first-exposure observation.
    first_sessions: dict[Any, dict[str, Any]] = {}
    for session in sorted(sessions, key=lambda row: (row["created_at"], row["session_id"])):
        if not session.get("is_first_account_session", True):
            continue
        identity = session.get("user_id", session["participant_id"])
        first_sessions.setdefault(identity, session)
    eligible = {
        session["session_id"] for session in first_sessions.values()
        if session["status"] == "complete" and session.get("completed_at") is not None
    }
    # Dataset 2 (legacy vs. redesigned display) is a between-subjects factor
    # of the *session*, not the trial: look it up per participant_session_id
    # so every trial in a spontaneous run inherits the one arm its session
    # was randomized into (see _next_display_variant in app/human_study.py).
    variant_by_session = {
        session["session_id"]: session.get("display_variant") for session in sessions
    }
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for trial in trials:
        if trial.get("study_mode") == "spontaneous" and trial.get("participant_session_id") in eligible:
            trial = dict(trial)
            trial["display_variant"] = variant_by_session.get(trial.get("participant_session_id"))
            grouped[trial["participant_id"]].append(trial)
    outcomes = []
    for participant, rows in sorted(grouped.items()):
        ordered = sorted(rows, key=lambda row: (row.get("step_index", 0), row["created_at"], row["trial_id"]))
        visible = [row for row in ordered if row["mutation_stage"] in VISIBLE_STAGES]
        first = visible[0] if visible else None
        # All trials in `ordered` share one session, hence one display_variant;
        # take it directly rather than re-deriving it from the grouped rows.
        variant = ordered[0]["display_variant"] if ordered else None
        outcomes.append({
            "participant_id": participant,
            "display_variant": variant,
            "first_visible_trial_id": first["trial_id"] if first else None,
            "first_visible_decision": first["participant_decision"] if first else None,
            "first_visible_backend": first["signing_backend"] if first else None,
            "overall": summarize(ordered),
            "by_backend": {backend: summarize([r for r in ordered if r["signing_backend"] == backend])
                           for backend in sorted({r["signing_backend"] for r in ordered})},
            "by_class": {label: summarize([r for r in ordered if r["mutation_type"] == label])
                         for label in sorted({r["mutation_type"] for r in ordered})},
        })
    observed = [row for row in outcomes if row["first_visible_decision"] in {"sign", "refuse"}]
    detected = sum(row["first_visible_decision"] == "refuse" for row in observed)
    display_variants_seen = sorted({row["display_variant"] for row in outcomes if row.get("display_variant")})

    def _primary_for(rows: list[dict[str, Any]]) -> dict[str, Any]:
        subset = [row for row in rows if row["first_visible_decision"] in {"sign", "refuse"}]
        hits = sum(row["first_visible_decision"] == "refuse" for row in subset)
        return {
            "participants": len(subset), "refusals": hits,
            "refusal_proportion": hits / len(subset) if subset else None,
            "wilson_95": wilson(hits, len(subset)),
        }

    return {
        "sampling_unit": "first session per account; one account per recruited person must be checked",
        "first_sessions": len(first_sessions),
        "completed_first_sessions": len(eligible),
        "incomplete_first_sessions": len(first_sessions) - len(eligible),
        "repeat_sessions_excluded": len(sessions) - len(first_sessions),
        "primary_first_visible_mismatch": {
            "participants": len(observed), "refusals": detected,
            "refusal_proportion": detected / len(observed) if observed else None,
            "wilson_95": wilson(detected, len(observed)),
            "missing_first_response": len(eligible) - len(observed),
        },
        # Dataset 2's primary comparison: does the redesigned confirmation
        # display change whether participants catch an unannounced mismatch
        # on the very first trial they see one, relative to the legacy
        # (pre-redesign layout, identical underlying signed-intent data)
        # arm? Same first-visible-trial logic as the line above, split by
        # display_variant instead of pooled across it.
        "primary_first_visible_mismatch_by_display_variant": {
            variant: _primary_for([row for row in outcomes if row.get("display_variant") == variant])
            for variant in display_variants_seen
        },
        "secondary_participant_means": participant_means(outcomes, "overall"),
        "secondary_by_backend": {key: participant_means(outcomes, "by_backend", key)
                                 for key in sorted({k for row in outcomes for k in row["by_backend"]})},
        "secondary_by_class": {key: participant_means(outcomes, "by_class", key)
                               for key in sorted({k for row in outcomes for k in row["by_class"]})},
        "secondary_by_display_variant": {
            variant: participant_means(
                [row for row in outcomes if row.get("display_variant") == variant], "overall"
            )
            for variant in display_variants_seen
        },
        "participant_outcomes": outcomes,
    }


def participant_means(outcomes: list[dict[str, Any]], group: str, key: str | None = None) -> dict[str, Any]:
    result = {}
    for metric in ("detection_accuracy", "false_verification_rate", "false_rejection_rate", "median_decision_time_seconds"):
        values = []
        for outcome in outcomes:
            record = outcome[group] if key is None else outcome[group].get(key, {})
            if record.get(metric) is not None:
                values.append(record[metric])
        interval = None
        if len(values) >= 2:
            rng = random.Random(20260903)
            means = sorted(statistics.fmean(rng.choices(values, k=len(values))) for _ in range(2000))
            interval = [means[49], means[1949]]
        result[metric] = {"participants": len(values), "mean": statistics.fmean(values) if values else None,
                          "participant_bootstrap_95": interval}
    return result


# Human-Computer Trust in Automation short scale (Jian, Bisantz & Drury,
# 2000, "Foundations for an Empirically Determined Scale of Trust in
# Automated Systems", International Journal of Cognitive Ergonomics 4(1)).
# The post-session questionnaire (app/templates/participant_workspace.html,
# validated against app/human_study.py's TRUST_SCALE_ITEMS) asks the 7
# positively-worded "trust" component items from that scale -- see the
# citation comment above TRUST_SCALE_ITEMS in app/human_study.py for the
# full item-by-item mapping and why this is the one validated-instrument
# measure in an otherwise descriptive questionnaire. None of these 7 items
# are reverse-worded in the original scale (Jian et al.'s reverse-worded
# items belong to the separate "distrust" component, which this
# questionnaire does not ask), so the composite below is the straight,
# unweighted mean of the 7 item scores -- the scoring method the original
# paper itself uses per factor. Scale: 1 = strongly disagree ... 7 =
# strongly agree. A session that answered "prefer not to answer" on any one
# of the 7 items is excluded from the composite entirely (no imputation),
# not scored with the remaining items.
TRUST_SCALE_ITEMS = (
    "trust_confident", "trust_secure", "trust_integrity", "trust_dependable",
    "trust_reliable", "trust_overall", "trust_familiar",
)
TRUST_SCALE_VALUE_SCORES = {
    "strongly_disagree": 1, "disagree": 2, "somewhat_disagree": 3, "neutral": 4,
    "somewhat_agree": 5, "agree": 6, "strongly_agree": 7,
}


def trust_composite(session: dict[str, Any]) -> float | None:
    """Participant-level composite trust score, or None if any of the 7
    TRUST_SCALE_ITEMS is missing or "prefer not to answer" for this session."""
    scores = []
    for item in TRUST_SCALE_ITEMS:
        score = TRUST_SCALE_VALUE_SCORES.get(session.get(item))
        if score is None:
            return None
        scores.append(score)
    return statistics.fmean(scores)


def trust_summary(sessions: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Overall and by-display_variant summary of the Jian et al. (2000)
    trust-component composite, with a participant-level bootstrap 95% CI on
    the mean (same resampling approach as participant_means above)."""

    def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
        scores = [score for score in (trust_composite(row) for row in rows) if score is not None]
        interval = None
        if len(scores) >= 2:
            rng = random.Random(20260908)
            means = sorted(statistics.fmean(rng.choices(scores, k=len(scores))) for _ in range(2000))
            interval = [means[49], means[1949]]
        return {
            "sessions": len(rows),
            "sessions_with_complete_trust_scale": len(scores),
            "mean": statistics.fmean(scores) if scores else None,
            "participant_bootstrap_95": interval,
            "interpretation": (
                "mean of the Jian et al. (2000) 7-item trust-component composite "
                "(1-7 scale, unweighted item mean per session); bootstrap CI resamples "
                "sessions, not trials"
            ),
        }

    rows = list(sessions)
    by_variant = {
        variant: _summary([row for row in rows if row.get("display_variant") == variant])
        for variant in sorted({row.get("display_variant") for row in rows if row.get("display_variant")})
    }
    return {"overall": _summary(rows), "by_display_variant": by_variant}


def enforcement_summary(trials: list[dict[str, Any]], events: list[dict[str, Any]]) -> dict[str, Any]:
    by_id = {trial["trial_id"]: trial for trial in trials}
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        trial = by_id[event["trial_id"]]
        if not event["event_type"].startswith("execution_") or trial["participant_decision"] != "sign":
            continue
        original, displayed, execution = (trial.get("original_sha256"), trial.get("displayed_sha256"), event.get("execution_sha256"))
        if not all((original, displayed, execution)):
            kind = "unclassified_missing_hashes"
        elif displayed != execution:
            kind = "core_signed_execution_mismatch"
        elif original != displayed:
            kind = "additional_original_task_mismatch"
        else:
            kind = "matching_semantics"
        groups[kind].append(event)
    signed_trial_ids = {trial["trial_id"] for trial in trials if trial["participant_decision"] == "sign"}
    event_trial_ids = {event["trial_id"] for event in events if event["event_type"].startswith("execution_")}
    result: dict[str, Any] = {
        "events": sum(map(len, groups.values())), "incorrect_events": 0,
        "signed_trials_without_execution_evidence": len(signed_trial_ids - event_trial_ids),
        "by_binding": {},
    }
    for kind, rows in groups.items():
        must_reject = kind in {"core_signed_execution_mismatch", "additional_original_task_mismatch"}
        incorrect = sum((must_reject and row["system_decision"] == "accept") or
                        (row["system_decision"] == "reject" and row.get("state_changed") == 1) for row in rows)
        result["incorrect_events"] += incorrect
        result["by_binding"][kind] = {
            "events": len(rows), "unique_trials": len({row["trial_id"] for row in rows}),
            "accepted": sum(row["system_decision"] == "accept" for row in rows),
            "rejected": sum(row["system_decision"] == "reject" for row in rows),
            "matching_control_rejections": sum(
                not must_reject and row["system_decision"] == "reject" for row in rows
            ),
            "incorrect_events": incorrect,
            "missing_state_evidence": sum(row.get("state_changed") is None for row in rows),
            "missing_decisions": sum(row["system_decision"] not in {"accept", "reject"} for row in rows),
            "rejection_reasons": dict(Counter(row.get("rejection_reason") or "unspecified" for row in rows
                                             if row["system_decision"] == "reject")),
        }
    result["evidence_issues"] = (
        result["signed_trials_without_execution_evidence"]
        + sum(row["missing_state_evidence"] + row["missing_decisions"]
              for row in result["by_binding"].values())
        + result["by_binding"].get("unclassified_missing_hashes", {}).get("events", 0)
    )
    return result


def write_rows(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0])
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--run-id", required=True, action="append", help="Repeat to combine collection days.")
    parser.add_argument("--participant-id")
    parser.add_argument("--exclude-participant-id", action="append", default=[])
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(args.db.resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    run_ids = list(dict.fromkeys(args.run_id))
    placeholders = ",".join("?" for _ in run_ids)
    trial_where = [f"study_run_id IN ({placeholders})"]
    trial_params: list[Any] = list(run_ids)
    if args.participant_id:
        trial_where.append("participant_id = ?")
        trial_params.append(args.participant_id)
    for excluded in args.exclude_participant_id:
        trial_where.append("participant_id != ?")
        trial_params.append(excluded)
    where_sql = " AND ".join(trial_where)
    trials = [dict(row) for row in connection.execute(
        f"SELECT * FROM poia_human_study_trials WHERE {where_sql} "
        "ORDER BY created_at, trial_id",
        trial_params,
    )]
    events = [dict(row) for row in connection.execute(
        "SELECT events.*, trials.participant_id, trials.mutation_stage, "
        "trials.mutation_type, trials.signing_backend "
        "FROM poia_human_study_events AS events "
        "JOIN poia_human_study_trials AS trials ON trials.trial_id = events.trial_id "
        f"WHERE {where_sql.replace('participant_id', 'trials.participant_id').replace('study_run_id', 'trials.study_run_id')} "
        "ORDER BY events.event_id",
        trial_params,
    )]
    has_sessions = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'poia_participant_sessions'"
    ).fetchone()
    sessions: list[dict[str, Any]] = []
    if has_sessions:
        session_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(poia_participant_sessions)")
        }
        design_version_sql = (
            "design_version" if "design_version" in session_columns
            else "'legacy-unversioned' AS design_version"
        )
        orientation_sql = (
            "orientation_response" if "orientation_response" in session_columns
            else "NULL AS orientation_response"
        )
        display_variant_sql = (
            "display_variant" if "display_variant" in session_columns
            # Matches the column's own SQL DEFAULT in app/db.py so an older
            # DB without this column reads the same as a fresh one would.
            else "'redesigned' AS display_variant"
        )
        session_where = [f"study_run_id IN ({placeholders})"]
        session_params: list[Any] = list(run_ids)
        if args.participant_id:
            session_where.append("participant_id = ?")
            session_params.append(args.participant_id)
        for excluded in args.exclude_participant_id:
            session_where.append("participant_id != ?")
            session_params.append(excluded)
        session_rows = connection.execute(
            "SELECT session_id, participant_id, user_id, study_run_id, cohort, current_step, status, created_at, "
            "completed_at, post_session_response, debrief_shown_at, debriefed_at, "
            f"{design_version_sql}, {orientation_sql}, {display_variant_sql}, "
            "session_id = (SELECT prior.session_id FROM poia_participant_sessions AS prior "
            "WHERE prior.user_id = current.user_id ORDER BY prior.created_at, prior.session_id LIMIT 1) "
            "AS is_first_account_session "
            "FROM poia_participant_sessions AS current WHERE " + " AND ".join(session_where) +
            " ORDER BY created_at, participant_id",
            session_params,
        ).fetchall()
        for row in session_rows:
            session = dict(row)
            try:
                response = json.loads(session.pop("post_session_response") or "{}")
            except (TypeError, ValueError):
                response = {}
            session.update(
                {
                    "purpose_guess": response.get("purpose_guess"),
                    "noticed_unusual": response.get("noticed_unusual"),
                    "unusual_detail": response.get("unusual_detail"),
                    "semantic_fields": "|".join(response.get("semantic_fields") or []),
                    "semantic_other": response.get("semantic_other"),
                    "matching_ease": response.get("matching_ease"),
                    "age_band": response.get("age_band"),
                    "banking_frequency": response.get("banking_frequency"),
                    "passkey_familiarity": response.get("passkey_familiarity"),
                    "authenticator_familiarity": response.get("authenticator_familiarity"),
                    "technical_experience": response.get("technical_experience"),
                    "webauthn_review_ease": response.get("webauthn_review_ease"),
                    "zt_review_ease": response.get("zt_review_ease"),
                    "backend_preference": response.get("backend_preference"),
                    **{item: response.get(item) for item in TRUST_SCALE_ITEMS},
                    "preference_reason": response.get("preference_reason"),
                    "final_comment": response.get("final_comment"),
                    "questionnaire_version": response.get("questionnaire_version"),
                    "confusion": response.get("confusion"),
                    "frustration": response.get("frustration"),
                    "technical_difficulty": response.get("technical_difficulty"),
                    "decision_explanation": response.get("decision_explanation"),
                    "real_world_use_likelihood": response.get("real_world_use_likelihood"),
                    "improvement_suggestion": response.get("improvement_suggestion"),
                }
            )
            sessions.append(session)
    connection.close()

    by_class: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_backend: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for trial in trials:
        by_class[str(trial["mutation_type"])].append(trial)
        by_backend[str(trial["signing_backend"])].append(trial)

    participant_analysis = participant_outcomes(trials, sessions)

    semantic_field_counts: Counter[str] = Counter()
    matching_ease_counts: Counter[str] = Counter()
    post_session_distributions = {
        field: Counter()
        for field in (
            "age_band", "banking_frequency", "passkey_familiarity",
            "authenticator_familiarity", "technical_experience",
            "webauthn_review_ease", "zt_review_ease", "backend_preference",
            "real_world_use_likelihood",
            *TRUST_SCALE_ITEMS,
        )
    }
    for session in sessions:
        semantic_field_counts.update(
            value for value in str(session.get("semantic_fields") or "").split("|") if value
        )
        if session.get("matching_ease"):
            matching_ease_counts[str(session["matching_ease"])] += 1
        for field, counts in post_session_distributions.items():
            if session.get(field):
                counts[str(session[field])] += 1

    summary = {
        "study_run_id": run_ids[0] if len(run_ids) == 1 else run_ids,
        "analysis_contract": "participant_analysis is inferential; overall/by_class/by_backend are descriptive only",
        "study_modes": dict(Counter(trial.get("study_mode", "instructed") for trial in trials)),
        "participant_filter": args.participant_id,
        "excluded_participant_ids": args.exclude_participant_id,
        "participants": participant_analysis["completed_first_sessions"],
        "participant_ids_observed": len({trial["participant_id"] for trial in trials}),
        "overall": summarize(trials),
        "by_presentation_class": {key: summarize(value) for key, value in sorted(by_class.items())},
        "by_signing_backend": {key: summarize(value) for key, value in sorted(by_backend.items())},
        "participant_analysis": participant_analysis,
        "enforcement": enforcement_summary(trials, events),
        "trust_instrument": trust_summary(sessions),
        "post_signature_decisions": dict(Counter(trial["participant_decision"] or "missing"
                                                 for trial in trials if trial["mutation_stage"] == "post_signature")),
        "incomplete_trials": sum(
            trial["participant_decision"] not in {"sign", "refuse"} for trial in trials
        ),
        "post_session": {
            "responses": sum(bool(session.get("purpose_guess")) for session in sessions),
            "semantic_field_counts": dict(sorted(semantic_field_counts.items())),
            "matching_ease_counts": dict(sorted(matching_ease_counts.items())),
            "distributions": {
                field: dict(sorted(counts.items()))
                for field, counts in post_session_distributions.items()
            },
        },
    }
    (args.out_dir / "human_study_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (args.out_dir / "human_study_by_class.csv").open("w", newline="", encoding="utf-8") as handle:
        fieldnames = [
            "presentation_class", "trials_created", "trials_completed", "correct",
            "detection_accuracy", "false_verifications", "false_verification_rate",
            "false_rejections", "false_rejection_rate", "median_decision_time_seconds",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for label, values in summary["by_presentation_class"].items():
            writer.writerow({"presentation_class": label, **{key: values.get(key) for key in fieldnames[1:]}})
    write_rows(args.out_dir / "human_study_trials.csv", trials)
    participant_rows = [
        {"participant_id": row["participant_id"], "first_visible_trial_id": row["first_visible_trial_id"],
         "first_visible_decision": row["first_visible_decision"], "first_visible_backend": row["first_visible_backend"],
         **row["overall"]}
        for row in participant_analysis["participant_outcomes"]
    ]
    write_rows(args.out_dir / "human_study_participant_outcomes.csv", participant_rows)
    write_rows(args.out_dir / "human_study_events.csv", events)
    write_rows(args.out_dir / "human_study_sessions.csv", [{k: v for k, v in row.items() if k != "user_id"} for row in sessions])
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if (summary["enforcement"]["incorrect_events"] == 0
                 and summary["enforcement"]["evidence_issues"] == 0) else 1


if __name__ == "__main__":
    raise SystemExit(main())
