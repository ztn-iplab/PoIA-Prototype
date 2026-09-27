#!/usr/bin/env python3
"""Synthetic prompt-contract checks, not browser/mobile rendering evidence."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import subprocess
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
ZT_ROOT = ROOT.parent / "ZT-Authenticator"
BACKENDS = ("webauthn", "zt_authenticator")
CASES = (
    "action_substitution",
    "target_substitution",
    "value_substitution",
    "principal_substitution",
    "rp_substitution",
    "workflow_substitution",
)


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def base_intent(domain: str) -> dict[str, Any]:
    definitions = {
        "banking": ("transfer", {"from_account": "account-17", "to_account": "beneficiary-23", "amount": 250, "currency": "USD"}),
        "enterprise": ("grant_role", {"target_user": "employee-29", "role": "reader", "tenant": "tenant-7", "duration_hours": 4}),
        "healthcare": ("export_record", {"patient_id": "patient-37", "record_type": "lab_results", "recipient": "clinic-11", "purpose": "referral"}),
        "cloud_api": ("rotate_key", {"key_id": "kms-key-41", "project": "project-13", "region": "ap-northeast-1"}),
    }
    action, scope = definitions[domain]
    return {
        "action": action,
        "scope": scope,
        "context": {"rp_id": f"poia-{domain}", "user_id": "principal-31", "workflow_id": f"workflow-{domain}"},
        "constraints": {"nonce": f"nonce-{domain}", "expires_in_seconds": 60},
    }


def changed(intent: dict[str, Any], path: tuple[str, ...], value: Any) -> dict[str, Any]:
    result = deepcopy(intent)
    cursor = result
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    return result


def mutation(domain: str, intent: dict[str, Any], case: str) -> tuple[dict[str, Any], tuple[str, ...]]:
    targets = {"banking": "to_account", "enterprise": "target_user", "healthcare": "patient_id", "cloud_api": "key_id"}
    values = {"banking": ("amount", 950), "enterprise": ("role", "administrator"), "healthcare": ("purpose", "marketing"), "cloud_api": ("project", "root-identity")}
    if case == "action_substitution":
        path, value = ("action",), "delete_resource"
    elif case == "target_substitution":
        path, value = ("scope", targets[domain]), "target-substituted"
    elif case == "value_substitution":
        key, value = values[domain]
        path = ("scope", key)
    elif case == "principal_substitution":
        path, value = ("context", "user_id"), "principal-substituted"
    elif case == "rp_substitution":
        path, value = ("context", "rp_id"), "poia-wrong-rp"
    else:
        path, value = ("context", "workflow_id"), "workflow-substituted"
    return changed(intent, path, value), path


def semantic_fields(intent: dict[str, Any]) -> list[tuple[str, ...]]:
    return (
        [("action",)]
        + [("scope", key) for key in intent["scope"]]
        + [("context", key) for key in ("user_id", "rp_id", "workflow_id")]
        + [("constraints", "expires_in_seconds")]
    )


def value_at(intent: dict[str, Any], path: tuple[str, ...]) -> Any:
    value: Any = intent
    for key in path:
        value = value[key]
    return value


def render(intent: dict[str, Any], backend: str) -> tuple[str, set[tuple[str, ...]]]:
    lines = [f"Action: {intent['action']}"]
    visible = {("action",)}
    for key, value in intent["scope"].items():
        lines.append(f"{key}: {value}")
        visible.add(("scope", key))
    context = intent["context"]
    for key, value in context.items():
        lines.append(f"{key}: {value}")
        visible.add(("context", key))
    lines.append(f"Expires in: {intent['constraints']['expires_in_seconds']}s")
    visible.add(("constraints", "expires_in_seconds"))
    return "\n".join(lines), visible


def analyze() -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    fields = []
    scenarios = []
    for domain in ("banking", "enterprise", "healthcare", "cloud_api"):
        approved = base_intent(domain)
        for backend in BACKENDS:
            prompt, visible = render(approved, backend)
            for path in semantic_fields(approved):
                fields.append({"backend": backend, "domain": domain, "field": ".".join(path), "visible": int(path in visible)})
            for case in CASES:
                requested, path = mutation(domain, approved, case)
                changed_prompt, changed_visible = render(requested, backend)
                changed_value = str(value_at(requested, path))
                scenarios.append(
                    {
                        "backend": backend,
                        "domain": domain,
                        "case": case,
                        "changed_field": ".".join(path),
                        "changed_field_visible": int(path in visible and path in changed_visible),
                        "changed_value_visible": int(changed_value in changed_prompt),
                        "rendering_differs": int(prompt != changed_prompt),
                        "mutation_detectable_from_content": int(path in visible and changed_value in changed_prompt and prompt != changed_prompt),
                        "explicit_action": int(("action",) in visible),
                        "explicit_rp": int(("context", "rp_id") in visible),
                        "explicit_expiry": int(("constraints", "expires_in_seconds") in visible),
                        "vague_only_prompt": int(prompt.strip().lower() in {"approve", "continue", "authorize"}),
                    }
                )
    summaries = []
    for backend in BACKENDS:
        backend_fields = [row for row in fields if row["backend"] == backend]
        backend_scenarios = [row for row in scenarios if row["backend"] == backend]
        summaries.append(
            {
                "evidence_kind": "synthetic_prompt_contract_not_ui_validation",
                "backend": backend,
                "visible_fields": sum(row["visible"] for row in backend_fields),
                "semantic_fields": len(backend_fields),
                "field_coverage_percent": 100 * sum(row["visible"] for row in backend_fields) / len(backend_fields),
                "detectable_mutations": sum(row["mutation_detectable_from_content"] for row in backend_scenarios),
                "mutations": len(backend_scenarios),
                "mutation_visibility_percent": 100 * sum(row["mutation_detectable_from_content"] for row in backend_scenarios) / len(backend_scenarios),
                "vague_only_prompts": sum(row["vague_only_prompt"] for row in backend_scenarios),
                "semantic_review_locus": "relying-party browser modal" if backend == "webauthn" else "dedicated authenticator app dialog",
                "cryptographic_action_locus": "platform WebAuthn ceremony" if backend == "webauthn" else "dedicated authenticator app dialog",
                "full_intent_at_application_signing_surface": backend == "zt_authenticator",
                "browser_intent_modal_shown": backend == "webauthn",
            }
        )
    return fields, scenarios, summaries


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    materialized = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=list(materialized[0]), lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(materialized)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--out-dir", default="experiments/usability_structured")
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    dirty = bool(git(ROOT, "status", "--porcelain"))
    if dirty and not args.allow_dirty:
        raise SystemExit("structured prompt analysis requires a clean PoIA tree")
    out = ROOT / args.out_dir
    paths = {name: out / f"{args.run_id}-{suffix}" for name, suffix in {"manifest": "manifest.json", "fields": "field-coverage.csv", "scenarios": "scenarios.csv", "summary": "summary.json", "table": "table.md", "checksums": "checksums.sha256"}.items()}
    if any(path.exists() for path in paths.values()):
        raise SystemExit(f"run ID already exists: {args.run_id}")
    web_source = ROOT / "app" / "templates" / "base.html"
    zt_source = ZT_ROOT / "mobile" / "lib" / "main.dart"
    web_text = web_source.read_text()
    zt_text = zt_source.read_text()
    if "appendIntentSection(container, 'Authorization context'" not in web_text or "poia_zt_enabled'] %} poia-hidden" not in web_text or "classList.remove('poia-hidden')" not in web_text or "visibleContext.map" not in zt_text or "Sign intent" not in zt_text:
        raise RuntimeError("production display contract markers not found")
    fields, scenarios, summaries = analyze()
    summary = {"run_id": args.run_id, "human_participants": 0, "human_outcomes_measured": False, "backends": summaries}
    write_csv(paths["fields"], fields)
    write_csv(paths["scenarios"], scenarios)
    write_json(paths["summary"], summary)
    lines = [f"# Structured Prompt Analysis: `{args.run_id}`", "", "| Backend | Visible fields | Field coverage | Detectable mutations | Mutation visibility | Browser intent modal | Semantic review locus | Cryptographic action locus | Full intent at application signing surface |", "|---|---:|---:|---:|---:|---:|---|---|---:|"]
    for item in summaries:
        lines.append(f"| {item['backend']} | {item['visible_fields']}/{item['semantic_fields']} | {item['field_coverage_percent']:.1f}% | {item['detectable_mutations']}/{item['mutations']} | {item['mutation_visibility_percent']:.1f}% | {'shown' if item['browser_intent_modal_shown'] else 'hidden'} | {item['semantic_review_locus']} | {item['cryptographic_action_locus']} | {'yes' if item['full_intent_at_application_signing_surface'] else 'no'} |")
    paths["table"].write_text("\n".join(lines) + "\n", encoding="utf-8")
    manifest = {"run_id": args.run_id, "repository_commit": git(ROOT, "rev-parse", "HEAD"), "repository_dirty": dirty, "tree_clean": not dirty, "zt_repository_commit": git(ZT_ROOT, "rev-parse", "HEAD"), "python_version": platform.python_version(), "runner_sha256": sha256_file(Path(__file__)), "web_display_sha256": sha256_file(web_source), "zt_display_sha256": sha256_file(zt_source), "preregistration_sha256": sha256_file(ROOT / "docs" / "experiments" / "usability_structured_preregistration.md"), "amendment_sha256": sha256_file(ROOT / "docs" / "experiments" / "usability_structured_amendment.md"), "human_participants": 0, "comparative_backend_performance_measured": False}
    write_json(paths["manifest"], manifest)
    artifacts = (Path(__file__), paths["manifest"], paths["fields"], paths["scenarios"], paths["summary"], paths["table"])
    paths["checksums"].write_text("\n".join(f"{sha256_file(path)}  {path.relative_to(ROOT)}" for path in artifacts) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
