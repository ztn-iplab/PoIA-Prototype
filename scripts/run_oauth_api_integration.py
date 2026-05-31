#!/usr/bin/env python3
"""OAuth/API integration experiment for PoIA."""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import statistics
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


TOKEN_KEY = b"oauth-token-signing-key"
POIA_KEY = b"oauth-poia-proof-key"


def canonical_json(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sign_token(claims: Dict[str, Any]) -> str:
    return hmac.new(TOKEN_KEY, canonical_json(claims), hashlib.sha256).hexdigest()


def valid_token(claims: Dict[str, Any], signature: str) -> bool:
    return hmac.compare_digest(sign_token(claims), signature)


def sign_intent(intent: Dict[str, Any]) -> str:
    return hmac.new(POIA_KEY, canonical_json(intent), hashlib.sha256).hexdigest()


def base_token() -> Dict[str, Any]:
    return {"sub": "user-1", "aud": "api.example", "scope": ["admin:write", "key:rotate"], "exp": 1_900_000_000}


def base_intent() -> Dict[str, Any]:
    return {
        "action": "rotate_key",
        "scope": {"key_id": "kms-key-77", "project": "prod-payments", "region": "ap-northeast-1"},
        "context": {"rp_id": "api.example", "user_id": "user-1", "oauth_audience": "api.example"},
        "constraints": {"nonce": "oauth-poia-nonce", "expires_at": 1_900_000_000},
    }


def mutate(intent: Dict[str, Any], path: Tuple[str, ...], value: Any) -> Dict[str, Any]:
    changed = deepcopy(intent)
    cursor = changed
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    return changed


def oauth_only(request: Dict[str, Any], token: Dict[str, Any], token_sig: str) -> tuple[bool, str, float]:
    start = time.perf_counter()
    if not valid_token(token, token_sig):
        return False, "invalid_token", (time.perf_counter() - start) * 1000
    if request["required_scope"] not in token["scope"]:
        return False, "insufficient_scope", (time.perf_counter() - start) * 1000
    return True, "oauth_scope_authorized", (time.perf_counter() - start) * 1000


def oauth_plus_poia(request: Dict[str, Any], token: Dict[str, Any], token_sig: str, approved_intent: Dict[str, Any], proof: str) -> tuple[bool, str, float]:
    start = time.perf_counter()
    ok, reason, _ = oauth_only(request, token, token_sig)
    if not ok:
        return False, reason, (time.perf_counter() - start) * 1000
    if not hmac.compare_digest(sign_intent(approved_intent), proof):
        return False, "invalid_poia_proof", (time.perf_counter() - start) * 1000
    if canonical_json(request["intent"]) != canonical_json(approved_intent):
        return False, "intent_mismatch", (time.perf_counter() - start) * 1000
    return True, "oauth_and_poia_authorized", (time.perf_counter() - start) * 1000


def scenarios() -> List[Dict[str, Any]]:
    intent = base_intent()
    return [
        {"name": "legitimate_api_call", "intent": intent, "expected_oauth": True, "expected_poia": True, "required_scope": "key:rotate"},
        {"name": "cross_action_token_misuse", "intent": mutate(intent, ("action",), "delete_key"), "expected_oauth": True, "expected_poia": False, "required_scope": "key:rotate"},
        {"name": "api_tampering_wrong_key", "intent": mutate(intent, ("scope", "key_id"), "kms-root"), "expected_oauth": True, "expected_poia": False, "required_scope": "key:rotate"},
        {"name": "api_tampering_wrong_project", "intent": mutate(intent, ("scope", "project"), "prod-identity"), "expected_oauth": True, "expected_poia": False, "required_scope": "key:rotate"},
    ]


def summarize(values: List[float]) -> Dict[str, float]:
    return {"median": statistics.median(values), "mean": statistics.mean(values), "max": max(values), "n": len(values)} if values else {"median": 0, "mean": 0, "max": 0, "n": 0}


def run(trials: int) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    token = base_token()
    token_sig = sign_token(token)
    approved_intent = base_intent()
    proof = sign_intent(approved_intent)
    rows: List[Dict[str, Any]] = []
    for trial in range(1, trials + 1):
        for scenario in scenarios():
            request = {"intent": scenario["intent"], "required_scope": scenario["required_scope"]}
            for mode in ("oauth_only", "oauth_plus_poia"):
                if mode == "oauth_only":
                    ok, reason, overhead = oauth_only(request, token, token_sig)
                    expected = scenario["expected_oauth"]
                else:
                    ok, reason, overhead = oauth_plus_poia(request, token, token_sig, approved_intent, proof)
                    expected = scenario["expected_poia"]
                rows.append(
                    {
                        "trial": trial,
                        "scenario": scenario["name"],
                        "mode": mode,
                        "accepted": ok,
                        "expected_accept": expected,
                        "correct": ok == expected,
                        "reason": reason,
                        "verification_overhead_ms": overhead,
                    }
                )
    summary = []
    for mode in ("oauth_only", "oauth_plus_poia"):
        for scenario in sorted({row["scenario"] for row in rows}):
            subset = [row for row in rows if row["mode"] == mode and row["scenario"] == scenario]
            attempts = len(subset)
            accepted = sum(1 for row in subset if row["accepted"])
            tampering_rejections = sum(1 for row in subset if not row["accepted"])
            summary.append(
                {
                    "mode": mode,
                    "scenario": scenario,
                    "attempts": attempts,
                    "accepted": accepted,
                    "cross_action_token_misuse_success_rate": round(accepted / attempts * 100.0, 3),
                    "api_tampering_rejection_rate": round(tampering_rejections / attempts * 100.0, 3),
                    "correct_decision_rate": round(sum(1 for row in subset if row["correct"]) / attempts * 100.0, 3),
                    "verification_overhead_ms": summarize([float(row["verification_overhead_ms"]) for row in subset]),
                    "reasons": sorted({row["reason"] for row in subset}),
                }
            )
    return rows, summary


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def write_md(path: Path, summary: List[Dict[str, Any]]) -> None:
    lines = [
        "# OAuth/API Integration with PoIA",
        "",
        "| Mode | Scenario | Accepted | Correct Decision Rate | Tampering Rejection Rate | Median Verification Overhead (ms) | Reasons |",
        "|---|---|---:|---:|---:|---:|---|",
    ]
    for item in summary:
        lines.append(
            f"| {item['mode']} | {item['scenario']} | {item['accepted']}/{item['attempts']} | "
            f"{item['correct_decision_rate']:.1f}% | {item['api_tampering_rejection_rate']:.1f}% | "
            f"{item['verification_overhead_ms']['median']:.4f} | {', '.join(item['reasons'])} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run OAuth/API + PoIA integration experiment.")
    parser.add_argument("--trials", type=int, default=60)
    parser.add_argument("--out-dir", default="experiments/oauth_api_integration")
    args = parser.parse_args()
    rows, summary = run(args.trials)
    out = Path(args.out_dir)
    write_json(out / "oauth_api_summary.json", {"experiment": "oauth_api_integration", "trials": args.trials, "summary": summary})
    write_csv(out / "oauth_api_trials.csv", rows)
    write_md(out / "oauth_api_table.md", summary)
    print(json.dumps({"experiment": "oauth_api_integration", "trials": args.trials, "summary": summary}, indent=2, sort_keys=True))
    print(f"\nArtifacts written to: {out}")


if __name__ == "__main__":
    main()
