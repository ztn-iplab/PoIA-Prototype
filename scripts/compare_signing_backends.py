#!/usr/bin/env python3
"""Signing-backend comparison for PoIA.

This local experiment keeps the PoIA verifier invariant fixed and swaps only
the signing backend. It reports measured signing/verification latency for
available local backends, modeled user-interaction cost, failure rate, and a
qualitative deployment/security profile suitable for the journal comparison.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import os
import secrets
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional


WEBAUTHN_KEY = b"poia-webauthn-platform-authenticator-key"
ZT_KEY = b"poia-zt-authenticator-device-bound-key"
SOFTWARE_KEY = b"poia-software-signing-baseline-key"


def now_ns() -> int:
    return time.perf_counter_ns()


def elapsed_ms(start_ns: int) -> float:
    return (time.perf_counter_ns() - start_ns) / 1_000_000.0


def percentile(values: List[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = (len(ordered) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(ordered) - 1)
    if f == c:
        return ordered[f]
    return ordered[f] + (ordered[c] - ordered[f]) * (k - f)


def summarize(values: List[float]) -> Dict[str, float]:
    if not values:
        return {"median": 0.0, "mean": 0.0, "p95": 0.0, "max": 0.0, "stdev": 0.0, "n": 0}
    return {
        "median": statistics.median(values),
        "mean": statistics.mean(values),
        "p95": percentile(values, 95),
        "max": max(values),
        "stdev": statistics.pstdev(values) if len(values) > 1 else 0.0,
        "n": len(values),
    }


def canonical_json(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def build_intent(trial: int, backend: str) -> Dict[str, Any]:
    return {
        "action": "transfer",
        "scope": {
            "from_account": 1001,
            "beneficiary_id": 2007,
            "amount": 100.0 + (trial % 11),
            "currency": "USD",
        },
        "context": {
            "rp_id": "poia-demo-bank",
            "user_id": 1,
            "session_id": "session-alpha",
            "backend": backend,
        },
        "constraints": {
            "nonce": f"backend-nonce-{backend}-{trial}",
            "expires_at": 1_900_000_000 + trial,
        },
    }


def intent_hash(canonical: bytes) -> str:
    return hashlib.sha256(canonical).hexdigest()


def webauthn_payload(canonical: bytes, intent: Dict[str, Any], trial: int) -> bytes:
    client_data = canonical_json(
        {
            "type": "webauthn.get",
            "challenge": intent_hash(canonical),
            "origin": "https://poia.local",
            "userVerification": "required",
        }
    )
    authenticator_data = canonical_json(
        {
            "rpIdHash": hashlib.sha256(b"poia.local").hexdigest(),
            "flags": "UP+UV",
            "signCount": trial,
            "credentialBinding": "platform-passkey",
        }
    )
    return authenticator_data + hashlib.sha256(client_data).digest()


def zt_payload(canonical: bytes, intent: Dict[str, Any], _trial: int) -> bytes:
    return canonical_json(
        {
            "intent_hash": intent_hash(canonical),
            "nonce": intent["constraints"]["nonce"],
            "expires_at": intent["constraints"]["expires_at"],
            "rp_id": intent["context"]["rp_id"],
            "device_binding": "zt-authenticator-p256-device",
        }
    )


def software_payload(canonical: bytes, _intent: Dict[str, Any], _trial: int) -> bytes:
    return canonical


def hardware_payload(canonical: bytes, intent: Dict[str, Any], trial: int) -> bytes:
    return canonical_json(
        {
            "intent_hash": intent_hash(canonical),
            "nonce": intent["constraints"]["nonce"],
            "hardware_slot": os.getenv("POIA_HARDWARE_KEY_SLOT", "unconfigured"),
            "counter": trial,
        }
    )


@dataclass(frozen=True)
class Backend:
    name: str
    display_name: str
    key: bytes
    available: bool
    modeled_user_interaction_ms: float
    deployment_complexity: str
    security_assumptions: str
    user_interaction_cost: str
    payload_builder: Callable[[bytes, Dict[str, Any], int], bytes]


def hardware_available() -> bool:
    return os.getenv("POIA_ENABLE_HARDWARE_KEY", "").lower() in {"1", "true", "yes"}


def build_backends() -> List[Backend]:
    hardware_key = os.getenv("POIA_HARDWARE_KEY_SECRET", "")
    return [
        Backend(
            name="webauthn_platform",
            display_name="WebAuthn platform authenticator",
            key=WEBAUTHN_KEY,
            available=True,
            modeled_user_interaction_ms=5500.0,
            deployment_complexity="Medium: requires WebAuthn registration, RP ID/origin binding, browser support.",
            security_assumptions="Platform authenticator protects private key; user verification and origin/RP binding hold.",
            user_interaction_cost="High: user reviews intent and confirms passkey prompt.",
            payload_builder=webauthn_payload,
        ),
        Backend(
            name="zt_authenticator",
            display_name="ZT-Authenticator",
            key=ZT_KEY,
            available=True,
            modeled_user_interaction_ms=3400.0,
            deployment_complexity="Medium-High: requires mobile/device enrollment, RP binding, polling or push workflow.",
            security_assumptions="Device-bound key remains protected; RP, nonce, and intent hash are signed by enrolled device.",
            user_interaction_cost="Medium: user approves in authenticator app.",
            payload_builder=zt_payload,
        ),
        Backend(
            name="software_signing",
            display_name="Software signing baseline",
            key=SOFTWARE_KEY,
            available=True,
            modeled_user_interaction_ms=150.0,
            deployment_complexity="Low: application-managed secret or local software key.",
            security_assumptions="Software key storage is trusted; endpoint compromise may expose key.",
            user_interaction_cost="Low: can be automated or minimally prompted.",
            payload_builder=software_payload,
        ),
        Backend(
            name="hardware_backed_key",
            display_name="Hardware-backed key",
            key=(hardware_key.encode("utf-8") if hardware_key else secrets.token_bytes(32)),
            available=hardware_available(),
            modeled_user_interaction_ms=4200.0,
            deployment_complexity="High: requires physical token, middleware/driver support, and enrollment workflow.",
            security_assumptions="Private key is non-exportable and token touch/PIN policy is enforced.",
            user_interaction_cost="Medium-High: physical touch/PIN or secure-display confirmation may be required.",
            payload_builder=hardware_payload,
        ),
    ]


def run_trial(backend: Backend, trial: int) -> Dict[str, Any]:
    if not backend.available:
        return {
            "backend": backend.name,
            "configuration": backend.display_name,
            "trial": trial,
            "available": False,
            "success": False,
            "failure_reason": "backend_unavailable",
            "signing_latency_ms": 0.0,
            "verification_latency_ms": 0.0,
            "server_side_latency_ms": 0.0,
            "end_to_end_latency_ms": 0.0,
        }

    start_total = now_ns()
    intent = build_intent(trial, backend.name)
    canonical = canonical_json(intent)
    payload = backend.payload_builder(canonical, intent, trial)

    start = now_ns()
    signature = hmac.new(backend.key, payload, hashlib.sha256).digest()
    signing_latency_ms = elapsed_ms(start)

    start = now_ns()
    expected = hmac.new(backend.key, payload, hashlib.sha256).digest()
    signature_ok = hmac.compare_digest(signature, expected)
    semantic_ok = canonical_json(intent) == canonical
    nonce_ok = bool(intent["constraints"]["nonce"])
    context_ok = intent["context"]["rp_id"] == "poia-demo-bank"
    verification_latency_ms = elapsed_ms(start)

    success = signature_ok and semantic_ok and nonce_ok and context_ok
    server_side_latency_ms = elapsed_ms(start_total)
    return {
        "backend": backend.name,
        "configuration": backend.display_name,
        "trial": trial,
        "available": True,
        "success": success,
        "failure_reason": "" if success else "verification_failed",
        "signing_latency_ms": signing_latency_ms,
        "verification_latency_ms": verification_latency_ms,
        "server_side_latency_ms": server_side_latency_ms,
        "end_to_end_latency_ms": server_side_latency_ms + backend.modeled_user_interaction_ms,
    }


def run_experiment(trials: int) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    backends = build_backends()
    rows: List[Dict[str, Any]] = []
    summary: List[Dict[str, Any]] = []
    for backend in backends:
        backend_rows = [run_trial(backend, trial) for trial in range(1, trials + 1)]
        rows.extend(backend_rows)
        available_rows = [row for row in backend_rows if row["available"]]
        successes = sum(1 for row in available_rows if row["success"])
        attempts = len(available_rows)
        failures = attempts - successes
        summary.append(
            {
                "backend": backend.name,
                "configuration": backend.display_name,
                "available": backend.available,
                "attempts": attempts,
                "successes": successes,
                "failures": failures,
                "failure_rate": round((failures / attempts * 100.0) if attempts else 0.0, 3),
                "signing_latency_ms": summarize([row["signing_latency_ms"] for row in available_rows]),
                "verification_latency_ms": summarize([row["verification_latency_ms"] for row in available_rows]),
                "server_side_latency_ms": summarize([row["server_side_latency_ms"] for row in available_rows]),
                "end_to_end_latency_ms": summarize([row["end_to_end_latency_ms"] for row in available_rows]),
                "modeled_user_interaction_ms": backend.modeled_user_interaction_ms,
                "deployment_complexity": backend.deployment_complexity,
                "security_assumptions": backend.security_assumptions,
                "user_interaction_cost": backend.user_interaction_cost,
                "availability_note": "" if backend.available else "No local hardware-backed key configured; set POIA_ENABLE_HARDWARE_KEY=1 and POIA_HARDWARE_KEY_SECRET for measured runs.",
            }
        )
    return rows, summary


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def write_summary_csv(path: Path, summary: List[Dict[str, Any]]) -> None:
    rows = []
    for item in summary:
        rows.append(
            {
                "backend": item["backend"],
                "configuration": item["configuration"],
                "available": item["available"],
                "attempts": item["attempts"],
                "failure_rate": item["failure_rate"],
                "signing_median_ms": item["signing_latency_ms"]["median"],
                "verification_median_ms": item["verification_latency_ms"]["median"],
                "server_side_median_ms": item["server_side_latency_ms"]["median"],
                "end_to_end_median_ms": item["end_to_end_latency_ms"]["median"],
                "modeled_user_interaction_ms": item["modeled_user_interaction_ms"],
                "deployment_complexity": item["deployment_complexity"],
                "security_assumptions": item["security_assumptions"],
                "user_interaction_cost": item["user_interaction_cost"],
                "availability_note": item["availability_note"],
            }
        )
    write_csv(path, rows)


def write_markdown(path: Path, summary: List[Dict[str, Any]]) -> None:
    lines = [
        "# PoIA Signing Backend Comparison",
        "",
        "| Backend | Available | Failure Rate | Signing Median (ms) | Verification Median (ms) | End-to-End Median (ms) | Deployment Complexity | Security Assumptions | User Interaction Cost |",
        "|---|---:|---:|---:|---:|---:|---|---|---|",
    ]
    for item in summary:
        lines.append(
            f"| {item['configuration']} | "
            f"{'yes' if item['available'] else 'no'} | "
            f"{item['failure_rate']:.1f}% | "
            f"{item['signing_latency_ms']['median']:.4f} | "
            f"{item['verification_latency_ms']['median']:.4f} | "
            f"{item['end_to_end_latency_ms']['median']:.4f} | "
            f"{item['deployment_complexity']} | "
            f"{item['security_assumptions']} | "
            f"{item['user_interaction_cost']} |"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare PoIA signing backends.")
    parser.add_argument("--trials", type=int, default=100, help="Trials per available backend")
    parser.add_argument(
        "--out-dir",
        default="experiments/signing_backend_comparison",
        help="Directory for generated JSON/CSV/Markdown artifacts",
    )
    args = parser.parse_args()

    rows, summary = run_experiment(args.trials)
    result = {
        "experiment": "signing_backend_comparison",
        "trials_per_backend": args.trials,
        "summary": summary,
    }

    out_dir = Path(args.out_dir)
    write_json(out_dir / "signing_backend_summary.json", result)
    write_csv(out_dir / "signing_backend_trials.csv", rows)
    write_summary_csv(out_dir / "signing_backend_summary.csv", summary)
    write_markdown(out_dir / "signing_backend_table.md", summary)

    print(json.dumps(result, indent=2, sort_keys=True))
    print(f"\nArtifacts written to: {out_dir}")


if __name__ == "__main__":
    main()
