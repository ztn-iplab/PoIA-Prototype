#!/usr/bin/env python3
"""Local PoIA performance and scalability experiment.

The runner measures decomposed costs for baseline session authorization and
two PoIA signing backends. It is dependency-free and deterministic enough for
paper artifact regeneration. WebAuthn and ZT-Authenticator user interaction
delay is modeled separately from server-side cryptographic work so throughput
numbers reflect verifier scalability rather than human review time.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List


BASELINE_KEY = b"poia-baseline-session-key"
WEBAUTHN_KEY = b"poia-webauthn-like-platform-key"
ZT_KEY = b"poia-zt-authenticator-like-device-key"


def now_ns() -> int:
    return time.perf_counter_ns()


def elapsed_ms(start_ns: int) -> float:
    return (time.perf_counter_ns() - start_ns) / 1_000_000.0


def canonical_json(data: Dict[str, Any]) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


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


def intent_hash(canonical: bytes) -> str:
    return hashlib.sha256(canonical).hexdigest()


def build_intent(user_id: int, request_id: int, backend: str) -> Dict[str, Any]:
    return {
        "action": "transfer",
        "scope": {
            "from_account": user_id * 1000 + 1,
            "beneficiary_id": user_id * 1000 + 7,
            "amount": 100.0 + (request_id % 17),
            "currency": "USD",
        },
        "context": {
            "rp_id": "poia-demo-bank",
            "user_id": user_id,
            "session_id": f"session-{user_id}",
            "tenant": "retail",
            "backend": backend,
        },
        "constraints": {
            "nonce": f"nonce-{backend}-{user_id}-{request_id}",
            "expires_at": 1_900_000_000 + request_id,
        },
    }


def baseline_authorize(user_id: int, request_id: int) -> Dict[str, float]:
    start_total = now_ns()

    start = now_ns()
    session = {"user_id": user_id, "session_id": f"session-{user_id}", "request_id": request_id}
    intent_construction_ms = elapsed_ms(start)

    start = now_ns()
    payload = canonical_json(session)
    canonicalization_ms = elapsed_ms(start)

    signature_generation_ms = 0.0

    start = now_ns()
    token = hmac.new(BASELINE_KEY, payload, hashlib.sha256).hexdigest()
    expected = hmac.new(BASELINE_KEY, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(token, expected):
        raise RuntimeError("baseline session check failed")
    verification_ms = elapsed_ms(start)

    total_ms = elapsed_ms(start_total)
    return {
        "intent_construction_ms": intent_construction_ms,
        "canonicalization_ms": canonicalization_ms,
        "signature_generation_ms": signature_generation_ms,
        "verification_ms": verification_ms,
        "server_side_latency_ms": total_ms,
        "end_to_end_latency_ms": total_ms,
    }


def webauthn_like_signing_payload(canonical: bytes, user_id: int, request_id: int) -> bytes:
    client_data = canonical_json(
        {
            "type": "webauthn.get",
            "challenge": hashlib.sha256(canonical).hexdigest(),
            "origin": "https://poia.local",
            "crossOrigin": False,
        }
    )
    authenticator_data = canonical_json(
        {
            "rpIdHash": hashlib.sha256(b"poia.local").hexdigest(),
            "flags": "UP+UV",
            "signCount": request_id,
            "user": user_id,
        }
    )
    return authenticator_data + hashlib.sha256(client_data).digest()


def zt_like_signing_payload(canonical: bytes, intent: Dict[str, Any]) -> bytes:
    payload = {
        "intent_hash": intent_hash(canonical),
        "nonce": intent["constraints"]["nonce"],
        "expires_at": intent["constraints"]["expires_at"],
        "rp_id": intent["context"]["rp_id"],
        "device_binding": "zt-authenticator-device",
    }
    return canonical_json(payload)


@dataclass(frozen=True)
class BackendSpec:
    name: str
    display_name: str
    key: bytes
    modeled_user_interaction_ms: float
    payload_builder: Callable[[bytes, Dict[str, Any], int, int], bytes]


def build_webauthn_payload(canonical: bytes, intent: Dict[str, Any], user_id: int, request_id: int) -> bytes:
    return webauthn_like_signing_payload(canonical, user_id, request_id)


def build_zt_payload(canonical: bytes, intent: Dict[str, Any], _user_id: int, _request_id: int) -> bytes:
    return zt_like_signing_payload(canonical, intent)


BACKENDS = {
    "baseline": BackendSpec(
        name="baseline",
        display_name="Baseline session authorization",
        key=BASELINE_KEY,
        modeled_user_interaction_ms=0.0,
        payload_builder=lambda canonical, intent, user_id, request_id: canonical,
    ),
    "poia_webauthn": BackendSpec(
        name="poia_webauthn",
        display_name="PoIA with WebAuthn",
        key=WEBAUTHN_KEY,
        modeled_user_interaction_ms=5500.0,
        payload_builder=build_webauthn_payload,
    ),
    "poia_zt_authenticator": BackendSpec(
        name="poia_zt_authenticator",
        display_name="PoIA with ZT-Authenticator",
        key=ZT_KEY,
        modeled_user_interaction_ms=3400.0,
        payload_builder=build_zt_payload,
    ),
}


def poia_authorize(user_id: int, request_id: int, spec: BackendSpec) -> Dict[str, float]:
    start_total = now_ns()

    start = now_ns()
    intent = build_intent(user_id, request_id, spec.name)
    intent_construction_ms = elapsed_ms(start)

    start = now_ns()
    canonical = canonical_json(intent)
    canonicalization_ms = elapsed_ms(start)

    start = now_ns()
    signing_payload = spec.payload_builder(canonical, intent, user_id, request_id)
    signature = hmac.new(spec.key, signing_payload, hashlib.sha256).digest()
    signature_generation_ms = elapsed_ms(start)

    start = now_ns()
    expected = hmac.new(spec.key, signing_payload, hashlib.sha256).digest()
    same_intent = canonical_json(intent) == canonical
    nonce_fresh = bool(intent["constraints"]["nonce"])
    context_ok = intent["context"]["rp_id"] == "poia-demo-bank"
    if not (hmac.compare_digest(signature, expected) and same_intent and nonce_fresh and context_ok):
        raise RuntimeError(f"{spec.name} proof verification failed")
    verification_ms = elapsed_ms(start)

    server_side_latency_ms = elapsed_ms(start_total)
    return {
        "intent_construction_ms": intent_construction_ms,
        "canonicalization_ms": canonicalization_ms,
        "signature_generation_ms": signature_generation_ms,
        "verification_ms": verification_ms,
        "server_side_latency_ms": server_side_latency_ms,
        "end_to_end_latency_ms": server_side_latency_ms + spec.modeled_user_interaction_ms,
    }


def run_one(mode: str, user_id: int, request_id: int) -> Dict[str, float]:
    if mode == "baseline":
        return baseline_authorize(user_id, request_id)
    return poia_authorize(user_id, request_id, BACKENDS[mode])


def run_mode_load(mode: str, users: int, ops_per_user: int) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    total_ops = users * ops_per_user
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=users) as executor:
        futures = []
        for user_id in range(1, users + 1):
            for op in range(1, ops_per_user + 1):
                request_id = ((user_id - 1) * ops_per_user) + op
                futures.append(executor.submit(run_one, mode, user_id, request_id))
        for future in as_completed(futures):
            rows.append(future.result())
    wall_seconds = time.perf_counter() - started
    throughput = total_ops / wall_seconds if wall_seconds > 0 else 0.0

    dimensions = [
        "intent_construction_ms",
        "canonicalization_ms",
        "signature_generation_ms",
        "verification_ms",
        "server_side_latency_ms",
        "end_to_end_latency_ms",
    ]
    aggregate = {
        "mode": mode,
        "display_name": BACKENDS[mode].display_name,
        "users": users,
        "operations": total_ops,
        "ops_per_user": ops_per_user,
        "wall_clock_seconds": wall_seconds,
        "server_side_throughput_ops_per_second": throughput,
        "modeled_user_interaction_ms": BACKENDS[mode].modeled_user_interaction_ms,
        "metrics": {dimension: summarize([row[dimension] for row in rows]) for dimension in dimensions},
    }
    return rows, aggregate


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


def write_summary_csv(path: Path, aggregates: List[Dict[str, Any]]) -> None:
    rows = []
    for item in aggregates:
        metrics = item["metrics"]
        rows.append(
            {
                "mode": item["mode"],
                "configuration": item["display_name"],
                "users": item["users"],
                "operations": item["operations"],
                "server_side_throughput_ops_per_second": item["server_side_throughput_ops_per_second"],
                "intent_construction_median_ms": metrics["intent_construction_ms"]["median"],
                "canonicalization_median_ms": metrics["canonicalization_ms"]["median"],
                "signature_generation_median_ms": metrics["signature_generation_ms"]["median"],
                "verification_median_ms": metrics["verification_ms"]["median"],
                "server_side_latency_median_ms": metrics["server_side_latency_ms"]["median"],
                "end_to_end_latency_median_ms": metrics["end_to_end_latency_ms"]["median"],
                "end_to_end_latency_p95_ms": metrics["end_to_end_latency_ms"]["p95"],
                "modeled_user_interaction_ms": item["modeled_user_interaction_ms"],
            }
        )
    write_csv(path, rows)


def write_markdown(path: Path, aggregates: List[Dict[str, Any]]) -> None:
    lines = [
        "# PoIA Performance and Scalability",
        "",
        "Server-side throughput excludes modeled human approval delay. End-to-end latency includes the modeled delay.",
        "",
        "| Configuration | Users | Throughput (ops/s) | Intent Construct Median (ms) | Canonicalize Median (ms) | Sign Median (ms) | Verify Median (ms) | Server Median (ms) | End-to-End Median (ms) | End-to-End P95 (ms) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in aggregates:
        metrics = item["metrics"]
        lines.append(
            f"| {item['display_name']} | {item['users']} | "
            f"{item['server_side_throughput_ops_per_second']:.1f} | "
            f"{metrics['intent_construction_ms']['median']:.4f} | "
            f"{metrics['canonicalization_ms']['median']:.4f} | "
            f"{metrics['signature_generation_ms']['median']:.4f} | "
            f"{metrics['verification_ms']['median']:.4f} | "
            f"{metrics['server_side_latency_ms']['median']:.4f} | "
            f"{metrics['end_to_end_latency_ms']['median']:.4f} | "
            f"{metrics['end_to_end_latency_ms']['p95']:.4f} |"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run local PoIA performance/scalability experiment.")
    parser.add_argument("--loads", default="1,10,50,100", help="Comma-separated concurrent user counts")
    parser.add_argument("--ops-per-user", type=int, default=20, help="Operations per user per configuration")
    parser.add_argument(
        "--out-dir",
        default="experiments/performance_scalability",
        help="Directory for generated JSON/CSV/Markdown artifacts",
    )
    args = parser.parse_args()

    loads = [int(item.strip()) for item in args.loads.split(",") if item.strip()]
    out_dir = Path(args.out_dir)
    aggregates: List[Dict[str, Any]] = []
    trial_rows: List[Dict[str, Any]] = []

    for users in loads:
        for mode in ("baseline", "poia_webauthn", "poia_zt_authenticator"):
            rows, aggregate = run_mode_load(mode, users, args.ops_per_user)
            aggregates.append(aggregate)
            for index, row in enumerate(rows, start=1):
                trial_rows.append(
                    {
                        "mode": mode,
                        "configuration": BACKENDS[mode].display_name,
                        "users": users,
                        "sample": index,
                        **row,
                    }
                )

    result = {
        "experiment": "performance_scalability",
        "loads": loads,
        "ops_per_user": args.ops_per_user,
        "configurations": {
            name: {
                "display_name": spec.display_name,
                "modeled_user_interaction_ms": spec.modeled_user_interaction_ms,
            }
            for name, spec in BACKENDS.items()
        },
        "aggregates": aggregates,
    }

    write_json(out_dir / "performance_scalability_summary.json", result)
    write_csv(out_dir / "performance_scalability_trials.csv", trial_rows)
    write_summary_csv(out_dir / "performance_scalability_summary.csv", aggregates)
    write_markdown(out_dir / "performance_scalability_table.md", aggregates)

    print(json.dumps(result, indent=2, sort_keys=True))
    print(f"\nArtifacts written to: {out_dir}")


if __name__ == "__main__":
    main()
