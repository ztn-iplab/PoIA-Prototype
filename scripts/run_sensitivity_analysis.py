#!/usr/bin/env python3
"""Sensitivity analysis for PoIA parameter choices."""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Iterable, List


KEY = b"poia-sensitivity-key"


def canonical_json(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def build_intent(params: int, complexity: str) -> Dict[str, Any]:
    scope = {f"field_{i:03d}": f"value-{i}" for i in range(params)}
    if complexity == "nested":
        scope = {f"group_{g}": {f"field_{i:03d}": f"value-{i}" for i in range(g * params // 5, (g + 1) * params // 5)} for g in range(5)}
    return {
        "action": "sensitivity_action",
        "scope": scope,
        "context": {"rp_id": "poia-demo", "user_id": "user-1", "complexity": complexity},
        "constraints": {"nonce": "sensitivity-nonce"},
    }


def verify_once(ttl_s: int, delay_s: int, params: int, complexity: str) -> Dict[str, Any]:
    start = time.perf_counter()
    intent = build_intent(params, complexity)
    canonical_start = time.perf_counter()
    canonical = canonical_json(intent)
    canonical_ms = (time.perf_counter() - canonical_start) * 1000
    sign_start = time.perf_counter()
    sig = hmac.new(KEY, canonical, hashlib.sha256).digest()
    sign_ms = (time.perf_counter() - sign_start) * 1000
    verify_start = time.perf_counter()
    expected = hmac.new(KEY, canonical, hashlib.sha256).digest()
    crypto_ok = hmac.compare_digest(sig, expected)
    expired = delay_s > ttl_s
    accepted = crypto_ok and not expired
    verify_ms = (time.perf_counter() - verify_start) * 1000
    server_ms = (time.perf_counter() - start) * 1000
    return {
        "ttl_s": ttl_s,
        "network_delay_s": delay_s,
        "params": params,
        "complexity": complexity,
        "accepted": accepted,
        "false_rejection": expired,
        "replay_window_exposure_s": ttl_s,
        "canonicalization_ms": canonical_ms,
        "signature_ms": sign_ms,
        "verification_ms": verify_ms,
        "server_latency_ms": server_ms,
        "end_to_end_latency_ms": server_ms + (delay_s * 1000),
    }


def summarize(values: List[float]) -> Dict[str, float]:
    return {"median": statistics.median(values), "mean": statistics.mean(values), "max": max(values), "n": len(values)} if values else {"median": 0, "mean": 0, "max": 0, "n": 0}


def run(trials: int, ttls: List[int], delays: List[int], concurrencies: List[int], param_counts: List[int], complexities: List[str]) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    rows: List[Dict[str, Any]] = []
    summary: List[Dict[str, Any]] = []
    configs = [(ttl, delay, conc, params, comp) for ttl in ttls for delay in delays for conc in concurrencies for params in param_counts for comp in complexities]
    for ttl, delay, conc, params, comp in configs:
        start_wall = time.perf_counter()
        config_rows = []
        with ThreadPoolExecutor(max_workers=conc) as ex:
            futures = [ex.submit(verify_once, ttl, delay, params, comp) for _ in range(trials)]
            for future in as_completed(futures):
                row = future.result()
                row["concurrent_requests"] = conc
                rows.append(row)
                config_rows.append(row)
        wall_s = time.perf_counter() - start_wall
        summary.append(
            {
                "ttl_s": ttl,
                "network_delay_s": delay,
                "concurrent_requests": conc,
                "params": params,
                "complexity": comp,
                "trials": len(config_rows),
                "latency_ms": summarize([float(r["end_to_end_latency_ms"]) for r in config_rows]),
                "verification_ms": summarize([float(r["verification_ms"]) for r in config_rows]),
                "canonicalization_ms": summarize([float(r["canonicalization_ms"]) for r in config_rows]),
                "false_rejection_rate": round(sum(1 for r in config_rows if r["false_rejection"]) / len(config_rows) * 100.0, 3),
                "replay_window_exposure_s": ttl,
                "throughput_ops_per_second": len(config_rows) / wall_s if wall_s > 0 else 0.0,
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
        "# PoIA Sensitivity Analysis",
        "",
        "| TTL (s) | Delay (s) | Concurrent | Params | Complexity | False Rejection | Median Latency (ms) | Median Verify (ms) | Median Canonicalize (ms) | Replay Window (s) |",
        "|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|",
    ]
    for item in summary:
        lines.append(
            f"| {item['ttl_s']} | {item['network_delay_s']} | {item['concurrent_requests']} | {item['params']} | {item['complexity']} | "
            f"{item['false_rejection_rate']:.1f}% | {item['latency_ms']['median']:.3f} | {item['verification_ms']['median']:.5f} | "
            f"{item['canonicalization_ms']['median']:.5f} | {item['replay_window_exposure_s']} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run PoIA sensitivity analysis.")
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--ttls", default="30,60,120")
    parser.add_argument("--delays", default="0,5,30,90,150")
    parser.add_argument("--concurrency", default="1,10,50")
    parser.add_argument("--params", default="5,20,50")
    parser.add_argument("--complexities", default="flat,nested")
    parser.add_argument("--out-dir", default="experiments/sensitivity_analysis")
    args = parser.parse_args()
    parse = lambda text: [int(x.strip()) for x in text.split(",") if x.strip()]
    rows, summary = run(args.trials, parse(args.ttls), parse(args.delays), parse(args.concurrency), parse(args.params), [x.strip() for x in args.complexities.split(",") if x.strip()])
    out = Path(args.out_dir)
    write_json(out / "sensitivity_summary.json", {"experiment": "sensitivity_analysis", "trials_per_config": args.trials, "summary": summary})
    write_csv(out / "sensitivity_trials.csv", rows)
    write_md(out / "sensitivity_table.md", summary)
    print(json.dumps({"experiment": "sensitivity_analysis", "trials_per_config": args.trials, "configurations": len(summary)}, indent=2, sort_keys=True))
    print(f"\nArtifacts written to: {out}")


if __name__ == "__main__":
    main()
