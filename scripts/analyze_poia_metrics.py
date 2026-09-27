#!/usr/bin/env python3
import argparse
import csv
import json
from pathlib import Path
from statistics import mean, median, pstdev
from typing import Dict, Iterable, List, Optional


ATTACK_SCENARIOS = [
    "replay",
    "relay_phishing",
    "session_misuse",
    "intent_substitution",
]


def percentile(values: List[float], pct: float) -> Optional[float]:
    if not values:
        return None
    values = sorted(values)
    k = (len(values) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(values) - 1)
    if f == c:
        return values[f]
    return values[f] + (values[c] - values[f]) * (k - f)


def load_rows(path: Optional[Path]) -> List[Dict[str, str]]:
    if not path or not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def parse_payload(row: Dict[str, str]) -> Dict[str, object]:
    raw = row.get("payload_json") or ""
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


def normalize_scenario(raw: str) -> str:
    tag = (raw or "").strip().lower()
    for prefix in ("baseline_", "poia_"):
        if tag.startswith(prefix):
            tag = tag[len(prefix) :]
    return tag


def scenario_for_row(row: Dict[str, str], scenario_map: Dict[str, str]) -> str:
    direct = normalize_scenario((row.get("scenario") or str(parse_payload(row).get("scenario", ""))))
    if direct:
        return direct
    intent_id = row.get("intent_id") or ""
    return normalize_scenario(scenario_map.get(intent_id, ""))


def build_scenario_map(rows: Iterable[Dict[str, str]]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for row in rows:
        scenario_tag = normalize_scenario(
            (row.get("scenario") or str(parse_payload(row).get("scenario", "")))
        )
        intent_id = row.get("intent_id") or ""
        if scenario_tag and intent_id:
            mapping[intent_id] = scenario_tag
    return mapping


def compute_attack_success(rows: List[Dict[str, str]], scenario_map: Dict[str, str]) -> Dict[str, Dict[str, float]]:
    results: Dict[str, Dict[str, float]] = {}
    for scenario in ATTACK_SCENARIOS:
        attempts = 0
        successes = 0
        for row in rows:
            scenario_tag = scenario_for_row(row, scenario_map)
            if scenario_tag != scenario:
                continue
            if row.get("event") not in {"intent_approve", "baseline_action"}:
                continue
            attempts += 1
            if row.get("status") == "approved":
                successes += 1
        rate = (successes / attempts * 100.0) if attempts else 0.0
        results[scenario] = {"attempts": attempts, "approved": successes, "success_rate": rate}
    return results


def compute_latency(
    rows: List[Dict[str, str]],
    events: set[str],
    status_filter: Optional[set[str]] = None,
) -> Dict[str, Optional[float]]:
    values = []
    for row in rows:
        if row.get("event") not in events:
            continue
        status = row.get("status") or ""
        if status_filter and status not in status_filter:
            continue
        latency = row.get("latency_ms")
        if not latency:
            continue
        try:
            values.append(float(latency))
        except ValueError:
            continue
    if not values:
        return {"median": None, "mean": None, "p95": None, "max": None, "stdev": None, "n": 0}
    return {
        "median": median(values),
        "mean": mean(values),
        "p95": percentile(values, 95),
        "max": max(values),
        "stdev": pstdev(values) if len(values) > 1 else 0.0,
        "n": len(values),
    }


def load_attack_json(path: Optional[Path]) -> Dict[str, Dict[str, float]]:
    if not path or not path.exists():
        return {}
    with path.open(encoding="utf-8") as handle:
        raw = json.load(handle)
    out: Dict[str, Dict[str, float]] = {}
    for scenario in ATTACK_SCENARIOS:
        item = raw.get(scenario, {})
        trials = int(item.get("trials", 0))
        approved = int(item.get("approved", 0))
        rate = float(item.get("success_rate", (approved / trials * 100.0) if trials else 0.0))
        out[scenario] = {"attempts": trials, "approved": approved, "success_rate": rate}
    return out


def load_baseline_latency_json(path: Optional[Path]) -> Optional[Dict[str, Dict[str, float]]]:
    if not path or not path.exists():
        return None
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        return None
    return data


def fmt(val: Optional[float]) -> str:
    if val is None:
        return "-"
    return f"{val:.3f}"


def to_report_markdown(
    run_folder: Optional[str],
    attack_baseline: Dict[str, Dict[str, float]],
    attack_poia: Dict[str, Dict[str, float]],
    baseline_latency: Dict[str, Dict[str, Optional[float]]],
    poia_webauthn: Dict[str, Optional[float]],
    poia_zt: Dict[str, Optional[float]],
) -> str:
    lines = ["# PoIA Experiment Run Summary", ""]
    if run_folder:
        lines.extend([f"Run folder: `{run_folder}`", ""])

    lines.extend(
        [
            "## Security Effectiveness (Attack Success %)",
            "",
            "| Scenario | Baseline | PoIA |",
            "|---|---:|---:|",
        ]
    )
    for scenario in ATTACK_SCENARIOS:
        b = attack_baseline.get(scenario, {}).get("success_rate", 0.0)
        p = attack_poia.get(scenario, {}).get("success_rate", 0.0)
        lines.append(f"| {scenario.replace('_', ' ')} | {b:.1f}% | {p:.1f}% |")

    lines.extend(
        [
            "",
            "## Baseline Performance (ms)",
            "",
            "| Flow | Median | Mean | P95 | Max | StdDev | n |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for flow in ("transfer", "statements"):
        data = baseline_latency.get(flow, {})
        lines.append(
            "| "
            f"{flow} | {fmt(data.get('median'))} | {fmt(data.get('mean'))} | {fmt(data.get('p95'))} | "
            f"{fmt(data.get('max'))} | {fmt(data.get('stdev'))} | {int(data.get('count', data.get('n', 0) or 0))} |"
        )

    lines.extend(
        [
            "",
            "## PoIA Approval Latency (ms)",
            "",
            "| Method | Median | Mean | P95 | Max | StdDev | n |",
            "|---|---:|---:|---:|---:|---:|---:|",
            f"| PoIA WebAuthn | {fmt(poia_webauthn.get('median'))} | {fmt(poia_webauthn.get('mean'))} | {fmt(poia_webauthn.get('p95'))} | {fmt(poia_webauthn.get('max'))} | {fmt(poia_webauthn.get('stdev'))} | {int(poia_webauthn.get('n', 0) or 0)} |",
            f"| PoIA ZT-Authenticator | {fmt(poia_zt.get('median'))} | {fmt(poia_zt.get('mean'))} | {fmt(poia_zt.get('p95'))} | {fmt(poia_zt.get('max'))} | {fmt(poia_zt.get('stdev'))} | {int(poia_zt.get('n', 0) or 0)} |",
            "",
            "## Notes",
            "- Baseline attacks are expected to succeed in non-PoIA emulation.",
            "- PoIA synthetic attack approvals are expected to be denied.",
            "- WebAuthn latency includes interactive user confirmation.",
        ]
    )
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Analyze PoIA experiment metrics and write comparison artifacts.")
    parser.add_argument("--poia", required=True, help="Path to poia_experiments.csv")
    parser.add_argument("--baseline-csv", help="Optional baseline CSV for direct comparison")
    parser.add_argument("--poia-attack-json", help="Optional JSON summary from run_poia_scenarios.py")
    parser.add_argument("--baseline-attack-json", help="Optional JSON summary from run_attack_baseline.py")
    parser.add_argument("--baseline-latency-json", help="Optional JSON summary from measure_baseline.py")
    parser.add_argument("--run-folder", help="Optional run folder path for report header")
    parser.add_argument("--out-json", help="Optional path to write machine-readable aggregate JSON")
    parser.add_argument("--out-csv", help="Optional path to write attack comparison CSV")
    parser.add_argument("--out-md", help="Optional path to write summary markdown")
    args = parser.parse_args()

    poia_rows = load_rows(Path(args.poia))
    baseline_rows = load_rows(Path(args.baseline_csv)) if args.baseline_csv else []
    scenario_map = build_scenario_map(poia_rows + baseline_rows)

    poia_attack = load_attack_json(Path(args.poia_attack_json) if args.poia_attack_json else None)
    if not poia_attack:
        poia_attack = compute_attack_success(poia_rows, scenario_map)

    baseline_attack = load_attack_json(Path(args.baseline_attack_json) if args.baseline_attack_json else None)
    if not baseline_attack:
        baseline_attack = compute_attack_success(baseline_rows, scenario_map)

    poia_webauthn = compute_latency(poia_rows, {"passkey_complete"}, {"approved"})
    poia_zt = compute_latency(poia_rows, {"intent_approve"}, {"approved"})

    baseline_latency = load_baseline_latency_json(
        Path(args.baseline_latency_json) if args.baseline_latency_json else None
    )
    if baseline_latency is None:
        baseline_latency = {
            "transfer": compute_latency(baseline_rows, {"baseline_action"}, {"approved"}),
            "statements": compute_latency(baseline_rows, {"baseline_action"}, {"approved"}),
        }

    aggregate = {
        "attacks": {"baseline": baseline_attack, "poia": poia_attack},
        "latency": {
            "baseline": baseline_latency,
            "poia_webauthn": poia_webauthn,
            "poia_zt_authenticator": poia_zt,
        },
    }

    print("Attack success rates (PoIA):")
    for scenario in ATTACK_SCENARIOS:
        data = poia_attack.get(scenario, {"success_rate": 0.0, "attempts": 0})
        print(f"- {scenario}: {data['success_rate']:.1f}% (n={int(data.get('attempts', 0))})")
    if baseline_attack:
        print("\nAttack success rates (baseline):")
        for scenario in ATTACK_SCENARIOS:
            data = baseline_attack.get(scenario, {"success_rate": 0.0, "attempts": 0})
            print(f"- {scenario}: {data['success_rate']:.1f}% (n={int(data.get('attempts', 0))})")

    print("\nLatency summary (PoIA approvals):")
    print({"method": "poia_webauthn", **poia_webauthn})
    print({"method": "poia_zt_authenticator", **poia_zt})

    if args.out_json:
        with Path(args.out_json).open("w", encoding="utf-8") as handle:
            json.dump(aggregate, handle, indent=2)
            handle.write("\n")

    if args.out_csv:
        with Path(args.out_csv).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle, lineterminator="\n")
            writer.writerow(["scenario", "baseline_success_pct", "poia_success_pct"])
            for scenario in ATTACK_SCENARIOS:
                writer.writerow(
                    [
                        scenario,
                        round(float(baseline_attack.get(scenario, {}).get("success_rate", 0.0)), 3),
                        round(float(poia_attack.get(scenario, {}).get("success_rate", 0.0)), 3),
                    ]
                )

    if args.out_md:
        summary = to_report_markdown(
            run_folder=args.run_folder,
            attack_baseline=baseline_attack,
            attack_poia=poia_attack,
            baseline_latency=baseline_latency,
            poia_webauthn=poia_webauthn,
            poia_zt=poia_zt,
        )
        Path(args.out_md).write_text(summary, encoding="utf-8")


if __name__ == "__main__":
    main()
