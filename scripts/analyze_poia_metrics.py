#!/usr/bin/env python3
import argparse
import csv
import json
from pathlib import Path
from statistics import median


ATTACK_SCENARIOS = {
    "replay",
    "relay_phishing",
    "session_misuse",
    "intent_substitution",
}


def percentile(values, pct):
    if not values:
        return None
    values = sorted(values)
    k = (len(values) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(values) - 1)
    if f == c:
        return values[f]
    return values[f] + (values[c] - values[f]) * (k - f)


def load_rows(path: Path):
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def parse_payload(row):
    raw = row.get("payload_json") or ""
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


def build_scenario_map(rows):
    scenario_map = {}
    for row in rows:
        scenario_tag = row.get("scenario") or parse_payload(row).get("scenario") or ""
        intent_id = row.get("intent_id") or ""
        if scenario_tag and intent_id:
            scenario_map[intent_id] = scenario_tag
    return scenario_map


def compute_attack_success(rows, scenario_map, method_label):
    results = {}
    for scenario in ATTACK_SCENARIOS:
        attempts = 0
        successes = 0
        for row in rows:
            scenario_tag = row.get("scenario") or parse_payload(row).get("scenario") or ""
            if not scenario_tag:
                intent_id = row.get("intent_id") or ""
                scenario_tag = scenario_map.get(intent_id, "")
            if scenario_tag != scenario:
                continue
            if row.get("event") not in {"intent_approve", "baseline_action"}:
                continue
            attempts += 1
            if row.get("status") == "approved":
                successes += 1
        rate = (successes / attempts * 100.0) if attempts else 0.0
        results[scenario] = {"attempts": attempts, "success_rate": rate, "method": method_label}
    return results


def compute_latency(rows, method_label, events):
    values = []
    for row in rows:
        if row.get("event") not in events:
            continue
        if row.get("status") != "approved":
            continue
        if not row.get("latency_ms"):
            continue
        values.append(int(row["latency_ms"]))
    return {
        "method": method_label,
        "median": median(values) if values else None,
        "p95": percentile(values, 95) if values else None,
        "max": max(values) if values else None,
        "count": len(values),
    }


def main():
    parser = argparse.ArgumentParser(description="Analyze PoIA experiment metrics.")
    parser.add_argument("--poia", required=True, help="Path to poia_experiments.csv")
    parser.add_argument("--baseline", help="Optional baseline metrics CSV")
    args = parser.parse_args()

    poia_rows = load_rows(Path(args.poia))
    baseline_rows = load_rows(Path(args.baseline)) if args.baseline else []
    scenario_map = build_scenario_map(poia_rows + baseline_rows)

    print("Attack success rates (PoIA):")
    for scenario, data in compute_attack_success(poia_rows, scenario_map, "poia").items():
        print(f"- {scenario}: {data['success_rate']:.1f}% (n={data['attempts']})")

    if baseline_rows:
        print("\nAttack success rates (baseline):")
        for scenario, data in compute_attack_success(baseline_rows, scenario_map, "baseline").items():
            print(f"- {scenario}: {data['success_rate']:.1f}% (n={data['attempts']})")

    poia_webauthn = compute_latency(poia_rows, "poia_webauthn", {"passkey_complete"})
    poia_zt = compute_latency(poia_rows, "poia_zt_authenticator", {"intent_approve"})
    print("\nLatency summary (PoIA approvals):")
    print(poia_webauthn)
    print(poia_zt)

    if baseline_rows:
        baseline_latency = compute_latency(baseline_rows, "baseline", {"baseline_action"})
        print("\nLatency summary (baseline actions):")
        print(baseline_latency)


if __name__ == "__main__":
    main()
