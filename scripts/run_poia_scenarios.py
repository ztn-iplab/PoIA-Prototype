#!/usr/bin/env python3
import argparse
import json

from _experiment_common import DEFAULT_SCENARIOS, build_session, run_attack_trials


def main():
    parser = argparse.ArgumentParser(description="Run PoIA synthetic scenarios (test mode).")
    parser.add_argument("--base-url", default="https://poia.local", help="PoIA base URL")
    parser.add_argument("--user-id", type=int, default=1, help="User ID for synthetic intent")
    parser.add_argument("--rp-id", default="poia-demo-bank", help="RP ID")
    parser.add_argument("--trials", type=int, default=30, help="Trials per scenario")
    parser.add_argument("--sleep", type=float, default=0.1, help="Sleep between trials")
    parser.add_argument("--timeout", type=float, default=12.0, help="Request timeout in seconds")
    parser.add_argument("--retries", type=int, default=2, help="HTTP retries for transient failures")
    parser.add_argument(
        "--approve",
        action="store_true",
        help="Approve intents instead of denying them (for PoIA latency collection in test mode).",
    )
    parser.add_argument(
        "--scenario-prefix",
        default="",
        help="Optional scenario tag prefix to keep attack and latency runs separable.",
    )
    parser.add_argument("--continue-on-error", action="store_true", help="Continue even if a trial fails")
    parser.add_argument("--output", help="Optional path to write JSON summary")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    args = parser.parse_args()

    session = build_session(insecure=args.insecure, retries=args.retries)
    summary = run_attack_trials(
        session=session,
        base_url=args.base_url,
        user_id=args.user_id,
        rp_id=args.rp_id,
        trials=args.trials,
        sleep_s=args.sleep,
        timeout_s=args.timeout,
        scenarios=DEFAULT_SCENARIOS,
        approve=args.approve,
        reason="synthetic_legitimate_approved" if args.approve else "synthetic_attack_blocked",
        continue_on_error=args.continue_on_error,
        scenario_prefix=args.scenario_prefix,
    )
    rendered = json.dumps(summary, indent=2)
    print(rendered)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered + "\n")


if __name__ == "__main__":
    main()
