#!/usr/bin/env python3
import argparse
import json
import time
from urllib.parse import urljoin

import requests
import urllib3


SCENARIOS = [
    "replay",
    "relay_phishing",
    "session_misuse",
    "intent_substitution",
]


def create_intent(session, base_url, action, user_id, rp_id, verify):
    payload = {
        "action": action,
        "scope": {"amount": 100.0, "currency": "USD", "account_id": 1},
        "context": {"rp_id": rp_id, "user_id": user_id},
    }
    res = session.post(
        urljoin(base_url, "/api/poia/test/intent"),
        json=payload,
        timeout=10,
        verify=verify,
    )
    res.raise_for_status()
    return res.json()


def approve_intent(session, base_url, intent_id, scenario, approved=True, reason="", verify=True):
    payload = {
        "intent_id": intent_id,
        "scenario": scenario,
        "force_status": "approved" if approved else "denied",
        "reason": reason,
    }
    res = session.post(
        urljoin(base_url, "/api/poia/test/approve"),
        json=payload,
        timeout=10,
        verify=verify,
    )
    res.raise_for_status()
    return res.json()


def main():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    parser = argparse.ArgumentParser(description="Run PoIA synthetic scenarios (test mode).")
    parser.add_argument("--base-url", default="https://poia.local", help="PoIA base URL")
    parser.add_argument("--user-id", type=int, default=1, help="User ID for synthetic intent")
    parser.add_argument("--rp-id", default="poia-demo-bank", help="RP ID")
    parser.add_argument("--trials", type=int, default=30, help="Trials per scenario")
    parser.add_argument("--sleep", type=float, default=0.1, help="Sleep between trials")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    args = parser.parse_args()

    session = requests.Session()
    summary = {}
    verify_tls = not args.insecure
    for scenario in SCENARIOS:
        approved = 0
        for _ in range(args.trials):
            intent = create_intent(session, args.base_url, "transfer", args.user_id, args.rp_id, verify_tls)
            intent_id = intent["intent_id"]
            if scenario in {"replay", "relay_phishing", "session_misuse", "intent_substitution"}:
                result = approve_intent(
                    session,
                    args.base_url,
                    intent_id,
                    scenario,
                    approved=False,
                    reason="synthetic_attack_blocked",
                    verify=verify_tls,
                )
            else:
                result = approve_intent(
                    session,
                    args.base_url,
                    intent_id,
                    scenario,
                    approved=True,
                    verify=verify_tls,
                )
            if result.get("status") == "approved":
                approved += 1
            time.sleep(args.sleep)
        summary[scenario] = {"approved": approved, "trials": args.trials}
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
