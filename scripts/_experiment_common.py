#!/usr/bin/env python3
"""Shared helpers for PoIA experiment scripts."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional
from urllib.parse import urljoin

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


DEFAULT_SCENARIOS = (
    "replay",
    "relay_phishing",
    "session_misuse",
    "intent_substitution",
)


@dataclass
class TrialCounts:
    approved: int = 0
    trials: int = 0
    errors: int = 0

    def as_dict(self) -> Dict[str, float]:
        success_rate = (self.approved / self.trials * 100.0) if self.trials else 0.0
        return {
            "approved": self.approved,
            "trials": self.trials,
            "errors": self.errors,
            "success_rate": round(success_rate, 3),
        }


def build_session(
    insecure: bool = False,
    retries: int = 2,
    backoff_factor: float = 0.2,
) -> requests.Session:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    session = requests.Session()
    session.verify = not insecure
    retry = Retry(
        total=max(0, retries),
        read=max(0, retries),
        connect=max(0, retries),
        backoff_factor=backoff_factor,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "POST"}),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=20)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def create_intent(
    session: requests.Session,
    base_url: str,
    action: str,
    user_id: int,
    rp_id: str,
    timeout_s: float,
    scope: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    payload = {
        "action": action,
        "scope": scope or {"amount": 100.0, "currency": "USD", "account_id": 1},
        "context": {"rp_id": rp_id, "user_id": user_id},
    }
    res = session.post(
        urljoin(base_url, "/api/poia/test/intent"),
        json=payload,
        timeout=timeout_s,
    )
    res.raise_for_status()
    body = res.json()
    if not isinstance(body, dict) or "intent_id" not in body:
        raise RuntimeError(f"Malformed intent response: {json.dumps(body)[:240]}")
    return body


def approve_intent(
    session: requests.Session,
    base_url: str,
    intent_id: str,
    scenario: str,
    approved: bool,
    reason: str,
    timeout_s: float,
) -> Dict[str, object]:
    payload = {
        "intent_id": intent_id,
        "scenario": scenario,
        "force_status": "approved" if approved else "denied",
        "reason": reason,
    }
    res = session.post(
        urljoin(base_url, "/api/poia/test/approve"),
        json=payload,
        timeout=timeout_s,
    )
    res.raise_for_status()
    body = res.json()
    if not isinstance(body, dict):
        raise RuntimeError(f"Malformed approval response: {json.dumps(body)[:240]}")
    return body


def run_attack_trials(
    session: requests.Session,
    base_url: str,
    user_id: int,
    rp_id: str,
    trials: int,
    sleep_s: float,
    timeout_s: float,
    scenarios: Iterable[str],
    approve: bool,
    reason: str,
    continue_on_error: bool,
    scenario_prefix: str = "",
) -> Dict[str, Dict[str, float]]:
    summary: Dict[str, Dict[str, float]] = {}
    for scenario in scenarios:
        counts = TrialCounts(trials=trials)
        for _ in range(trials):
            try:
                intent = create_intent(
                    session=session,
                    base_url=base_url,
                    action="transfer",
                    user_id=user_id,
                    rp_id=rp_id,
                    timeout_s=timeout_s,
                )
                intent_id = str(intent["intent_id"])
                result = approve_intent(
                    session=session,
                    base_url=base_url,
                    intent_id=intent_id,
                    scenario=f"{scenario_prefix}{scenario}",
                    approved=approve,
                    reason=reason,
                    timeout_s=timeout_s,
                )
                if result.get("status") == "approved":
                    counts.approved += 1
            except Exception:
                counts.errors += 1
                if not continue_on_error:
                    raise
            if sleep_s > 0:
                time.sleep(sleep_s)
        summary[scenario] = counts.as_dict()
    return summary
