import argparse
import json
import sqlite3
import statistics
import time
from typing import Dict, List, Tuple

import requests
from itsdangerous import URLSafeSerializer


def load_account_id(db_path: str, user_id: int) -> int:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT id FROM accounts WHERE user_id = ? ORDER BY id LIMIT 1", (user_id,)
    ).fetchone()
    conn.close()
    if not row:
        raise RuntimeError(f"No accounts found for user_id={user_id}")
    return int(row["id"])


def make_session_cookie(secret: str, data: Dict[str, object]) -> str:
    serializer = URLSafeSerializer(secret_key=secret, salt="starlette.sessions")
    return serializer.dumps(data)


def percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    values_sorted = sorted(values)
    k = (len(values_sorted) - 1) * p
    f = int(k)
    c = min(f + 1, len(values_sorted) - 1)
    if f == c:
        return values_sorted[f]
    return values_sorted[f] + (values_sorted[c] - values_sorted[f]) * (k - f)


def run_trials(session: requests.Session, method: str, url: str, payload: Dict[str, object], trials: int) -> List[float]:
    samples = []
    for _ in range(trials):
        start = time.perf_counter()
        if method == "POST":
            resp = session.post(url, data=payload, timeout=15)
        else:
            resp = session.get(url, timeout=15)
        resp.raise_for_status()
        elapsed_ms = (time.perf_counter() - start) * 1000
        samples.append(elapsed_ms)
    return samples


def summarize(samples: List[float]) -> Dict[str, float]:
    return {
        "median": statistics.median(samples),
        "p95": percentile(samples, 0.95),
        "max": max(samples) if samples else 0.0,
        "count": len(samples),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="https://poia.local")
    parser.add_argument("--db-path", required=True)
    parser.add_argument("--user-id", type=int, default=1)
    parser.add_argument("--secret", default="change-me-in-prod")
    parser.add_argument("--trials", type=int, default=30)
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()

    account_id = load_account_id(args.db_path, args.user_id)

    session = requests.Session()
    session.verify = not args.insecure
    cookie = make_session_cookie(args.secret, {"user_id": args.user_id})
    session.cookies.set("session", cookie, domain="poia.local", path="/")

    transfer_payload = {
        "from_account": account_id,
        "to_type": "external",
        "external_account": "EXT-BASELINE",
        "amount": "10.00",
        "currency": "USD",
    }
    transfer_url = f"{args.base_url}/transfer"
    statement_url = f"{args.base_url}/statements.csv?account_id={account_id}&txn_type=&date_from=&date_to="

    transfer_samples = run_trials(session, "POST", transfer_url, transfer_payload, args.trials)
    statement_samples = run_trials(session, "GET", statement_url, {}, args.trials)

    results = {
        "transfer": summarize(transfer_samples),
        "statements": summarize(statement_samples),
    }
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
