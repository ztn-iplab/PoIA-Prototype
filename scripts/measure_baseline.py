import argparse
import json
import sqlite3
import statistics
import time
from urllib.parse import urlparse
from typing import Dict, List, Tuple

import requests
from itsdangerous import URLSafeSerializer
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


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


def run_trials(
    session: requests.Session,
    method: str,
    url: str,
    payload: Dict[str, object],
    trials: int,
    timeout_s: float,
) -> List[float]:
    samples = []
    for _ in range(trials):
        start = time.perf_counter()
        if method == "POST":
            resp = session.post(url, data=payload, timeout=timeout_s)
        else:
            resp = session.get(url, timeout=timeout_s)
        resp.raise_for_status()
        elapsed_ms = (time.perf_counter() - start) * 1000
        samples.append(elapsed_ms)
    return samples


def summarize(samples: List[float]) -> Dict[str, float]:
    return {
        "median": statistics.median(samples),
        "mean": statistics.mean(samples),
        "p95": percentile(samples, 0.95),
        "max": max(samples) if samples else 0.0,
        "stdev": statistics.pstdev(samples) if len(samples) > 1 else 0.0,
        "count": len(samples),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="https://poia.local")
    parser.add_argument("--db-path", required=True)
    parser.add_argument("--user-id", type=int, default=1)
    parser.add_argument("--secret", default="change-me-in-prod")
    parser.add_argument("--trials", type=int, default=30)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--pause-ms", type=float, default=0.0)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--output", help="Optional path to write JSON summary")
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()

    account_id = load_account_id(args.db_path, args.user_id)

    session = requests.Session()
    session.verify = not args.insecure
    retry = Retry(
        total=max(0, args.retries),
        read=max(0, args.retries),
        connect=max(0, args.retries),
        backoff_factor=0.2,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "POST"}),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=20)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    cookie = make_session_cookie(args.secret, {"user_id": args.user_id})
    cookie_domain = urlparse(args.base_url).hostname or "poia.local"
    session.cookies.set("session", cookie, domain=cookie_domain, path="/")

    transfer_payload = {
        "from_account": account_id,
        "to_type": "external",
        "external_account": "EXT-BASELINE",
        "amount": "10.00",
        "currency": "USD",
    }
    transfer_url = f"{args.base_url}/transfer"
    statement_url = f"{args.base_url}/statements.csv?account_id={account_id}&txn_type=&date_from=&date_to="

    if args.warmup > 0:
        run_trials(session, "POST", transfer_url, transfer_payload, args.warmup, args.timeout)
        run_trials(session, "GET", statement_url, {}, args.warmup, args.timeout)

    transfer_samples = []
    statement_samples = []
    for _ in range(args.trials):
        transfer_samples.extend(run_trials(session, "POST", transfer_url, transfer_payload, 1, args.timeout))
        statement_samples.extend(run_trials(session, "GET", statement_url, {}, 1, args.timeout))
        if args.pause_ms > 0:
            time.sleep(args.pause_ms / 1000.0)

    results = {
        "transfer": summarize(transfer_samples),
        "statements": summarize(statement_samples),
    }
    rendered = json.dumps(results, indent=2)
    print(rendered)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered + "\n")


if __name__ == "__main__":
    main()
