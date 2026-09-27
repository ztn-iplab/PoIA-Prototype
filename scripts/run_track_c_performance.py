#!/usr/bin/env python3
"""Pre-registered Track C1 protocol-path performance runner."""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import platform
import random
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.core import build_proof_payload  # noqa: E402
from app.intent_codec import canonical_json  # noqa: E402


CONFIGURATIONS = ("session_baseline", "poia_webauthn_p256", "poia_zt_p256")
WORKLOADS = ("accept", "reject", "mixed")
POIA_NONCE_BACKENDS = ("memory", "sqlite")
COMPONENT_FIELDS = (
    "intent_construction_ms",
    "canonicalization_ms",
    "proof_construction_ms",
    "signature_generation_ms",
    "signature_verification_ms",
    "semantic_comparison_ms",
    "nonce_consumption_ms",
    "audit_serialization_ms",
    "total_ms",
)


def elapsed_ms(start_ns: int) -> float:
    return (time.perf_counter_ns() - start_ns) / 1_000_000


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def summarize(values: list[float]) -> dict[str, float | int]:
    return {
        "n": len(values),
        "median_ms": statistics.median(values),
        "iqr_ms": percentile(values, 0.75) - percentile(values, 0.25),
        "p95_ms": percentile(values, 0.95),
        "p99_ms": percentile(values, 0.99),
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def build_intent(index: int) -> dict[str, Any]:
    return {
        "action": "transfer",
        "scope": {
            "from_account": f"account-{index % 97}",
            "beneficiary_id": f"beneficiary-{index % 193}",
            "amount": 100 + (index % 17),
            "currency": "USD",
        },
        "context": {
            "rp_id": "poia-demo-bank",
            "user_id": 1 + (index % 50),
            "workflow_id": f"workflow-{index}",
        },
        "constraints": {"expires_in_seconds": 60},
    }


def mismatch_intent(intent: dict[str, Any]) -> dict[str, Any]:
    changed = json.loads(json.dumps(intent))
    changed["scope"]["beneficiary_id"] += "-substituted"
    return changed


@dataclass(frozen=True)
class KeyMaterial:
    private: ec.EllipticCurvePrivateKey
    public: ec.EllipticCurvePublicKey


@dataclass(frozen=True)
class PreparedDecision:
    configuration: str
    nonce: str
    canonical_intent: bytes
    requested_canonical: bytes
    signed_message: bytes
    signature: bytes
    expected_accept: bool


def generate_key() -> KeyMaterial:
    private = ec.generate_private_key(ec.SECP256R1())
    return KeyMaterial(private=private, public=private.public_key())


def proof_message(configuration: str, proof_payload: bytes, nonce: str) -> bytes:
    if configuration == "poia_webauthn_p256":
        return hashlib.sha256(proof_payload).digest()
    proof_hash = hashlib.sha256(proof_payload).hexdigest()
    return f"{proof_hash}|1|poia-demo-bank|{nonce}".encode("utf-8")


def prepare_decision(
    configuration: str,
    index: int,
    expected_accept: bool,
    key: KeyMaterial,
) -> PreparedDecision:
    intent = build_intent(index)
    canonical = canonical_json(intent)
    nonce = f"track-c-{configuration}-{index}"
    if configuration == "session_baseline":
        message = canonical_json({"session": f"session-{index}", "user_id": intent["context"]["user_id"]})
        signature = hmac.new(b"track-c-session-key", message, hashlib.sha256).digest()
        if not expected_accept:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
    else:
        payload = build_proof_payload(intent, nonce, 1_900_000_000 + index)
        message = proof_message(configuration, payload, nonce)
        signature = key.private.sign(message, ec.ECDSA(hashes.SHA256()))
    requested = canonical if expected_accept else canonical_json(mismatch_intent(intent))
    return PreparedDecision(configuration, nonce, canonical, requested, message, signature, expected_accept)


class MemoryNonceStore:
    def __init__(self, nonces: Iterable[str]) -> None:
        self._nonces = set(nonces)
        self._lock = threading.Lock()

    def consume(self, nonce: str) -> bool:
        with self._lock:
            if nonce not in self._nonces:
                return False
            self._nonces.remove(nonce)
            return True

    def close(self) -> None:
        return None


class SQLiteNonceStore:
    def __init__(self, path: Path, nonces: Iterable[str]) -> None:
        self.path = path
        self._local = threading.local()
        with sqlite3.connect(path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("CREATE TABLE nonces (nonce TEXT PRIMARY KEY, consumed INTEGER NOT NULL DEFAULT 0)")
            conn.executemany("INSERT INTO nonces (nonce) VALUES (?)", ((nonce,) for nonce in nonces))

    def _connection(self) -> sqlite3.Connection:
        connection = getattr(self._local, "connection", None)
        if connection is None:
            connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            connection.execute("PRAGMA busy_timeout=30000")
            self._local.connection = connection
        return connection

    def consume(self, nonce: str) -> bool:
        conn = self._connection()
        conn.execute("BEGIN IMMEDIATE")
        try:
            cursor = conn.execute("UPDATE nonces SET consumed = 1 WHERE nonce = ? AND consumed = 0", (nonce,))
            conn.execute("COMMIT")
            return cursor.rowcount == 1
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def close(self) -> None:
        connection = getattr(self._local, "connection", None)
        if connection is not None:
            connection.close()


def verify_decision(
    prepared: PreparedDecision,
    key: KeyMaterial,
    nonce_store: MemoryNonceStore | SQLiteNonceStore | None,
) -> tuple[bool, float]:
    started = time.perf_counter_ns()
    if prepared.configuration == "session_baseline":
        expected = hmac.new(b"track-c-session-key", prepared.signed_message, hashlib.sha256).digest()
        accepted = hmac.compare_digest(prepared.signature, expected)
    else:
        try:
            key.public.verify(prepared.signature, prepared.signed_message, ec.ECDSA(hashes.SHA256()))
            signature_ok = True
        except InvalidSignature:
            signature_ok = False
        semantic_ok = hmac.compare_digest(prepared.canonical_intent, prepared.requested_canonical)
        accepted = signature_ok and semantic_ok
        if accepted:
            accepted = nonce_store is not None and nonce_store.consume(prepared.nonce)
    return accepted, elapsed_ms(started)


def component_operation(configuration: str, index: int, key: KeyMaterial) -> dict[str, Any]:
    total_started = time.perf_counter_ns()
    phase = time.perf_counter_ns()
    intent = build_intent(index)
    intent_construction_ms = elapsed_ms(phase)

    phase = time.perf_counter_ns()
    canonical = canonical_json(intent)
    canonicalization_ms = elapsed_ms(phase)

    nonce = f"component-{configuration}-{index}"
    phase = time.perf_counter_ns()
    if configuration == "session_baseline":
        proof_payload = canonical_json({"session": f"session-{index}", "user_id": intent["context"]["user_id"]})
        message = proof_payload
    else:
        proof_payload = build_proof_payload(intent, nonce, 1_900_000_000 + index)
        message = proof_message(configuration, proof_payload, nonce)
    proof_construction_ms = elapsed_ms(phase)

    phase = time.perf_counter_ns()
    if configuration == "session_baseline":
        signature = hmac.new(b"track-c-session-key", message, hashlib.sha256).digest()
    else:
        signature = key.private.sign(message, ec.ECDSA(hashes.SHA256()))
    signature_generation_ms = elapsed_ms(phase)

    phase = time.perf_counter_ns()
    if configuration == "session_baseline":
        expected = hmac.new(b"track-c-session-key", message, hashlib.sha256).digest()
        signature_ok = hmac.compare_digest(signature, expected)
    else:
        try:
            key.public.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            signature_ok = True
        except InvalidSignature:
            signature_ok = False
    signature_verification_ms = elapsed_ms(phase)

    phase = time.perf_counter_ns()
    semantic_ok = hmac.compare_digest(canonical, canonical_json(intent))
    semantic_comparison_ms = elapsed_ms(phase)

    store = MemoryNonceStore([nonce]) if configuration != "session_baseline" else None
    phase = time.perf_counter_ns()
    nonce_ok = True if store is None else store.consume(nonce)
    nonce_consumption_ms = elapsed_ms(phase)

    phase = time.perf_counter_ns()
    json.dumps({"decision": "accept", "intent_hash": hashlib.sha256(canonical).hexdigest(), "index": index})
    audit_serialization_ms = elapsed_ms(phase)
    if not (signature_ok and semantic_ok and nonce_ok):
        raise RuntimeError("component operation failed")
    return {
        "configuration": configuration,
        "sample": index,
        "intent_construction_ms": intent_construction_ms,
        "canonicalization_ms": canonicalization_ms,
        "proof_construction_ms": proof_construction_ms,
        "signature_generation_ms": signature_generation_ms,
        "signature_verification_ms": signature_verification_ms,
        "semantic_comparison_ms": semantic_comparison_ms,
        "nonce_consumption_ms": nonce_consumption_ms,
        "audit_serialization_ms": audit_serialization_ms,
        "total_ms": elapsed_ms(total_started),
    }


def workload_expectation(workload: str, index: int) -> bool:
    if workload == "accept":
        return True
    if workload == "reject":
        return False
    return index % 2 == 0


def make_store(backend: str, prepared: list[PreparedDecision], temp_dir: Path, cell_id: str):
    nonces = [item.nonce for item in prepared if item.expected_accept]
    if backend == "memory":
        return MemoryNonceStore(nonces)
    if backend == "sqlite":
        return SQLiteNonceStore(temp_dir / f"{cell_id}.sqlite3", nonces)
    return None


def run_throughput_cell(
    configuration: str,
    nonce_backend: str,
    workload: str,
    concurrency: int,
    operations: int,
    key: KeyMaterial,
    temp_dir: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    prepared = [
        prepare_decision(configuration, index, workload_expectation(workload, index), key)
        for index in range(operations)
    ]
    cell_id = f"{configuration}-{nonce_backend}-{workload}-{concurrency}"
    store = make_store(nonce_backend, prepared, temp_dir, cell_id)
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        outcomes = list(executor.map(lambda item: verify_decision(item, key, store), prepared))
    wall_seconds = time.perf_counter() - started
    if store is not None:
        store.close()

    rows = []
    incorrect_accepts = 0
    incorrect_rejects = 0
    for index, (prepared_item, (accepted, latency_ms)) in enumerate(zip(prepared, outcomes)):
        incorrect_accepts += int(accepted and not prepared_item.expected_accept)
        incorrect_rejects += int(not accepted and prepared_item.expected_accept)
        rows.append(
            {
                "cell_id": cell_id,
                "sample": index,
                "expected_accept": int(prepared_item.expected_accept),
                "observed_accept": int(accepted),
                "latency_ms": latency_ms,
            }
        )
    latencies = [row["latency_ms"] for row in rows]
    expected_accepts = sum(row["expected_accept"] for row in rows)
    observed_accepts = sum(row["observed_accept"] for row in rows)
    summary = {
        "cell_id": cell_id,
        "configuration": configuration,
        "nonce_backend": nonce_backend,
        "workload": workload,
        "concurrency": concurrency,
        "operations": operations,
        "wall_seconds": wall_seconds,
        "throughput_decisions_per_second": operations / wall_seconds,
        "expected_accepts": expected_accepts,
        "expected_rejects": operations - expected_accepts,
        "observed_accepts": observed_accepts,
        "observed_rejects": operations - observed_accepts,
        "incorrect_accepts": incorrect_accepts,
        "incorrect_rejects": incorrect_rejects,
        "latency": summarize(latencies),
    }
    if incorrect_accepts or incorrect_rejects or len(rows) != operations:
        raise RuntimeError(f"invalid Track C cell: {cell_id}")
    return summary, rows


def write_csv(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_table(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        f"# Track C1 Results: `{summary['run_id']}`",
        "",
        "## Component Decomposition",
        "",
        "| Configuration | Component | n | Median ms | IQR ms | P95 ms | P99 ms |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for configuration, metrics in summary["components"].items():
        for component, values in metrics.items():
            lines.append(
                f"| {configuration} | {component} | {values['n']} | {values['median_ms']:.4f} | "
                f"{values['iqr_ms']:.4f} | {values['p95_ms']:.4f} | {values['p99_ms']:.4f} |"
            )
    lines += [
        "",
        "## Throughput",
        "",
        "| Configuration | Nonce store | Workload | Concurrency | decisions/s | P95 ms | Incorrect accept | Incorrect reject |",
        "|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for cell in summary["throughput_cells"]:
        lines.append(
            f"| {cell['configuration']} | {cell['nonce_backend']} | {cell['workload']} | "
            f"{cell['concurrency']} | {cell['throughput_decisions_per_second']:.1f} | "
            f"{cell['latency']['p95_ms']:.4f} | {cell['incorrect_accepts']} | {cell['incorrect_rejects']} |"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--component-warmup", type=int, default=500)
    parser.add_argument("--component-samples", type=int, default=5000)
    parser.add_argument("--cell-operations", type=int, default=5000)
    parser.add_argument("--concurrency", default="1,10,50,100,200")
    parser.add_argument("--seed", type=int, default=20260620)
    args = parser.parse_args()
    random.seed(args.seed)

    if git("status", "--porcelain"):
        raise SystemExit("Track C confirmatory runs require a clean working tree")
    concurrency_levels = [int(value) for value in args.concurrency.split(",")]
    run_id = args.run_id
    raw_dir = ROOT / "experiments" / "track_c" / "raw" / run_id
    manifest_path = ROOT / "experiments" / "track_c" / "manifests" / f"{run_id}.json"
    summary_path = ROOT / "experiments" / "track_c" / "analysis" / f"{run_id}-summary.json"
    table_path = ROOT / "experiments" / "track_c" / "tables" / f"{run_id}.md"
    checksum_path = ROOT / "experiments" / "track_c" / "analysis" / f"{run_id}-checksums.sha256"
    if any(path.exists() for path in (raw_dir, manifest_path, summary_path, table_path, checksum_path)):
        raise SystemExit(f"run ID already exists: {run_id}")

    manifest = {
        "run_id": run_id,
        "track": "C1",
        "repository_commit": git("rev-parse", "HEAD"),
        "tree_clean": True,
        "seed": args.seed,
        "component_warmup": args.component_warmup,
        "component_samples": args.component_samples,
        "cell_operations": args.cell_operations,
        "concurrency": concurrency_levels,
        "configurations": list(CONFIGURATIONS),
        "workloads": list(WORKLOADS),
        "poia_nonce_backends": list(POIA_NONCE_BACKENDS),
        "clock": "time.perf_counter_ns",
        "host": {"platform": platform.platform(), "machine": platform.machine(), "python": platform.python_version()},
        "runner_sha256": sha256_file(Path(__file__)),
        "preregistration_sha256": sha256_file(ROOT / "docs" / "experiments" / "track_c_preregistration.md"),
    }
    write_json(manifest_path, manifest)

    keys = {configuration: generate_key() for configuration in CONFIGURATIONS}
    component_rows = []
    for configuration in CONFIGURATIONS:
        for index in range(args.component_warmup):
            component_operation(configuration, -index - 1, keys[configuration])
        for index in range(args.component_samples):
            component_rows.append(component_operation(configuration, index, keys[configuration]))
    write_csv(raw_dir / "component_trials.csv", component_rows)
    components = {
        configuration: {
            field: summarize([row[field] for row in component_rows if row["configuration"] == configuration])
            for field in COMPONENT_FIELDS
        }
        for configuration in CONFIGURATIONS
    }

    throughput_cells = []
    with tempfile.TemporaryDirectory(prefix="poia-track-c-") as temp:
        temp_dir = Path(temp)
        for configuration in CONFIGURATIONS:
            backends = ("none",) if configuration == "session_baseline" else POIA_NONCE_BACKENDS
            for nonce_backend in backends:
                for workload in WORKLOADS:
                    for concurrency in concurrency_levels:
                        cell, rows = run_throughput_cell(
                            configuration,
                            nonce_backend,
                            workload,
                            concurrency,
                            args.cell_operations,
                            keys[configuration],
                            temp_dir,
                        )
                        throughput_cells.append(cell)
                        write_csv(raw_dir / "throughput" / f"{cell['cell_id']}.csv", rows)

    summary = {"run_id": run_id, "manifest": str(manifest_path.relative_to(ROOT)), "components": components, "throughput_cells": throughput_cells}
    write_json(summary_path, summary)
    write_table(table_path, summary)

    files = [manifest_path, summary_path, table_path, *sorted(raw_dir.rglob("*"))]
    checksum_lines = [f"{sha256_file(path)}  {path.relative_to(ROOT)}" for path in files if path.is_file()]
    checksum_path.parent.mkdir(parents=True, exist_ok=True)
    checksum_path.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    print(json.dumps({"run_id": run_id, "cells": len(throughput_cells), "raw_dir": str(raw_dir)}, indent=2))


if __name__ == "__main__":
    main()
