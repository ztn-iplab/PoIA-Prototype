#!/usr/bin/env python3
"""Track C2 loopback HTTP topology and shared-verifier fault runner."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import hmac
import json
import multiprocessing
import platform
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.core import build_proof_payload  # noqa: E402
from app.intent_codec import canonical_json  # noqa: E402

TOPOLOGIES = ("gateway_only", "service_local", "shared_verifier", "hybrid")
DEPENDENT_TOPOLOGIES = ("shared_verifier", "hybrid")


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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


def build_intent(index: int) -> dict[str, Any]:
    return {
        "action": "transfer",
        "scope": {"account": f"account-{index % 97}", "target": f"target-{index % 193}", "amount": 100 + index % 17},
        "context": {"rp_id": "poia-demo-bank", "user_id": 1 + index % 50, "workflow_id": f"workflow-{index}"},
        "constraints": {"expires_in_seconds": 60},
    }


def build_request(index: int, legitimate: bool, private_key: ec.EllipticCurvePrivateKey) -> dict[str, Any]:
    intent = build_intent(index)
    requested = json.loads(json.dumps(intent))
    if not legitimate:
        requested["scope"]["target"] += "-substituted"
    nonce = f"track-c2-{index}"
    expires_at = 1_900_000_000 + index
    message = hashlib.sha256(build_proof_payload(intent, nonce, expires_at)).digest()
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return {
        "intent": intent,
        "requested": requested,
        "nonce": nonce,
        "expires_at": expires_at,
        "signature": base64.b64encode(signature).decode("ascii"),
        "expected_accept": legitimate,
    }


def verify_payload(payload: dict[str, Any], public_key: ec.EllipticCurvePublicKey) -> bool:
    message = hashlib.sha256(
        build_proof_payload(payload["intent"], payload["nonce"], payload["expires_at"])
    ).digest()
    try:
        public_key.verify(base64.b64decode(payload["signature"]), message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return False
    return hmac.compare_digest(canonical_json(payload["intent"]), canonical_json(payload["requested"]))


def decode_public_key(public_der: bytes) -> ec.EllipticCurvePublicKey:
    key = serialization.load_der_public_key(public_der)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise TypeError("expected EC public key")
    return key


def read_json(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0"))
    return json.loads(handler.rfile.read(length))


def send_json(handler: BaseHTTPRequestHandler, status: int, body: dict[str, Any]) -> None:
    encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(encoded)))
    handler.end_headers()
    handler.wfile.write(encoded)


def verifier_process(public_der: bytes, ready, requested_port: int = 0) -> None:
    public_key = decode_public_key(public_der)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            payload = read_json(self)
            accepted = verify_payload(payload, public_key)
            send_json(self, 200, {"accepted": accepted})

        def log_message(self, _format: str, *args: Any) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", requested_port), Handler)
    ready.send(server.server_address[1])
    ready.close()
    server.serve_forever()


def call_verifier(port: int, payload: dict[str, Any]) -> bool:
    status, body = http_json(port, payload, timeout=2.0)
    return status == 200 and bool(body.get("accepted"))


def resource_process(topology: str, public_der: bytes, verifier_port: int, ready) -> None:
    public_key = decode_public_key(public_der)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            payload = read_json(self)
            try:
                if topology == "gateway_only":
                    accepted = bool(payload.get("gateway_verified"))
                elif topology == "service_local":
                    accepted = verify_payload(payload, public_key)
                elif topology == "shared_verifier":
                    accepted = call_verifier(verifier_port, payload)
                else:
                    accepted = bool(payload.get("gateway_verified")) and call_verifier(verifier_port, payload)
            except (OSError, urllib.error.URLError, TimeoutError):
                send_json(self, 503, {"executed": False, "reason": "verifier_unavailable"})
                return
            send_json(self, 200, {"executed": accepted, "reason": "executed" if accepted else "intent_mismatch"})

        def log_message(self, _format: str, *args: Any) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ready.send(server.server_address[1])
    ready.close()
    server.serve_forever()


def start_process(target, *args):
    parent, child = multiprocessing.Pipe(duplex=False)
    process = multiprocessing.Process(target=target, args=(*args, child), daemon=True)
    process.start()
    if not parent.poll(10):
        process.terminate()
        raise RuntimeError("child process did not become ready")
    return process, int(parent.recv())


def start_verifier(public_der: bytes, requested_port: int = 0):
    parent, child = multiprocessing.Pipe(duplex=False)
    process = multiprocessing.Process(target=verifier_process, args=(public_der, child, requested_port), daemon=True)
    process.start()
    if not parent.poll(10):
        process.terminate()
        raise RuntimeError("verifier did not become ready")
    return process, int(parent.recv())


def stop_process(process: multiprocessing.Process | None) -> None:
    if process is None:
        return
    process.terminate()
    process.join(timeout=5)
    if process.is_alive():
        process.kill()
        process.join(timeout=5)


def http_json(port: int, payload: dict[str, Any], timeout: float = 5.0) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/execute",
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def gateway_request(
    topology: str,
    resource_port: int,
    payload: dict[str, Any],
    public_key: ec.EllipticCurvePublicKey,
) -> tuple[int, dict[str, Any], float]:
    started = time.perf_counter_ns()
    outbound = dict(payload)
    if topology in ("gateway_only", "hybrid"):
        outbound["gateway_verified"] = verify_payload(payload, public_key)
        if not outbound["gateway_verified"]:
            return 200, {"executed": False, "reason": "gateway_intent_mismatch"}, (time.perf_counter_ns() - started) / 1_000_000
    status, body = http_json(resource_port, outbound)
    return status, body, (time.perf_counter_ns() - started) / 1_000_000


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
        f"# Track C2 Results: `{summary['run_id']}`",
        "",
        "| Topology | Workload | n | Median ms | IQR ms | P95 ms | P99 ms | Incorrect accept | Incorrect reject |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for cell in summary["normal_cells"]:
        latency = cell["latency"]
        lines.append(
            f"| {cell['topology']} | {cell['workload']} | {cell['n']} | {latency['median_ms']:.4f} | "
            f"{latency['iqr_ms']:.4f} | {latency['p95_ms']:.4f} | {latency['p99_ms']:.4f} | "
            f"{cell['incorrect_accepts']} | {cell['incorrect_rejects']} |"
        )
    lines += ["", "| Fault topology | Outage n | Failed closed | Executed | Detection P95 ms | Recovery ms | Recovered accepts |", "|---|---:|---:|---:|---:|---:|---:|"]
    for fault in summary["fault_cells"]:
        lines.append(
            f"| {fault['topology']} | {fault['outage_n']} | {fault['failed_closed']} | {fault['incorrect_executions']} | "
            f"{fault['detection_latency']['p95_ms']:.4f} | {fault['recovery_ms']:.4f} | {fault['recovered_accepts']} |"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--warmup", type=int, default=200)
    parser.add_argument("--samples-per-workload", type=int, default=2000)
    parser.add_argument("--outage-samples", type=int, default=200)
    parser.add_argument("--recovery-samples", type=int, default=200)
    parser.add_argument("--out-dir", default="experiments/track_c")
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    dirty = bool(git("status", "--porcelain"))
    if dirty and not args.allow_dirty:
        raise SystemExit("Track C2 confirmatory runs require a clean working tree")

    out_root = ROOT / args.out_dir
    raw_dir = out_root / "raw" / args.run_id
    manifest_path = out_root / "manifests" / f"{args.run_id}.json"
    summary_path = out_root / "analysis" / f"{args.run_id}-summary.json"
    table_path = out_root / "tables" / f"{args.run_id}.md"
    checksum_path = out_root / "analysis" / f"{args.run_id}-checksums.sha256"
    if any(path.exists() for path in (raw_dir, manifest_path, summary_path, table_path, checksum_path)):
        raise SystemExit(f"run ID already exists: {args.run_id}")

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    public_der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    manifest = {
        "run_id": args.run_id,
        "track": "C2",
        "repository_commit": git("rev-parse", "HEAD"),
        "tree_clean": not dirty,
        "repository_dirty": dirty,
        "topologies": list(TOPOLOGIES),
        "warmup": args.warmup,
        "samples_per_workload": args.samples_per_workload,
        "outage_samples": args.outage_samples,
        "recovery_samples": args.recovery_samples,
        "transport": "loopback HTTP with separate processes",
        "host": {"platform": platform.platform(), "machine": platform.machine(), "python": platform.python_version()},
        "runner_sha256": sha256_file(Path(__file__)),
        "preregistration_sha256": sha256_file(ROOT / "docs" / "experiments" / "track_c2_preregistration.md"),
    }
    write_json(manifest_path, manifest)

    normal_cells = []
    fault_cells = []
    all_rows = []
    next_index = 0
    for topology in TOPOLOGIES:
        verifier = None
        verifier_port = 0
        resource = None
        try:
            if topology in DEPENDENT_TOPOLOGIES:
                verifier, verifier_port = start_verifier(public_der)
            resource, resource_port = start_process(resource_process, topology, public_der, verifier_port)
            warmups = [build_request(next_index + i, True, private_key) for i in range(args.warmup)]
            next_index += args.warmup
            for payload in warmups:
                gateway_request(topology, resource_port, payload, public_key)

            for workload, legitimate in (("legitimate", True), ("semantic_mismatch", False)):
                payloads = [build_request(next_index + i, legitimate, private_key) for i in range(args.samples_per_workload)]
                next_index += args.samples_per_workload
                rows = []
                for sample, payload in enumerate(payloads):
                    status, body, latency_ms = gateway_request(topology, resource_port, payload, public_key)
                    executed = bool(body.get("executed"))
                    rows.append({"topology": topology, "workload": workload, "sample": sample, "status": status, "expected_accept": int(legitimate), "executed": int(executed), "latency_ms": latency_ms})
                incorrect_accepts = sum(int(row["executed"] and not row["expected_accept"]) for row in rows)
                incorrect_rejects = sum(int(not row["executed"] and row["expected_accept"]) for row in rows)
                if incorrect_accepts or incorrect_rejects or len(rows) != args.samples_per_workload:
                    raise RuntimeError(f"invalid normal cell: {topology}/{workload}")
                normal_cells.append({"topology": topology, "workload": workload, "n": len(rows), "incorrect_accepts": incorrect_accepts, "incorrect_rejects": incorrect_rejects, "latency": summarize([row["latency_ms"] for row in rows])})
                all_rows.extend(rows)

            if topology in DEPENDENT_TOPOLOGIES:
                old_port = verifier_port
                stop_process(verifier)
                verifier = None
                outage_payloads = [build_request(next_index + i, True, private_key) for i in range(args.outage_samples)]
                next_index += args.outage_samples
                outage_rows = []
                for sample, payload in enumerate(outage_payloads):
                    status, body, latency_ms = gateway_request(topology, resource_port, payload, public_key)
                    outage_rows.append({"topology": topology, "workload": "verifier_outage", "sample": sample, "status": status, "expected_accept": 0, "executed": int(bool(body.get("executed"))), "latency_ms": latency_ms})
                incorrect_executions = sum(row["executed"] for row in outage_rows)
                if incorrect_executions or len(outage_rows) != args.outage_samples:
                    raise RuntimeError(f"invalid outage cell: {topology}")

                recovery_started = time.perf_counter_ns()
                verifier, verifier_port = start_verifier(public_der, old_port)
                if verifier_port != old_port:
                    raise RuntimeError("verifier did not recover on its original endpoint")
                probe = build_request(next_index, True, private_key)
                next_index += 1
                probe_status, probe_body, _ = gateway_request(topology, resource_port, probe, public_key)
                recovery_ms = (time.perf_counter_ns() - recovery_started) / 1_000_000
                if probe_status != 200 or not probe_body.get("executed"):
                    raise RuntimeError(f"recovery probe failed: {topology}")
                recovered_payloads = [build_request(next_index + i, True, private_key) for i in range(args.recovery_samples)]
                next_index += args.recovery_samples
                recovered_accepts = 0
                for payload in recovered_payloads:
                    _status, body, _latency = gateway_request(topology, resource_port, payload, public_key)
                    recovered_accepts += int(bool(body.get("executed")))
                if recovered_accepts != args.recovery_samples:
                    raise RuntimeError(f"recovery confirmation failed: {topology}")
                fault_cells.append({"topology": topology, "outage_n": len(outage_rows), "failed_closed": len(outage_rows) - incorrect_executions, "incorrect_executions": incorrect_executions, "detection_latency": summarize([row["latency_ms"] for row in outage_rows]), "recovery_ms": recovery_ms, "recovered_accepts": recovered_accepts})
                all_rows.extend(outage_rows)
        finally:
            stop_process(resource)
            stop_process(verifier)

    write_csv(raw_dir / "distributed_trials.csv", all_rows)
    summary = {"run_id": args.run_id, "manifest": str(manifest_path.relative_to(ROOT)), "normal_cells": normal_cells, "fault_cells": fault_cells}
    write_json(summary_path, summary)
    write_table(table_path, summary)
    files = [manifest_path, summary_path, table_path, *sorted(raw_dir.rglob("*"))]
    checksum_path.parent.mkdir(parents=True, exist_ok=True)
    checksum_path.write_text("\n".join(f"{sha256_file(path)}  {path.relative_to(ROOT)}" for path in files if path.is_file()) + "\n", encoding="utf-8")
    print(json.dumps({"run_id": args.run_id, "normal_cells": len(normal_cells), "fault_cells": len(fault_cells)}, indent=2))


if __name__ == "__main__":
    multiprocessing.set_start_method("spawn")
    main()
