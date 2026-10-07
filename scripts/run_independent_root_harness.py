#!/usr/bin/env python3
"""Independent-root commitment experiment (E6b).

The published commitment experiment injects a root's *output* and then checks
that a rule requiring agreement rejects two disagreeing reports. That measures
the comparison, not the sourcing, and it is close to definitional: both roots
read the same row in the same process, so a corrupted row corrupts both and
agreement could never have detected it.

This harness compromises a *source* instead and never injects a report. Root A
reads the primary store. Root B is a separate OS process reading its own
append-only referent journal. Three arms:

  independent   Rewrite the beneficiary row in the primary store only. Root A
                reports the attacker's account number, Root B reconstructs the
                approved one from its journal, the digests differ, and the gate
                refuses. Each trial is paired with an uncorrupted control that
                must be accepted, so refusal is attributable to disagreement
                rather than to the gate rejecting everything.

  shared        The same corruption with Root B pointed at the primary store,
                standing for roots that share an upstream. One corrupted row
                now yields agreeing reports and the gate accepts. This arm is
                expected to fail, and is the point: it measures the boundary
                the manuscript previously only asserted.

  mutation      Harness controls. A forced-agreement gate must show 100% false
                acceptance and a forced-disagreement gate 100% false rejection,
                demonstrating this harness can report its own failure.

Decisions are gate-level: no signatures are obtained and no protected operation
executes. Latency is the gate call, including the loopback request to Root B,
and is a cost figure rather than an end-to-end authorization measurement.
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
ROOT_B_HOST = "127.0.0.1"


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def free_port() -> int:
    with contextlib.closing(socket.socket()) as sock:
        sock.bind((ROOT_B_HOST, 0))
        return sock.getsockname()[1]


def median(values: List[float]) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


class RootBProcess:
    """Root B, started as a genuinely separate OS process."""

    def __init__(self, *, port: int, source: str, journal_path: Path, db_path: Path):
        self.port = port
        self.source = source
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO_ROOT)
        env["POIA_REFERENT_JOURNAL_ENABLED"] = "true"
        env["POIA_REFERENT_JOURNAL_PATH"] = str(journal_path)
        env["POIA_DB_PATH"] = str(db_path)
        if source == "primary":
            env["POIA_ROOT_B_ALLOW_PRIMARY"] = "true"
        self._env = env
        self._proc: Optional[subprocess.Popen] = None

    def __enter__(self) -> "RootBProcess":
        self._proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "app.root_b_service",
                "--host",
                ROOT_B_HOST,
                "--port",
                str(self.port),
                "--source",
                self.source,
            ],
            cwd=str(REPO_ROOT),
            env=self._env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.time() + 15.0
        while time.time() < deadline:
            if self._proc.poll() is not None:
                _, err = self._proc.communicate()
                raise RuntimeError(f"Root B exited: {err.decode(errors='replace')[:500]}")
            try:
                with contextlib.closing(socket.create_connection((ROOT_B_HOST, self.port), 0.25)):
                    return self
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("Root B did not become reachable")

    def __exit__(self, *exc) -> None:
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    @property
    def pid(self) -> Optional[int]:
        return self._proc.pid if self._proc is not None else None


def make_beneficiary(db_module, journal, user_id: int, index: int) -> Dict[str, Any]:
    """Create a beneficiary in the primary store and journal its content, as the
    application does on a beneficiary_add."""
    honest_account = f"{700000 + index}"
    with db_module.db_connect() as conn:
        beneficiary_id = conn.execute(
            "INSERT INTO beneficiaries (user_id, name, bank, account_number, version, updated_at, created_at) "
            "VALUES (?, ?, ?, ?, 1, ?, ?)",
            (user_id, f"Approved Payee {index}", "Origin Bank", honest_account,
             int(time.time()), int(time.time())),
        ).lastrowid
        journal.record_beneficiary(conn, beneficiary_id)
    return {"id": beneficiary_id, "account_number": honest_account}


def corrupt_primary(db_module, beneficiary_id: int, index: int) -> str:
    """Rewrite the primary row in place: a compromised source, not an injected
    report. The version is deliberately left alone so this is a commitment-time
    compromise rather than something the execution-time referent check would
    catch on version alone."""
    attacker_account = f"ATTACKER-{index}"
    with db_module.db_connect() as conn:
        conn.execute(
            "UPDATE beneficiaries SET account_number = ? WHERE id = ?",
            (attacker_account, beneficiary_id),
        )
    return attacker_account


def run_sourcing_arm(*, arm: str, trials: int, db_module, journal, cc_module,
                     journal_path: Path, db_path: Path) -> Dict[str, Any]:
    source = "journal" if arm == "independent" else "primary"
    port = free_port()
    rows: List[Dict[str, Any]] = []
    attack_accepted = 0
    control_accepted = 0
    reasons: Dict[str, int] = {}
    latencies: List[float] = []
    control_latencies: List[float] = []

    with db_module.db_connect() as conn:
        user_id = conn.execute(
            "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)",
            (f"e6b-{arm}-{os.getpid()}@example.invalid", "unused", int(time.time())),
        ).lastrowid

    with RootBProcess(port=port, source=source, journal_path=journal_path, db_path=db_path) as root_b:
        cc_module.KOFN_ENABLED = True
        cc_module.KOFN_ROOT_B_MODE = "service"
        cc_module.KOFN_ROOT_B_URL = f"http://{ROOT_B_HOST}:{port}"

        for index in range(trials):
            # Paired control first: nothing corrupted, the roots must agree.
            control = make_beneficiary(db_module, journal, user_id, 10_000_000 + index)
            control_scope = {
                "from_account": 0, "amount": 250.0, "currency": "USD",
                "beneficiary_id": control["id"],
            }
            context = {"rp_id": "poia-demo-bank"}
            started = time.perf_counter()
            control_reason = cc_module.confine_commitment(
                action="transfer", scope=control_scope, context=context
            )
            control_latencies.append((time.perf_counter() - started) * 1000.0)
            if control_reason is None:
                control_accepted += 1

            # Attack: corrupt the primary source only.
            target = make_beneficiary(db_module, journal, user_id, index)
            attacker_account = corrupt_primary(db_module, target["id"], index)
            scope = {
                "from_account": 0, "amount": 250.0, "currency": "USD",
                "beneficiary_id": target["id"],
            }
            started = time.perf_counter()
            reason = cc_module.confine_commitment(
                action="transfer", scope=scope, context=context
            )
            latencies.append((time.perf_counter() - started) * 1000.0)
            if reason is None:
                attack_accepted += 1
            else:
                reasons[reason] = reasons.get(reason, 0) + 1

            rows.append({
                "trial": index,
                "arm": arm,
                "root_b_source": source,
                "root_b_pid": root_b.pid,
                "honest_account_number": target["account_number"],
                "primary_store_account_number_after_compromise": attacker_account,
                "attack_decision": "accept" if reason is None else "reject",
                "attack_reason": reason or "",
                "paired_control_decision": "accept" if control_reason is None else "reject",
                "paired_control_reason": control_reason or "",
            })

    return {
        "arm": arm,
        "root_b_source": source,
        "root_b_separate_process": True,
        "attempts": trials,
        "attack_acceptance_rate": attack_accepted / trials,
        "paired_control_acceptance_rate": control_accepted / trials,
        "rejection_reasons": reasons,
        "median_gate_latency_ms_attack": median(latencies),
        "median_gate_latency_ms_control": median(control_latencies),
        "rows": rows,
    }


def run_cost_arm(*, trials: int, db_module, journal, cc_module,
                 journal_path: Path, db_path: Path, repetitions: int = 3) -> Dict[str, Any]:
    """Cost of the gate in each root configuration, measured in one harness.

    Both configurations are timed on the same uncorrupted commitments, which is
    the steady-state path: the gate consults both roots and accepts. Timing them
    here rather than against the published injected-report experiment matters,
    because that experiment overrides Root A's output and so skips its database
    read -- subtracting its median from a cross-process median would compare
    different work.
    """
    rep_inprocess: List[float] = []
    rep_service: List[float] = []
    accepted = {"inprocess": 0, "service": 0}
    expected = trials * repetitions

    with db_module.db_connect() as conn:
        user_id = conn.execute(
            "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)",
            (f"e6b-cost-{os.getpid()}@example.invalid", "unused", int(time.time())),
        ).lastrowid

    for repetition in range(repetitions):
      port = free_port()
      inprocess_ms: List[float] = []
      service_ms: List[float] = []
      with RootBProcess(port=port, source="journal", journal_path=journal_path, db_path=db_path):
        cc_module.KOFN_ENABLED = True
        for index in range(trials):
            target = make_beneficiary(db_module, journal, user_id,
                                      30_000_000 + repetition * 1_000_000 + index)
            scope = {"from_account": 0, "amount": 250.0, "currency": "USD",
                     "beneficiary_id": target["id"]}
            context = {"rp_id": "poia-demo-bank"}

            cc_module.KOFN_ROOT_B_MODE = "inprocess"
            started = time.perf_counter()
            reason = cc_module.confine_commitment(action="transfer", scope=scope, context=context)
            inprocess_ms.append((time.perf_counter() - started) * 1000.0)
            if reason is None:
                accepted["inprocess"] += 1

            cc_module.KOFN_ROOT_B_MODE = "service"
            cc_module.KOFN_ROOT_B_URL = f"http://{ROOT_B_HOST}:{port}"
            started = time.perf_counter()
            reason = cc_module.confine_commitment(action="transfer", scope=scope, context=context)
            service_ms.append((time.perf_counter() - started) * 1000.0)
            if reason is None:
                accepted["service"] += 1
      rep_inprocess.append(median(inprocess_ms))
      rep_service.append(median(service_ms))

    return {
        "trials_per_repetition": trials,
        "repetitions": repetitions,
        "measured_on": "uncorrupted commitments, both configurations accepted",
        "both_configurations_accepted": accepted["inprocess"] == expected and accepted["service"] == expected,
        "median_gate_latency_ms_inprocess": median(rep_inprocess),
        "median_gate_latency_ms_separate_process": median(rep_service),
        "per_repetition_median_ms_inprocess": [round(v, 3) for v in rep_inprocess],
        "per_repetition_median_ms_separate_process": [round(v, 3) for v in rep_service],
    }


def run_mutation_controls(*, trials: int, db_module, journal, cc_module,
                          journal_path: Path, db_path: Path) -> Dict[str, Any]:
    """Break the gate deliberately and confirm the harness notices."""
    port = free_port()
    results: Dict[str, Any] = {}
    original_digest = cc_module._digest

    with db_module.db_connect() as conn:
        user_id = conn.execute(
            "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?, ?, 0, ?)",
            (f"e6b-mutation-{os.getpid()}@example.invalid", "unused", int(time.time())),
        ).lastrowid

    with RootBProcess(port=port, source="journal", journal_path=journal_path, db_path=db_path):
        cc_module.KOFN_ENABLED = True
        cc_module.KOFN_ROOT_B_MODE = "service"
        cc_module.KOFN_ROOT_B_URL = f"http://{ROOT_B_HOST}:{port}"

        for label, stub in (
            ("forced_agreement", lambda canonical: "identical"),
            ("forced_disagreement", lambda canonical, _c=[0]: f"unique-{_c.append(1) or len(_c)}"),
        ):
            cc_module._digest = stub
            accepted = 0
            try:
                for index in range(trials):
                    target = make_beneficiary(db_module, journal, user_id, 20_000_000 + index)
                    corrupt_primary(db_module, target["id"], index)
                    reason = cc_module.confine_commitment(
                        action="transfer",
                        scope={"from_account": 0, "amount": 250.0, "currency": "USD",
                               "beneficiary_id": target["id"]},
                        context={"rp_id": "poia-demo-bank"},
                    )
                    if reason is None:
                        accepted += 1
            finally:
                cc_module._digest = original_digest
            results[label] = {
                "attempts": trials,
                "acceptance_rate": accepted / trials,
                "expected_acceptance_rate": 1.0 if label == "forced_agreement" else 0.0,
            }

    # Root B taken offline: the gate must fail closed rather than fall back to A.
    cc_module.KOFN_ROOT_B_URL = f"http://{ROOT_B_HOST}:{free_port()}"
    offline_reason = cc_module.confine_commitment(
        action="transfer",
        scope={"from_account": 0, "amount": 250.0, "currency": "USD", "beneficiary_id": 1},
        context={"rp_id": "poia-demo-bank"},
    )
    results["root_b_offline"] = {
        "decision": "accept" if offline_reason is None else "reject",
        "reason": offline_reason or "",
        "fails_closed": offline_reason is not None,
    }
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Independent-root commitment experiment: source compromise, not output injection."
    )
    parser.add_argument("--trials", type=int, default=300)
    parser.add_argument("--mutation-trials", type=int, default=50)
    parser.add_argument("--out-dir", type=str, default="experiments/independent_root")
    args = parser.parse_args()

    import tempfile

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "bank.db"
        journal_path = Path(tmp) / "referent_journal.db"
        os.environ["POIA_REFERENT_JOURNAL_ENABLED"] = "true"
        os.environ["POIA_REFERENT_JOURNAL_PATH"] = str(journal_path)
        os.environ["POIA_DB_PATH"] = str(db_path)

        sys.path.insert(0, str(REPO_ROOT))
        from app import commitment_confinement as cc_module
        from app import db as db_module
        from app import referent_journal as journal

        db_module.DB_PATH = db_path
        journal.JOURNAL_ENABLED = True
        journal.JOURNAL_PATH = journal_path
        db_module.init_db()
        journal.init_journal()

        independent = run_sourcing_arm(
            arm="independent", trials=args.trials, db_module=db_module, journal=journal,
            cc_module=cc_module, journal_path=journal_path, db_path=db_path,
        )
        shared = run_sourcing_arm(
            arm="shared", trials=args.trials, db_module=db_module, journal=journal,
            cc_module=cc_module, journal_path=journal_path, db_path=db_path,
        )
        cost = run_cost_arm(
            trials=args.trials, db_module=db_module, journal=journal,
            cc_module=cc_module, journal_path=journal_path, db_path=db_path,
        )
        mutations = run_mutation_controls(
            trials=args.mutation_trials, db_module=db_module, journal=journal,
            cc_module=cc_module, journal_path=journal_path, db_path=db_path,
        )

    write_csv(out_dir / "independent_root_trials.csv", independent.pop("rows"))
    write_csv(out_dir / "shared_dependency_trials.csv", shared.pop("rows"))
    summary = {
        "generated_at": int(time.time()),
        "python": sys.version.split()[0],
        "evidence_level": "gate-level: no signatures obtained, no protected operation executed",
        "compromise_model": "primary store row rewritten; no root output injected",
        "independent_sourcing_arm": independent,
        "shared_dependency_arm": shared,
        "gate_cost_by_configuration": cost,
        "harness_controls": mutations,
    }
    write_json(out_dir / "independent_root_summary.json", summary)

    lines = [
        "| Arm | Root B source | Attempts | Attack acceptance | Paired control acceptance | Median gate latency (ms) |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for result in (independent, shared):
        lines.append(
            f"| {result['arm']} | {result['root_b_source']} | {result['attempts']} | "
            f"{result['attack_acceptance_rate'] * 100:.1f}% | "
            f"{result['paired_control_acceptance_rate'] * 100:.1f}% | "
            f"{result['median_gate_latency_ms_attack']:.3f} |"
        )
    (out_dir / "independent_root_table.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
