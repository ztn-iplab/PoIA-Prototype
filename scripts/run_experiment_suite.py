#!/usr/bin/env python3
import argparse
import datetime as dt
import shlex
import subprocess
import sys
from pathlib import Path


def run_cmd(cmd: list[str], cwd: Path, stdout_file: Path | None = None) -> None:
    text = f"$ {' '.join(shlex.quote(part) for part in cmd)}"
    print(text)
    result = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    if stdout_file:
        stdout_file.write_text(result.stdout, encoding="utf-8")
    if result.returncode != 0:
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        raise SystemExit(result.returncode)
    if result.stdout:
        print(result.stdout.rstrip())


def main() -> None:
    parser = argparse.ArgumentParser(description="Run PoIA research experiment suite end-to-end.")
    parser.add_argument("--base-url", default="https://poia.local")
    parser.add_argument("--db-path", default=".tmp_bank.db")
    parser.add_argument("--poia-csv", default="app/data/poia_experiments.csv")
    parser.add_argument("--user-id", type=int, default=1)
    parser.add_argument("--rp-id", default="poia-demo-bank")
    parser.add_argument("--secret", default="change-me-in-prod")
    parser.add_argument("--trials", type=int, default=30)
    parser.add_argument("--sleep", type=float, default=0.1)
    parser.add_argument("--timeout", type=float, default=12.0)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--pause-ms", type=float, default=0.0)
    parser.add_argument("--out-dir", default="experiments")
    parser.add_argument("--run-name", help="Optional explicit run folder name")
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    scripts_dir = Path(__file__).resolve().parent
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_name = args.run_name or f"poia_run_{timestamp}"
    run_dir = root / args.out_dir / run_name
    run_dir.mkdir(parents=True, exist_ok=True)

    baseline_attack_json = run_dir / "baseline_attack.json"
    poia_attack_json = run_dir / "poia_attack.json"
    baseline_latency_json = run_dir / "baseline_latency.json"
    poia_analysis_txt = run_dir / "poia_analysis.txt"
    attack_comparison_csv = run_dir / "attack_comparison.csv"
    summary_md = run_dir / "SUMMARY.md"
    aggregate_json = run_dir / "aggregate_metrics.json"

    insecure_flag = ["--insecure"] if args.insecure else []

    run_cmd(
        [
            sys.executable,
            str(scripts_dir / "run_attack_baseline.py"),
            "--base-url",
            args.base_url,
            "--user-id",
            str(args.user_id),
            "--rp-id",
            args.rp_id,
            "--trials",
            str(args.trials),
            "--sleep",
            str(args.sleep),
            "--timeout",
            str(args.timeout),
            "--retries",
            str(args.retries),
            "--continue-on-error",
            "--output",
            str(baseline_attack_json),
            *insecure_flag,
        ],
        cwd=root,
    )

    run_cmd(
        [
            sys.executable,
            str(scripts_dir / "run_poia_scenarios.py"),
            "--base-url",
            args.base_url,
            "--user-id",
            str(args.user_id),
            "--rp-id",
            args.rp_id,
            "--trials",
            str(args.trials),
            "--sleep",
            str(args.sleep),
            "--timeout",
            str(args.timeout),
            "--retries",
            str(args.retries),
            "--continue-on-error",
            "--output",
            str(poia_attack_json),
            *insecure_flag,
        ],
        cwd=root,
    )

    run_cmd(
        [
            sys.executable,
            str(scripts_dir / "measure_baseline.py"),
            "--base-url",
            args.base_url,
            "--db-path",
            str((root / args.db_path).resolve()),
            "--user-id",
            str(args.user_id),
            "--secret",
            args.secret,
            "--trials",
            str(args.trials),
            "--warmup",
            str(args.warmup),
            "--pause-ms",
            str(args.pause_ms),
            "--timeout",
            str(args.timeout),
            "--retries",
            str(args.retries),
            "--output",
            str(baseline_latency_json),
            *insecure_flag,
        ],
        cwd=root,
    )

    run_cmd(
        [
            sys.executable,
            str(scripts_dir / "analyze_poia_metrics.py"),
            "--poia",
            str((root / args.poia_csv).resolve()),
            "--poia-attack-json",
            str(poia_attack_json),
            "--baseline-attack-json",
            str(baseline_attack_json),
            "--baseline-latency-json",
            str(baseline_latency_json),
            "--run-folder",
            str(run_dir.resolve()),
            "--out-json",
            str(aggregate_json),
            "--out-csv",
            str(attack_comparison_csv),
            "--out-md",
            str(summary_md),
        ],
        cwd=root,
        stdout_file=poia_analysis_txt,
    )

    print("\nGenerated artifacts:")
    print(f"- {baseline_attack_json}")
    print(f"- {poia_attack_json}")
    print(f"- {baseline_latency_json}")
    print(f"- {poia_analysis_txt}")
    print(f"- {attack_comparison_csv}")
    print(f"- {summary_md}")
    print(f"- {aggregate_json}")


if __name__ == "__main__":
    main()
