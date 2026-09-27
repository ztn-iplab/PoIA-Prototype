#!/usr/bin/env python3
"""Reproduce the atomic-binding proofs and guard-removal negative controls."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = "4d823a783a57c80725adba0be2cf0f1fcb634ccf"
MODEL = ROOT / "formal-models/atomic_referent_binding.spthy"
PRIMARY = ("executable", "single_execution", "causal_authorization", "no_execution_after_version_change")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def rules(source):
    return {m[1]: m[2] for m in re.finditer(r"rule (\w+):([\s\S]*?)(?=\nrule |\nlemma |\nend)", source)}


def formula(source, name):
    match = re.search(r"lemma " + name + r"(?:\s*\[[^]]*\])?:\s*(exists-trace\s*)?\"([^\"]*)\"", source)
    if not match:
        raise ValueError(f"Missing formula: {name}")
    return (bool(match[1]), re.sub(r"\s+", "", match[2]))


def audit_extension(source, reference):
    """Check this theory's simple rule syntax, not arbitrary Tamarin syntax."""
    require(not re.search(r"^\s*(restriction|equations|functions)\b", source, re.M), "Unexpected semantic declaration")
    require(re.search(r"builtins:([^\n]+)", source)[1] == re.search(r"builtins:([^\n]+)", reference)[1], "Changed algebra")
    old, new = rules(reference), rules(source)
    require(old.keys() == new.keys(), "Changed rule set")
    for name, body in old.items():
        original = re.findall(r"\[([^]]*)\]", body)
        updated = re.findall(r"\[([^]]*)\]", new[name])
        for a, b in ((original[0], updated[0]), (original[-1], updated[-1])):
            require(re.sub(r"\s+", "", a) == re.sub(r"\s+", "", b), f"Changed rule state: {name}")
        if len(original) == 3:
            require(re.sub(r"\s+", "", original[1]) in re.sub(r"\s+", "", updated[1]), f"Changed original event: {name}")
    for name in PRIMARY:
        require(formula(source, name) == formula(reference, name), f"Changed formula: {name}")


def run(theory, certificate, log, extra, timeout, *, prove=True):
    command = ["tamarin-prover", str(theory), *(["--prove"] if prove else []), "--quit-on-warning",
               f"--oraclename={ROOT / 'formal-models/oracle'}", f"--output={certificate}", *extra]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    output = result.stdout + result.stderr
    log.write_text(output)
    if result.returncode:
        raise RuntimeError(f"Tamarin failed; see {log}")
    summary = output.split("summary of summaries:")[-1]
    outcomes = dict(re.findall(r"^\s*(\w+) \((?:all-traces|exists-trace)\): (verified|falsified|analysis incomplete)", summary, re.M))
    print(json.dumps({"theory": theory.name, "outcomes": outcomes}), flush=True)
    return {"command": command, "outcomes": outcomes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "formal-models/proofs")
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    source = MODEL.read_text()
    reference = subprocess.check_output(["git", "show", f"{REFERENCE}:formal-models/atomic_referent_binding.spthy"], cwd=ROOT, text=True)
    audit_extension(source, reference)
    (out / "reference_model.spthy").write_text(reference)
    certificate = out / "atomic_referent_binding_verified.spthy"
    results = [run(MODEL, certificate, out / "verification.log", ["--bound=10"], args.timeout)]
    expected = set(re.findall(r"^lemma (\w+)", source, re.M))
    require(set(results[0]["outcomes"]) == expected, "Missing lemma result")
    require(set(results[0]["outcomes"].values()) == {"verified"}, "Incomplete positive proof")
    # Recheck the completed certificate without a proof-search depth bound.
    results.append(run(certificate, out / "certificate_rechecked.spthy", out / "certificate_recheck.log", [], args.timeout, prove=False))
    require(results[1]["outcomes"] == results[0]["outcomes"], "Certificate replay differs")
    rule_prefix = source.split("\nlemma ")[0]
    execute = rules(source)["Execute"]
    controls = {
        "without_signature": ("causal_authorization", execute.replace(",\n    In(sign(<u,n,a,r,v,h(c)>,sk))", "")),
        "without_current_version": ("no_execution_after_version_change", execute.replace(", Current(r,v)", "").replace("-> [ Current(r,v) ]", "-> [ ]")),
    }
    for label, (target, replacement) in controls.items():
        require(replacement != execute, "Negative control did not remove its guard")
        # No reusable helper is imported into an intentionally broken model.
        mutant = rule_prefix.replace(execute, replacement).replace("theory Atomic_Referent_Binding begin", f"theory {label} begin")
        match = re.search(r"lemma " + target + r"[^:]*:\s*\"([^\"]*)\"", source)
        mutant += f'\nlemma {target}:\n  "{match[1]}"\nend\n'
        path = out / f"{label}.spthy"
        path.write_text(mutant)
        result = run(path, out / f"{label}_counterexample.spthy", out / f"{label}.log",
                     ["--bound=20", "--stop-on-trace=BFS"], args.timeout)
        require(result["outcomes"] == {target: "falsified"}, f"Negative control did not falsify {target}")
        results.append(result)
    files = [MODEL, ROOT / "formal-models/oracle", Path(__file__), *out.glob("*.spthy"), *out.glob("*.log")]
    manifest = {"reference_commit": REFERENCE, "rule_premises_and_conclusions_unchanged": True,
                "original_four_formulas_unchanged": True, "attacker_restrictions_added": False,
                "results": results, "sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files if p.is_relative_to(ROOT)}}
    (out / "verification_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
