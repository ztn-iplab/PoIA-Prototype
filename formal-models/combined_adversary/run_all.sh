#!/bin/sh
# Reproduce the combined-adversary results (Tamarin 1.12.0, Maude 3.5.1).
set -u
for f in composition_two_action composition_two_action_no_agreement composition_one_action_no_rsi composition_three_action composition_two_action_fresh_mutation_no_agreement; do
  echo "== $f"; tamarin-prover --prove "$f.spthy" > "$f.log" 2>&1
  sed -n '/summary of summaries/,$p' "$f.log" | grep -E "processing time|exists-trace|all-traces"
done
