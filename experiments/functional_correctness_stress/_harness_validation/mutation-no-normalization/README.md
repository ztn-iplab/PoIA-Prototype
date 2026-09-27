# Harness validation: no-normalization mutation

Validity control for `scripts/measure_functional_correctness.py`. The comparison
canonicalizer is stripped of NFC and numeric normalization, so canonically
equivalent inputs must be wrongly rejected. The experiment is otherwise
unmodified. A non-zero exit is the pass condition: it shows the correctness
harness reports failure when the system under test is broken.

## Command

    POIA_FC_MUTATION=no_normalization python3 \
      scripts/_functional_correctness_mutation_wrapper.py --trials 200

## Result

Exit status 1. 400 false rejections of 600 valid cases (FRR 66.6667%), 0 false
acceptances. The 400 are exactly the two canonical-equivalence categories,
`canonical_equivalent_numeric` and `canonical_equivalent_unicode`, 200 each;
`exact_valid_match` and all six reject categories were unaffected.

Environment: Linux aarch64, CPython 3.10.12, dependencies from
`requirements.txt`. Seed 20260910, as in the unmutated run.
