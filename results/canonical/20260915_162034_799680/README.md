# Latest canonical confirmation run

The current source is `run1/numbers.json`, generated on 2026-09-15 at 16:21:19 local time. This was one additional requested full run, not a retry selected for a favourable timing result. Its predecessor is `../20260915_052647_101641/run2/numbers.json`; all preceding data remain unchanged.

- Python audit, E1–E9 and C1: exit 0. EU DSS on the same PDFs: exit 0.
- Comparison with the predecessor: 389 selected invariants, 0 differences. Twelve size/offset fields exhibit expected drift within tolerance.
- E5 median A: 215.95945000444772 ms; median B: 196.99924999440555 ms. Difference B−A: -18.960200010042172 ms; independent-bootstrap 95% interval: [-45.59625000547385, 20.06950000213692] ms. Raw observations and analysis metadata are in the JSON. A always precedes B; the interval does not establish equivalence.
- E1 order-A inner offset: 6644 bytes. E2 order-A inner offset: 27850 bytes. Offsets are specific to this run, not constants of the construction.
- E7 still rejects one honest document; E9 still defeats several candidate rules. DSS undecidable cases and all original warnings are retained.

`numbers.pipeline.json` retains the pre-DSS record. `numbers.json` folds in same-run DSS without another signing pass. Logs and the acquisition manifest are preserved verbatim, including original local paths. Their presentation-output references describe the acquisition environment; no manuscript or presentation-generation code is included in this repository.

`SOURCE_CORRESPONDENCE.json` records AST correspondence between the public scientific modules and the acquisition snapshot, excluding the output-path module. Public `run_all.py` is the JSON-only runner. The acquisition manifest's git base and source hashes describe the original local environment, not an assertion that it was the present public checkout.

Run `python verify_canonical.py` at the repository root to check the preceding pair and this confirmation: compare invariants, replay statistics/bootstrap, verify byte-identical prefixes and read CMS identifiers. This is a read-only check, not another experiment. `python reproduce.py --with-dss --reference results/canonical/20260915_162034_799680/run1/numbers.json` performs a fresh experiment.

Only PDFs and public test certificates are included in the new artifact directories; newly generated private keys are excluded. Earlier public test artifacts are retained unchanged. See the root manifest for committed-file SHA-256 hashes.
