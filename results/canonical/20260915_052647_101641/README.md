# Frozen canonical pair

`run2/numbers.json` is the canonical result; `run1/numbers.json` is the independent replication. Run2 was selected before the pair completed, not by its timing outcome. This record supersedes the root timing record as the source to quote; older files are preserved, not rewritten.

Both Python runs and both EU DSS passes exited zero. DSS operated on each run's own PDFs. `numbers.pipeline.json` is the unmodified pre-DSS output; `numbers.json` folds in same-run DSS output and records the fold in metadata. The raw `run_all.log`, `dss_console.log`, and DSS reports are retained. The logs are acquisition evidence, including warnings, not cleaned summaries.

The strict comparator checks 389 selected invariants with zero differences between the pair. Eight size/offset fields drift within tolerance; timing is not expected to be numerically equal. E5 stores 40 A-then-B blocks, independent-bootstrap metadata and raw measurements. Run2 has median(B)-median(A) = -15.44669999202597 ms and 95% interval [-74.46300000447081, 25.477999999566237] ms. This does not establish equivalence.

E7 still rejects one honest case; E9 still defeats several rules. The missing changed-field-set warning remains in the raw logs. DSS undecidable cases are not converted to acceptance. `independent_checks.json` contains the original read-back checks. Run `python verify_canonical.py` from the repository root to replay statistics and verify prefix bytes and CMS identifiers without creating signatures.

## Acquisition and source correspondence

The pair was acquired in an isolated local orchestration workspace. `execution_manifest.json` records that acquisition's original source hashes, local paths, git base plus working source, environment and exit codes; it is not a claim that its git base identifies the present public checkout. It is retained verbatim. Local acquisition orchestration also had presentation-output code; that code and its generated documents are not part of this experiment-only repository. We have not rewritten acquisition logs to conceal the distinction.

`SOURCE_CORRESPONDENCE.json` records an AST comparison of the public experimental/audit/control/cryptographic modules with the acquisition snapshot. Their executable ASTs match; `src/hybridpdf/paths.py` is deliberately excluded because the public package has experimental output paths only. Public `run_all.py` is an experimental JSON runner; it does not produce a manuscript. The scientific computations and decision rules are unchanged. `compare_runs.py` adds strict version validation; tests cover single-verdict mutations in E6-E9. `verify_canonical.py` is an additional read-only verifier, not the acquisition script.

PDFs and public test certificates are included. Newly acquired private test keys are not included; reproduction creates fresh keys. Previously published test artifacts remain historical. The canonical record contains no manuscript or TeX source. No assertion is made that raw timing is portable across machines, or that a successful invariant comparison proves universal security.
