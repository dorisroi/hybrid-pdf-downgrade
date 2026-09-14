# Hybrid PDF Signature Experiments

Experimental code and test data for sequential ECDSA / ML-DSA-44 signatures
in PDF documents, including incremental-update truncation, signing order,
PAdES-B-LTA, and the limits of verifier rules.

## Reproduce the experiments

Install the pinned Python dependencies:

```powershell
pip install -r requirements.txt
python reproduce.py
python reproduce.py --with-dss
```

The DSS cross-check additionally requires JDK 17 and Maven.
The reproduction harness runs E1-E9, C1 and the cryptographic audit with fresh
test keys, checks results against `results/reference/`, and writes
`results/reproduce/<timestamp>/REVIEWER_REPORT.md` with PASS/FAIL/NOTE
verdicts and supporting evidence. It reads signature algorithm identifiers
from the PDFs and checks byte identity from the files on disk.
Inspect the report and exit status before treating a run as reproduced.

For Docker:

```sh
docker build -t hybridpdf-repro .
docker run --rm -v "$PWD/results/reproduce:/work/results/reproduce" hybridpdf-repro
```

`python run_all.py` runs the Python experiments alone. For a same-run DSS
cross-check, use `python reproduce.py --with-dss`: it validates the PDFs and
folds the DSS output in without signing the PDFs again. Do not use the cycle
`run_all -> run_dss -> run_all` as same-run evidence: the final invocation
creates new artifacts while retaining the preceding DSS measurements.

## Canonical measurement record

The current canonical record is
[`results/canonical/20260915_052647_101641/run2/numbers.json`](results/canonical/20260915_052647_101641/run2/numbers.json).
`run1` in the same directory is the independent replication. Run2 was selected
before the validation pair completed, not according to its timing result.
See [the evidence index](results/canonical/20260915_052647_101641/README.md)
for acquisition provenance, original logs, artifact hashes and limitations.
The older `results/numbers.json` and `results/reference/` are retained as
historical records; they are not the source of the current timing values.

```powershell
python verify_canonical.py
python -m unittest discover -s tests -v
python reproduce.py --with-dss --reference results/canonical/20260915_052647_101641/run2/numbers.json
```

The comparator checks 389 selected invariants, including E6-E9 and the
installed pyHanko version. Missing or `unknown` versions fail even if equal
on both sides. Timing samples and bootstrap metadata are recorded under
`E5.observations` and `E5.analysis`. The estimator is median(B)-median(A),
with independent within-order bootstrap resampling, not paired resampling.
A always precedes B; there is no randomisation or counterbalancing.
An interval containing zero does not establish equivalence.

## Experiments and scope

| Experiment | What is tested |
|---|---|
| E1 | Truncation of plain hybrid PDFs under both signing orders. |
| E2 | Truncation of PAdES-B-LTA files and survival of archival timestamps. |
| E3 | Appended forgery when the adversary holds the classical private key. |
| E4 | Require-PQ and modification-level rules on the original test corpus. |
| E5 | Signing-time and size measurements for the two signing orders. |
| E6 | Form filling, field creation and page-content replacement. |
| E7 | A rule based on the changed-form-field set, including false rejections. |
| E8 | Ordinary field-value stability across revisions. |
| E9 | Signature-field-name spoofing and appearance-only changes with unchanged field values. |
| C1 | An ECDSA-only control isolating the effect of the document structure. |

Acceptance on one corpus is not a general security guarantee. E6-E9 expose
limitations of the earlier rules: form edits can receive a benign modification
level; a changed-field rule can reject an honest form; value stability does
not imply appearance stability; and a signature-field name does not establish
which algorithm signed it. Algorithm identity must be checked together with
signature verification. The appearance check is evaluated on the supplied
cases, not presented as a complete rendered-content integrity guarantee.

The classical-key-compromise experiments supply a test ECDSA private key to
the adversary. They do not perform cryptanalysis or give it the ML-DSA key.
C1 uses an ECDSA stand-in named `RoleSimPQ`; it is not a post-quantum experiment.

## Repository layout

```text
reproduce.py              coordinated reproduction and evidence checks
run_all.py                experimental pipeline
compare_runs.py           comparison of selected invariants and size drift
src/hybridpdf/            test PKI, PDF signing, revisions and validation
src/audit/                cryptographic audit
src/experiments/          E1-E9
src/controls/             C1
results/numbers.json      structured experimental results
results/reference/       reference results for comparison
results/artifacts/       generated test PDFs, certificates and keys
results/reproduce/       per-run reports
dssval/                  Java harness for EU DSS
acrobat_eval/            Acrobat evaluation notes and screenshots
```

## Verification and test data

The cryptographic audit checks ML-DSA algorithm identity and signature
verification, including negative controls that corrupt signatures.
A failed audit blocks the experimental pipeline.

File sizes and hashes can change when fresh keys, certificates and signatures
are generated. Compare semantic results using the supplied checks, and inspect
byte-identity evidence for each decisive truncation rather than treating a
particular offset or file size as universal.

`results/artifacts/*_key.pem` are test keys generated by the experimental
PKI. Never use them as production credentials or trust anchors.

## Environment

The pinned environment uses Python 3.13 and pyHanko 0.37.0, with cryptography,
asn1crypto and ReportLab. See `requirements.txt` for exact Python package
versions and `dssval/pom.xml` for Java dependencies.
