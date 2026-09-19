# Hybrid PDF Signature Experiments

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22806085.svg)](https://doi.org/10.5281/zenodo.22806085)

**Data used in the paper:**
[`results/canonical/20260915_162034_799680/run1/numbers.json`](results/canonical/20260915_162034_799680/run1/numbers.json).
Historical records and newly generated `results/numbers.json` are not the
source of the reported measurements. The corresponding
[comparison report](results/canonical/20260915_162034_799680/compare_canonical.txt)
checks **389 selected invariants, with 0 differences**.

Experimental code and test data for sequential ECDSA / ML-DSA-44 signatures
in PDF documents, including incremental-update truncation, signing order,
PAdES-B-LTA, and the limits of verifier rules.

## Reproduce the experiments

Use Python 3.13 in a virtual environment and install the pinned dependencies
with that same interpreter (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -c "from importlib.metadata import version; from cryptography.hazmat.primitives.asymmetric import mldsa; print(version('cryptography'))"
.\.venv\Scripts\python verify_canonical.py
```

The pin is `cryptography==50.0.1`, which provides the ML-DSA API used here.
The import check should print `50.0.1`. If it fails, check the installation
and interpreter before attempting reproduction. Even `verify_canonical.py`
imports experimental helpers that depend on this API. This check replays
stored evidence; it does not sign new PDFs.

To run fresh experiments with a same-run DSS cross-check:

```powershell
.\.venv\Scripts\python reproduce.py --with-dss --reference results/canonical/20260915_162034_799680/run1/numbers.json
```

Commands below using `python` assume this interpreter or an activated venv.

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
[`results/canonical/20260915_162034_799680/run1/numbers.json`](results/canonical/20260915_162034_799680/run1/numbers.json).
This is one additional confirmation run, not a timing-selected retry. It
agrees on 389 selected invariants with the preceding independent run
`20260915_052647_101641/run2`. The preceding pair is retained in full.
See [the evidence index](results/canonical/20260915_162034_799680/README.md)
for acquisition provenance, original logs, artifact hashes and limitations.
The old root records are retained unchanged as
`results/numbers_legacy_20260913.json` and
`results/compare_report_legacy_20260913.txt` (the latter checks 141 invariants).
`results/reference/` also remains a historical baseline. None is the source
of the current timing values. A fresh pipeline run still writes
`results/numbers.json`; this is replaceable run output, not the frozen source
used in the paper. `reproduce.py` without `--reference` uses the historical
baseline; use the explicit canonical argument above for the current source.
`--freeze-reference` requires an existing freshly generated `results/numbers.json`.

```powershell
python verify_canonical.py
python -m unittest discover -s tests -v
python reproduce.py --with-dss --reference results/canonical/20260915_162034_799680/run1/numbers.json
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
results/numbers.json      generated by a fresh run; not the frozen source
results/*_legacy_*        preserved historical root records
results/canonical/       frozen records, including the current source
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

## How to cite

Cite both the artifact and the paper it accompanies. The concept DOI
[10.5281/zenodo.22806085](https://doi.org/10.5281/zenodo.22806085) always
resolves to the latest version; cite a version DOI instead when you need to
pin the exact record you used.

```
Đinh, T. T., & Lê, P. Đ. hybrid-pdf-downgrade: downgrade attack on hybrid
PDF signatures. Zenodo. https://doi.org/10.5281/zenodo.22806085
```

Machine-readable metadata is in `CITATION.cff`; the metadata deposited with
each release is in `.zenodo.json`.
