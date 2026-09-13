# Put the Post-Quantum Signature First

Artifact for *"Put the Post-Quantum Signature First: Format-Layer Downgrade
Resistance in Sequential Hybrid PDF Signing"*.

## Reproduce in one command

```
python reproduce.py --with-dss     # or: make reproduce-dss
python reproduce.py                # without the DSS cross-check (no JDK needed)
docker build -t hybridpdf-repro . && \
  docker run --rm -v "$PWD/results/reproduce:/work/results/reproduce" hybridpdf-repro
```

This regenerates E1-E9, C1 and the audit with fresh keys, re-validates the new
artifacts with DSS 6.5 (with `--with-dss`), compares every invariant against
`results/reference/` (the run the paper was built from), and writes
`results/reproduce/<timestamp>/REVIEWER_REPORT.md`: one PASS/FAIL/NOTE verdict
per reviewer question, with evidence from the run. The ML-DSA OIDs are read
back from the PDFs and byte identity is re-hashed from the files on disk, not
taken from the pipeline's own records. Exit status is 0 only if everything
reproduced.

The individual steps, for reference:

```
python run_all.py     # 1. all experiments, pure Python (~25 s)
.\run_dss.ps1         # 2. independent cross-check with EU DSS 6.5 (needs JDK 17)
python run_all.py     # 3. fold the DSS figures into numbers.tex
```

Step 2 is separate on purpose: `run_all.py` must stay runnable without a JDK.
If step 2 has never run, the DSS macros render as a loud `??` in the PDF rather
than silently carrying a stale number.

It runs five experiments E1--E5 plus the C1 control, writes the complete record to
`results/numbers.json`, and regenerates `paper/generated/numbers.tex`, which the
paper `\input`s. The paper cites `\eOneDiscarded`, never a hand-typed `22,958`.

## Why the indirection

Earlier revisions kept one self-contained script per experiment and copied
figures into the `.tex` by hand. Three numbers went wrong that way, and the
errors were only visible by re-reading the scripts:

- a boundary count measured on the **archival** document was quoted in a table
  describing the **plain** one;
- byte figures from a run where *both* layers were ECDSA were quoted under a
  description claiming a genuine ML-DSA signer and a test root CA;
- absolute file sizes were quoted as if stable, though DER-encoded ECDSA
  signatures vary in length and sizes drift a few bytes per run.

A generated macro cannot be copied from the wrong experiment. Byte **identity**,
which is what the claims actually rest on, does not drift; each decisive
artifact is additionally pinned by SHA-256 in `results/numbers.json`.

## Layout

```
run_all.py               the whole pipeline
src/hybridpdf/           shared machinery
  pki.py                 test PKI: root CA, ECDSA / ML-DSA / TSA leaves, CRL
  pdfdoc.py              document creation, plain and B-LTA signing, forgery
  revisions.py           %%EOF boundaries, truncation, byte identity, SHA-256
  verify.py              pyHanko validation, normalised to plain dicts
src/audit/audit_crypto.py  runs FIRST; blocks the pipeline if it fails
src/experiments/         the results the paper rests on  (genuine ML-DSA-44)
  e1_plain_downgrade.py  plain sequential hybrid, orders A and B
  e2_lta_downgrade.py    PAdES-B-LTA under a real test PKI, orders A and B
  e3_t2_forgery.py       the t2 adversary: append-forgery, not truncation
  e4_verifier_rule.py    the proposed rule, implemented and scored
  e5_cost.py             does the mitigation cost anything? interleaved + bootstrap
src/controls/            ablations   (NOT post-quantum; see the warning in-file)
  c1_algorithm_invariance.py
paper/                   paper_update.tex (current), paper.tex, paper_vi.tex
  generated/numbers.tex  GENERATED -- do not edit
results/
  numbers.json           full record of the last run
  artifacts/             every PDF, key and certificate the run produced
dssval/                  Java harness driving DSS 6.5 (independent validation)
acrobat_eval/            Adobe Acrobat Reader 26.002 signature-panel evaluation
_tools/TinyTeX/          self-contained LaTeX toolchain
_archive/                out of scope; safe to delete
```

## Experiments

| | What it establishes | PQ layer |
|---|---|---|
| **E1** | A plain hybrid truncates to classical-only under order A; under order B the classical-only state is unreachable. | ML-DSA-44 |
| **E2** | PAdES-B-LTA does not mitigate it. Several boundaries reach the adversary's goal, one of them byte-identical to a legitimate classical-only archive, and one leaves a document timestamp covering the whole remaining file. | ML-DSA-44 |
| **E3** | Order inversion is necessary but **not sufficient**. At t2 the adversary appends instead of truncating. Honest and forged order-B files report the *same* coverage; only the modification level separates them. | ML-DSA-44 |
| **E4** | The proposed verifier rule works. Over 4 legitimate documents and 6 attacks: today's rule (*every signature intact*) catches 0; the paired rule (*require-PQ* + *nothing after it altered page content*) catches 6, with 0 false positives — including on B-LTA archives whose timestamps are legitimately appended after the PQ layer. | ML-DSA-44 |
| **E5** | The mitigation is free. 40 interleaved repetitions per order; a 95% bootstrap interval on the median signing-time difference straddles zero, and order B's file is 792 B *smaller*. | ML-DSA-44 |
| **C1** | Control. The outcome is fixed by the container, not the algorithm: same 1-vs-0 result with a several-fold different byte layout. | **none — ECDSA stand-in** |

## The audit gate

`src/audit/audit_crypto.py` runs before anything else and `run_all.py` aborts if
it fails. It asserts what a docstring cannot: the ML-DSA-44 OID
`2.16.840.1.101.3.4.3.17` in the CMS `SignerInfo`, a 2420-byte signature, and —
the check that cannot be satisfied by accident — that corrupting the
post-quantum signature bytes makes validation **fail** while the classical layer
stays intact. If the verifier were silently skipping the post-quantum signature,
that check would pass corruption unnoticed. 11/11 must pass.

**Test keys.** `results/artifacts/` contains `*_key.pem` files. These are test
keys generated fresh on every run, they protect nothing, and they are required
for reproduction. No production key material is in this repository.

`C1` names its second layer `RoleSimPQ`, not `PQLayer`. That field is an ECDSA
key standing in for a post-quantum one so the container can be held fixed while
the algorithm varies. Nothing in the controls may be cited as a post-quantum
result.

## Building the paper

```
cd paper
..\_tools\TinyTeX\bin\windows\pdflatex -interaction=nonstopmode paper_update.tex
```

Run it three times so cross-references settle. Run `run_all.py` first if
`paper/generated/numbers.tex` is missing.

## Requirements

Python 3.13 with `pyhanko` 0.37, `cryptography` (ML-DSA support required),
`asn1crypto`, `reportlab`. DSS validation additionally needs a JDK and Maven;
see `dssval/`.

Install the pinned Python dependencies from `requirements.txt`.
To populate the DSS dependencies with the bundled Maven, run `_tools\apache-maven-3.9.16\bin\mvn.cmd -f dssval\pom.xml dependency:go-offline`.
