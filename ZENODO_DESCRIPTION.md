# Artifact — Put the Post-Quantum Signature First

Reproduces every experimental figure in the accompanying paper on format-layer
downgrade of sequential hybrid PDF signatures.

## What this is

A sequential hybrid PDF carries a classical and a post-quantum signature in
two incremental revisions. Truncating the file at the previous `%%EOF`
removes the outer layer. When the post-quantum signature is the outer one,
the result is byte-identical to a document that was never hybrid-signed, and
the adversary needs no key, reads no signature bytes and writes nothing.

The artifact contains the attack, the signing-order mitigation, the
PAdES-B-LTA evaluation, an independent cross-check against EU DSS 6.5, and
four probes of candidate verifier rules.

## Reproducing

```
pip install -r requirements.txt
python reproduce.py --with-dss   # E1-E9, DSS 6.5 cross-check, compare, REVIEWER_REPORT.md
python reproduce.py              # the same without the JDK-dependent DSS step
make reproduce                   # or: docker build -t hybridpdf-repro . (see Dockerfile)
```

`reproduce.py` writes `results/reproduce/<timestamp>/REVIEWER_REPORT.md`, one
PASS/FAIL/NOTE verdict per reviewer question with evidence from the run, and
exits non-zero if any claim or invariant fails to reproduce.

`results/numbers.json` is the full record; `compare_runs.py` compares two runs
and separates real regressions from the byte-level drift that DER-encoded
ECDSA signatures cause between runs.

## About the key files

`results/artifacts/` contains `*_key.pem`. These are **test keys generated
fresh on every run**. They protect nothing, they are required for
reproduction, and no production key material appears anywhere in this record.
Automated secret scanners will flag them; this is expected.

`results/artifacts/` is included even though running the pipeline regenerates
it, because the paper's decisive claims are byte-identity claims. Checking
them requires the exact bytes measured, which `MANIFEST.sha256` pins.

## Not included

The manuscript. Releasing code and data is not publishing the paper.

## Licence

Code under Apache-2.0; data, logs and signed artifacts under CC-BY-4.0.
