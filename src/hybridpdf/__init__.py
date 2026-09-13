"""
hybridpdf — shared machinery for the format-layer downgrade experiments.

Every experiment in `src/experiments` and `src/controls` is built from these
four modules, so that a number appearing in the paper has exactly one place it
can come from:

    pki        issue the test PKI (root CA, ECDSA / ML-DSA / TSA leaves, CRL)
    pdfdoc     create documents and sign them, plain or at PAdES-B-LTA
    revisions  find %%EOF boundaries, truncate, compare bytes
    verify     run pyHanko validation and normalise what it reports

Earlier versions of this study kept a separate self-contained script per
experiment. That is how the paper ended up quoting a figure produced by one
run under the description of another; the shared module exists to make that
mistake impossible.
"""
from . import paths, pki, pdfdoc, revisions, verify  # noqa: F401

__all__ = ["paths", "pki", "pdfdoc", "revisions", "verify"]
