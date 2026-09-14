"""Paths for experimental results and artifacts."""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

RESULTS = os.path.join(ROOT, "results")
ARTIFACTS = os.path.join(RESULTS, "artifacts")        # PDFs, PEMs, cut files


def ensure():
    for d in (RESULTS, ARTIFACTS):
        os.makedirs(d, exist_ok=True)


def art(name):
    """Path to a generated artifact."""
    ensure()
    return os.path.join(ARTIFACTS, name)


def result(name):
    ensure()
    return os.path.join(RESULTS, name)
