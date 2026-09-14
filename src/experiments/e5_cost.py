#!/usr/bin/env python3
"""
E5 — what does the mitigation actually cost?

Section VI-C claims order inversion "costs nothing". That is an empirical claim
and it was never measured, so this measures it: the same document is signed
under both orders, repeatedly, and we record wall-clock signing time and the
size of the resulting file.

Three methodological points, two of them learned the hard way in an earlier
cost study.

First, report the MEDIAN and the interquartile range, not a mean with a standard
deviation. Signing time on a loaded desktop is heavy-tailed; a mean over a
handful of runs measures the scheduler, not the construction.

Second, interleave fixed A-then-B blocks rather than separate batches.
This can reduce sensitivity to temporal drift but does not cancel it:
the order is neither randomised nor counterbalanced, so order bias remains.

Third, put an interval on the difference. A median difference quoted without
one cannot be distinguished from sampling noise, and with an interquartile range
of tens of milliseconds a difference of ten is exactly the case in doubt. We
bootstrap the difference of sample medians by resampling each order independently,
not by resampling pairs. An interval containing zero does not establish
equivalence. New runs retain individual observations and analysis metadata;
historical aggregate-only records cannot recover those observations.
"""
import os
import random
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hybridpdf import paths, pki, pdfdoc

CLASSICAL, PQ = "ClassicalLayer", "PQLayer"
BOOTSTRAP_RESAMPLES = 10000
BOOTSTRAP_SEED = 12345


def _one(first, second, first_field, second_field, tag):
    """One signing of the document under a given order. Returns (ms, bytes)."""
    base = pdfdoc.make_pdf(paths.art(f"_e5_{tag}_plain.pdf"))
    t0 = time.perf_counter()
    inner = pdfdoc.sign(base, paths.art(f"_e5_{tag}_1.pdf"), first, first_field)
    full = pdfdoc.sign(inner, paths.art(f"_e5_{tag}_2.pdf"), second, second_field)
    return (time.perf_counter() - t0) * 1000.0, os.path.getsize(full)


def _bootstrap_median_diff(xs, ys, iters=BOOTSTRAP_RESAMPLES, seed=BOOTSTRAP_SEED):
    """95% interval for median(ys) - median(xs), by resampling with replacement."""
    rng = random.Random(seed)
    n, m = len(xs), len(ys)
    diffs = []
    for _ in range(iters):
        bx = statistics.median(rng.choices(xs, k=n))
        by = statistics.median(rng.choices(ys, k=m))
        diffs.append(by - bx)
    diffs.sort()
    lo = diffs[int(0.025 * iters)]
    hi = diffs[int(0.975 * iters) - 1]
    return lo, hi


def _stats(xs):
    xs = sorted(xs)
    q = statistics.quantiles(xs, n=4) if len(xs) >= 4 else [xs[0], statistics.median(xs), xs[-1]]
    return {"median": statistics.median(xs), "q1": q[0], "q3": q[2],
            "iqr": q[2] - q[0], "min": xs[0], "max": xs[-1], "n": len(xs)}


def run(reps=40, verbose=True):
    classical = pki.selfsigned("_e5_c", "Classical Signer", "ec")
    pq = pki.selfsigned("_e5_q", "PQ Signer", "mldsa")

    # Fixed A then B; interleaving is not randomisation or counterbalancing.
    tA, sA, tB, sB = [], [], [], []
    for _ in range(reps):
        t, s = _one(classical, pq, CLASSICAL, PQ, "A")
        tA.append(t); sA.append(s)
        t, s = _one(pq, classical, PQ, CLASSICAL, "B")
        tB.append(t); sB.append(s)

    lo, hi = _bootstrap_median_diff(tA, tB)
    a_med, b_med = statistics.median(tA), statistics.median(tB)

    out = {
        "name": "E5 cost of the mitigation",
        "reps": reps,
        "interleaved": True,
        "time_ms": {"A": _stats(tA), "B": _stats(tB)},
        "size_bytes": {"A": _stats(sA), "B": _stats(sB)},
        "time_delta_ms": b_med - a_med,
        "time_delta_ci95": [lo, hi],
        "time_difference_demonstrated": not (lo <= 0.0 <= hi),
        "size_delta_bytes": statistics.median(sB) - statistics.median(sA),
        # Additive recording only: all legacy estimators above are unchanged.
        # Sequence indexes preserve execution blocks, not a paired estimator.
        "observations": [
            {"block_index": i + 1, "execution_order": ["A", "B"],
             "A": {"time_ms": ta, "size_bytes": sa},
             "B": {"time_ms": tb, "size_bytes": sb}}
            for i, (ta, sa, tb, sb) in enumerate(zip(tA, sA, tB, sB))
        ],
        "analysis": {
            "estimator": "median(B.time_ms) - median(A.time_ms)",
            "paired_analysis": False,
            "execution_order": ["A", "B"],
            "randomised": False,
            "counterbalanced": False,
            "bootstrap": {
                "method": "independent resampling with replacement within each order",
                "resamples": BOOTSTRAP_RESAMPLES,
                "seed": BOOTSTRAP_SEED,
                "rng": "random.Random",
                "confidence_level": 0.95,
                "interval": "percentile",
                "sorted_zero_based_endpoint_indices": [
                    int(0.025 * BOOTSTRAP_RESAMPLES),
                    int(0.975 * BOOTSTRAP_RESAMPLES) - 1,
                ],
            },
            "quartiles": "statistics.quantiles(n=4, method='exclusive')",
            "timed_scope": "two pdfdoc.sign calls; excludes key generation and make_pdf",
        },
    }
    if verbose:
        report(out)
    return out


def report(out):
    print(f"\n{'='*78}\nE5  cost of the mitigation — {out['reps']} interleaved "
          f"repetitions per order\n{'='*78}")
    print(f"  {'':30s} {'median':>10s} {'IQR':>10s} {'min':>10s} {'max':>10s}")
    for k, lbl in (("A", "signing time, ms   order A"),
                   ("B", "signing time, ms   order B")):
        s = out["time_ms"][k]
        print(f"  {lbl:30s} {s['median']:>10.1f} {s['iqr']:>10.1f} "
              f"{s['min']:>10.1f} {s['max']:>10.1f}")
    print()
    for k, lbl in (("A", "hybrid size, B     order A"),
                   ("B", "hybrid size, B     order B")):
        s = out["size_bytes"][k]
        print(f"  {lbl:30s} {s['median']:>10.0f} {s['iqr']:>10.0f} "
              f"{s['min']:>10.0f} {s['max']:>10.0f}")

    lo, hi = out["time_delta_ci95"]
    print(f"\n  order B minus order A : {out['time_delta_ms']:+.1f} ms "
          f"(95% bootstrap interval {lo:+.1f} to {hi:+.1f} ms)")
    if out["time_difference_demonstrated"]:
        print("  >>> the interval excludes zero: a signing-cost difference IS")
        print("      demonstrated, and the paper must report it rather than say")
        print("      the change is free.")
    else:
        print("  >>> the interval straddles zero: no signing-cost difference is")
        print("      demonstrated. The two orders perform the same two operations;")
        print("      only their sequence changes.")
    print(f"  size difference       : {out['size_delta_bytes']:+.0f} B "
          f"({'order B is smaller' if out['size_delta_bytes'] < 0 else 'order B is larger'})")


if __name__ == "__main__":
    run()
