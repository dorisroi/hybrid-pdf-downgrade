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

Second, INTERLEAVE the two orders rather than running one batch after the other.
Machine load drifts over seconds, and a back-to-back layout charges that drift
to whichever construction ran second.

Third, put an interval on the difference. A median difference quoted without
one cannot be distinguished from sampling noise, and with an interquartile range
of tens of milliseconds a difference of ten is exactly the case in doubt. We
bootstrap the difference of medians and report a 95% interval; if it straddles
zero, no cost difference has been demonstrated.
"""
import os
import random
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hybridpdf import paths, pki, pdfdoc

CLASSICAL, PQ = "ClassicalLayer", "PQLayer"


def _one(first, second, first_field, second_field, tag):
    """One signing of the document under a given order. Returns (ms, bytes)."""
    base = pdfdoc.make_pdf(paths.art(f"_e5_{tag}_plain.pdf"))
    t0 = time.perf_counter()
    inner = pdfdoc.sign(base, paths.art(f"_e5_{tag}_1.pdf"), first, first_field)
    full = pdfdoc.sign(inner, paths.art(f"_e5_{tag}_2.pdf"), second, second_field)
    return (time.perf_counter() - t0) * 1000.0, os.path.getsize(full)


def _bootstrap_median_diff(xs, ys, iters=10000, seed=12345):
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

    # interleaved, so drift in machine load is charged to both orders equally
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
