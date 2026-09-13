#!/usr/bin/env python3
"""
compare_runs.py -- did re-running the pipeline change anything that matters?

Re-running `run_all.py` generates fresh keys, so a naive diff of two
`numbers.json` files is useless: every SHA-256 changes, every timing changes,
and file sizes wobble by a few bytes because DER-encoded ECDSA signatures vary
in length. A reader who diffs the raw JSON sees hundreds of differences and
learns nothing.

This script classifies every figure into one of three kinds and reports them
separately:

    INVARIANT   must be byte-for-byte equal across runs. These are the claims
                the paper actually makes -- boundary counts, coverage levels,
                modification levels, rule verdicts, the audit. A difference
                here is a real regression and the paper's text may be wrong.

    DRIFT       expected to move a little. Absolute file sizes and the byte
                counts derived from them. Flagged only if the movement exceeds
                a tolerance, which would mean something structural changed
                rather than a signature encoding.

    IGNORED     hashes, timings, wall-clock metadata. Different every run by
                construction; comparing them is noise.

Usage:

    python compare_runs.py results/numbers.baseline.json results/numbers.json

Exit code 0 if no invariant differs and no drift exceeds tolerance, 1 otherwise,
so it can gate a re-run before the paper is recompiled.
"""
import json
import sys

# how far a size-like figure may move before it stops being signature-encoding
# noise. ECDSA DER varies by a couple of bytes per signature; a B-LTA document
# carries several, so the archival budget is larger.
DRIFT_TOLERANCE = 256


def _sig_rows(sigs):
    """Signature rows reduced to the fields the paper's claims rest on."""
    return [
        (s.get("field"), s.get("timestamp"), s.get("intact"), s.get("valid"),
         s.get("trusted"), s.get("coverage"), s.get("modification_level"))
        for s in (sigs or [])
    ]


def invariants(d):
    """Every figure that must not move between runs."""
    out = {}

    au = d.get("AUDIT", {})
    for k in ("checks_passed", "checks_total", "pq_oid", "pq_sig_len",
              "classical_oid", "negative_controls_ok", "all_passed"):
        out[f"AUDIT.{k}"] = au.get(k)

    for exp in ("E1", "E2", "C1"):
        e = d.get(exp)
        if not e:
            continue
        for o in ("A", "B"):
            x = (e.get("orders") or {}).get(o)
            if not x:
                continue
            for k in ("boundaries", "cut_points", "cuts_valid_document",
                      "cuts_classical_only", "cuts_pq_only"):
                out[f"{exp}.{o}.{k}"] = x.get(k)
            out[f"{exp}.{o}.signatures"] = _sig_rows(x.get("intact_signatures"))
            # which cut reproduces the legitimately signed inner document
            cuts = x.get("cuts") or []
            out[f"{exp}.{o}.identical_cuts"] = [
                c.get("index") for c in cuts if c.get("identical_to_inner")]
            out[f"{exp}.{o}.surviving_per_cut"] = [
                (c.get("index"), tuple(c.get("surviving") or []))
                for c in cuts if "surviving" in c]

    e3 = d.get("E3")
    if e3:
        out["E3.orderB_cuts_classical_only"] = e3.get("orderB_cuts_classical_only")
        pq = (e3.get("honest_B") or {}).get("pq") or {}
        for k in ("present", "intact", "coverage", "modification_level",
                  "covers_rendered"):
            out[f"E3.honest_B.{k}"] = pq.get(k)
        for name, sc in (e3.get("scenarios") or {}).items():
            p = sc.get("pq") or {}
            for k in ("present", "intact", "coverage", "modification_level",
                      "covers_rendered"):
                out[f"E3.{name}.{k}"] = p.get(k)

    e4 = d.get("E4")
    if e4:
        out["E4.n_attacks"] = e4.get("n_attacks")
        out["E4.n_legitimate"] = e4.get("n_legitimate")
        out["E4.benign_levels"] = sorted(e4.get("benign_levels") or [])
        for rule in ("naive", "proposed"):
            r = e4.get(rule) or {}
            for k in ("rejected_attacks", "missed_attacks", "accepted_honest",
                      "rejected_honest"):
                out[f"E4.{rule}.{k}"] = r.get(k)
        for c in e4.get("cases") or []:
            s = c.get("scenario")
            out[f"E4.case[{s}].legitimate"] = c.get("legitimate")
            out[f"E4.case[{s}].naive_accepts"] = c.get("naive_accepts")
            out[f"E4.case[{s}].proposed_accepts"] = c.get("proposed_accepts")
            # carries the modification level, which is the substance of R2
            out[f"E4.case[{s}].proposed_why"] = c.get("proposed_why")

    e5 = d.get("E5")
    if e5:
        out["E5.reps"] = e5.get("reps")
        out["E5.interleaved"] = e5.get("interleaved")
        out["E5.time_difference_demonstrated"] = e5.get("time_difference_demonstrated")
        ci = e5.get("time_delta_ci95") or [None, None]
        # the claim is not the interval's endpoints but that it straddles zero
        out["E5.ci_straddles_zero"] = (
            None if ci[0] is None else (ci[0] <= 0 <= ci[1]))
        out["E5.order_B_is_smaller"] = (
            None if e5.get("size_delta_bytes") is None
            else e5["size_delta_bytes"] < 0)

    dss = d.get("DSS")
    if dss:
        for k in ("attacks", "legitimate", "total", "naive_attacks_accepted",
                  "naive_legitimate_rejected", "rule_decidable",
                  "rule_undecidable", "rule_attacks_missed",
                  "rule_false_positives"):
            out[f"DSS.{k}"] = dss.get(k)

    # E6-E9: the signal table and the rule-bypass results rest on every field
    # of every case -- verdicts, levels, reasons, OIDs, the rendered amount.
    # Two re-runs with fresh keys reproduced these rows exactly, so nothing in
    # them is run-dependent. Rows are keyed by case name, not position, so a
    # reordering reads as a shape change rather than as spurious regressions.
    for exp, rows_key, name_key in (("E6", "variants", "label"),
                                    ("E7", "cases", "case"),
                                    ("E8", "cases", "case"),
                                    ("E9", "rows", "case")):
        e = d.get(exp)
        if not e:
            continue
        rows = e.get(rows_key) or []
        out[f"{exp}.n_cases"] = len(rows)
        for r in rows:
            for field, v in r.items():
                if field != name_key:
                    out[f"{exp}[{r.get(name_key)}].{field}"] = _norm(v)
    if d.get("E6"):
        out["E6.errors"] = _norm(d["E6"].get("errors"))

    # a different validator version can change every verdict above; a baseline
    # that never recorded one ("unknown") must not silently pass
    out["meta.pyhanko"] = (d.get("meta") or {}).get("pyhanko")

    return out


def _norm(v):
    """JSON round-trip, so an in-memory tuple equals the list it serialises to."""
    return json.loads(json.dumps(v, default=str))


def drifters(d):
    """Figures expected to move by a few bytes between runs."""
    out = {}
    for exp in ("E1", "E2", "C1"):
        e = d.get(exp)
        if not e:
            continue
        for o in ("A", "B"):
            x = (e.get("orders") or {}).get(o)
            if not x:
                continue
            for k in ("inner_size", "hybrid_size", "bytes_discarded"):
                if k in x:
                    out[f"{exp}.{o}.{k}"] = x[k]
    e5 = d.get("E5")
    if e5 and e5.get("size_delta_bytes") is not None:
        out["E5.size_delta_bytes"] = e5["size_delta_bytes"]
    return out


def _fmt(v):
    s = json.dumps(v, ensure_ascii=False, default=str)
    return s if len(s) <= 96 else s[:93] + "..."


def compare(base, new):
    inv_b, inv_n = invariants(base), invariants(new)
    dr_b, dr_n = drifters(base), drifters(new)

    regressions, missing, added = [], [], []
    for k in sorted(set(inv_b) | set(inv_n)):
        if k not in inv_n:
            missing.append(k)
        elif k not in inv_b:
            added.append(k)
        elif inv_b[k] != inv_n[k]:
            regressions.append((k, inv_b[k], inv_n[k]))

    drifts, excessive = [], []
    for k in sorted(set(dr_b) & set(dr_n)):
        a, b = dr_b[k], dr_n[k]
        if a == b:
            continue
        delta = b - a
        (excessive if abs(delta) > DRIFT_TOLERANCE else drifts).append((k, a, b, delta))

    print("=" * 80)
    print("compare_runs -- baseline vs new")
    print("=" * 80)
    print(f"  baseline generated: {(base.get('meta') or {}).get('generated')}")
    print(f"  new      generated: {(new.get('meta') or {}).get('generated')}")
    print(f"  invariants checked: {len(set(inv_b) & set(inv_n))}")

    print(f"\n--- INVARIANT DIFFERENCES ({len(regressions)}) " + "-" * 40)
    if not regressions:
        print("  none. Every claim the paper makes reproduced exactly.")
    for k, a, b in regressions:
        print(f"  {k}")
        print(f"      baseline {_fmt(a)}")
        print(f"      new      {_fmt(b)}")

    if missing or added:
        print(f"\n--- SHAPE CHANGED ({len(missing)} gone, {len(added)} new) " + "-" * 26)
        for k in missing:
            print(f"  gone from new run : {k}")
        for k in added:
            print(f"  only in new run   : {k}")

    print(f"\n--- EXPECTED DRIFT ({len(drifts)}) " + "-" * 47)
    for k, a, b, d in drifts:
        print(f"  {k:34s} {a:>9} -> {b:>9}  ({d:+d} B)")
    if not drifts:
        print("  none")

    if excessive:
        print(f"\n--- DRIFT BEYOND TOLERANCE ({DRIFT_TOLERANCE} B) " + "-" * 30)
        for k, a, b, d in excessive:
            print(f"  {k:34s} {a:>9} -> {b:>9}  ({d:+d} B)")
        print("  A move this large is structural, not signature encoding.")

    ok = not regressions and not excessive and not missing and not added
    print("\n" + "=" * 80)
    if ok:
        print("  RESULT: reproduced. Regenerate numbers.tex and recompile.")
    else:
        print("  RESULT: NOT reproduced. Do not recompile the paper until the")
        print("  differences above are explained -- the text may assert something")
        print("  this run does not show.")
    print("=" * 80 + "\n")
    return ok


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        print("usage: python compare_runs.py <baseline.json> <new.json>")
        sys.exit(2)
    with open(sys.argv[1], encoding="utf-8") as f:
        base = json.load(f)
    with open(sys.argv[2], encoding="utf-8") as f:
        new = json.load(f)
    sys.exit(0 if compare(base, new) else 1)


if __name__ == "__main__":
    main()
