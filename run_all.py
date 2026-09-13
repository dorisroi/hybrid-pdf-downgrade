#!/usr/bin/env python3
"""
run_all.py — one command that reproduces every number in the paper.

    python run_all.py

Runs E1, E2, E3 and the C1 control, writes the full record to
`results/numbers.json`, and emits `paper/generated/numbers.tex` as a set of
LaTeX macros. The paper \\input{}s that file and cites \\eOneDiscarded rather
than a hand-typed 22,958.

That indirection is the point. Before it existed, figures were copied by hand
from whichever run happened to be open, and the paper ended up quoting an
ECDSA-only result under an ML-DSA description, and a B-LTA boundary count under
a plain-hybrid table. A macro cannot be copied from the wrong experiment.

Absolute file sizes drift a few bytes between runs, because DER-encoded ECDSA
signatures vary in length. Byte-IDENTITY does not drift, and that is what the
claims rest on; the SHA-256 of each decisive artifact is recorded so a reader
can check the released bundle against the paper.
"""
import io
import json
import os
import sys
import time

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from hybridpdf import paths                                    # noqa: E402
from experiments import e1_plain_downgrade as e1               # noqa: E402
from experiments import e2_lta_downgrade as e2                 # noqa: E402
from experiments import e3_t2_forgery as e3                    # noqa: E402
from experiments import e4_verifier_rule as e4                 # noqa: E402
from experiments import e5_cost as e5                          # noqa: E402
from experiments import e6_formfill_probe as e6                # noqa: E402
from experiments import e7_refined_rule as e7                  # noqa: E402
from experiments import e8_value_rule as e8                    # noqa: E402
from experiments import e9_rule_bypass_probe as e9             # noqa: E402
from controls import c1_algorithm_invariance as c1             # noqa: E402
from audit import audit_crypto                                 # noqa: E402


def grp(n):
    """22958 -> '22{,}958', the IEEEtran-safe thousands separator."""
    return f"{n:,}".replace(",", "{,}")


def tex(s):
    """Escape a value for LaTeX text mode.

    pyHanko's enum names carry underscores (FORM_FILLING, ENTIRE_REVISION), and
    an unescaped one is a subscript outside math mode.
    """
    s = str(s)
    for ch in ("\\", "&", "%", "#", "$", "_", "{", "}"):
        s = s.replace(ch, "\\" + ch) if ch != "\\" else s
    return s


def _dss(res, key):
    """A DSS figure, or a loud '??' if run_dss.ps1 has not been run.

    Deliberately not silent: a stale or missing cross-check should be visible in
    the compiled PDF, not quietly replaced by last week's number.
    """
    d = res.get("DSS")
    return str(d[key]) if d and key in d else "??"


def _find(records, key, needle):
    """The one record whose `key` starts with `needle`. None if absent.

    Cases are addressed by their human label rather than by position,
    so inserting a case into a corpus cannot silently renumber a macro
    and change a table cell.
    """
    hits = [r for r in records if str(r.get(key, "")).startswith(needle)]
    return hits[0] if len(hits) == 1 else None


def _mark(separates):
    r"""A measured separation, as a table symbol.

    None means the experiment did not produce the case at all, which is
    a different statement from "did not separate" and must not be
    silently rendered as either symbol.
    """
    if separates is None:
        return "\\textbf{??}"
    return "\\cmark" if separates else "\\xmark"


def signal_cells(res):
    r"""The eight measured cells of the signals table.

    Columns: a /Contents override, and a fill of an existing form
    field. Rows: the four observables. A cell is True when the honest
    document and the attack differ in that observable.
    """
    E3, E6 = res["E3"], res["E6"]
    e7c, e8c = res["E7"]["cases"], res["E8"]["cases"]
    v = E6["variants"]

    honest_b = E3["honest_B"]["pq"]
    forged_b = E3["scenarios"]["S2_orderB_append_and_forge"]["pq"]
    v0 = _find(v, "label", "V0 honest")
    v1 = _find(v, "label", "V1")
    v4 = _find(v, "label", "V4")

    def lvl(x):
        return None if x is None else x.get("modification_level")

    cov_override = (None if not (honest_b and forged_b)
                    else honest_b["coverage"] != forged_b["coverage"])
    cov_fill = (None if not (v0 and v1)
                else v0.get("coverage") != v1.get("coverage"))

    mod_override = (None if not (v0 and v4) else lvl(v0) != lvl(v4))
    mod_fill = (None if not (v0 and v1) else lvl(v0) != lvl(v1))

    h7 = _find(e7c, "case", "form order-B, honest")
    f7 = _find(e7c, "case", "form order-B, t2 field-fill")
    o7 = _find(e7c, "case", "plain order-B, t2 /Contents")
    fields_override = (None if not (h7 and o7)
                       else h7["refined_accepts"] is True
                       and o7["refined_accepts"] is False)
    fields_fill = (None if not (h7 and f7)
                   else h7["refined_accepts"] is True
                   and f7["refined_accepts"] is False)

    h8 = _find(e8c, "case", "form order-B, honest")
    f8 = _find(e8c, "case", "form order-B, t2 field-fill")
    o8 = _find(e8c, "case", "plain order-B, t2 /Contents")
    values_override = (None if not (h8 and o8)
                       else h8["accepts"] is True and o8["accepts"] is False)
    values_fill = (None if not (h8 and f8)
                   else h8["accepts"] is True and f8["accepts"] is False)

    out = {
        "sigCovOverride": _mark(cov_override),
        "sigCovFill": _mark(cov_fill),
        "sigModOverride": _mark(mod_override),
        "sigModFill": _mark(mod_fill),
        "sigFieldsOverride": _mark(fields_override),
        "sigFieldsFill": _mark(fields_fill),
        "sigValuesOverride": _mark(values_override),
        "sigValuesFill": _mark(values_fill),
    }

    b2 = _find(res["E9"]["rows"], "case", "B2")
    h9 = _find(res["E9"]["rows"], "case", "honest form order-B")

    def sep(honest_key, attack_key, key):
        if not (h9 and b2) or not b2.get("built"):
            return None
        return h9.get(key) is True and b2.get(key) is False

    out["sigCovAppearance"]    = _mark(
        None if not (h9 and b2 and b2.get("built"))
        else h9.get("coverage") != b2.get("coverage"))
    out["sigModAppearance"]    = _mark(
        None if not (h9 and b2 and b2.get("built"))
        else h9.get("pq_level") != b2.get("pq_level"))
    out["sigFieldsAppearance"] = _mark(sep(None, None, "e7"))
    out["sigValuesAppearance"] = _mark(sep(None, None, "e8"))
    return out


def macros(res):
    """Every figure the paper cites, as LaTeX macros."""
    E1, E2, E3, C1 = res["E1"], res["E2"], res["E3"], res["C1"]
    E4, E5, AU = res["E4"], res["E5"], res["AUDIT"]
    a1, b1 = E1["orders"]["A"], E1["orders"]["B"]
    a2, b2 = E2["orders"]["A"], E2["orders"]["B"]

    honestB = E3["honest_B"]["pq"]
    forgedB = E3["scenarios"]["S2_orderB_append_and_forge"]["pq"]
    forgedA = E3["scenarios"]["S1_orderA_truncate_then_forge"]["pq"]

    # the decisive cut: the one byte-identical to the legitimately signed inner
    def decisive(o):
        for c in o["cuts"]:
            if c["identical_to_inner"]:
                return c
        return None

    d1, d2 = decisive(a1), decisive(a2)

    m = {
        # ---- algorithms ----
        "classicalAlgo": E1["classical_algo"],
        "pqAlgo": E1["pq_algo"],
        "tsaAlgo": E2["tsa_algo"],

        # ---- E1: plain hybrid ----
        "eOneHybridSize": grp(a1["hybrid_size"]),
        "eOneInnerSize": grp(a1["inner_size"]),
        "eOneDiscarded": grp(a1["bytes_discarded"]),
        "eOneBoundaries": str(a1["boundaries"]),
        "eOneCutPointsA": str(a1["cut_points"]),
        "eOneValidCutsA": str(a1["cuts_valid_document"]),
        "eOneClassicalOnlyA": str(a1["cuts_classical_only"]),
        "eOneCutPointsB": str(b1["cut_points"]),
        "eOneValidCutsB": str(b1["cuts_valid_document"]),
        "eOneClassicalOnlyB": str(b1["cuts_classical_only"]),
        "eOnePqOnlyB": str(b1["cuts_pq_only"]),
        "eOneInnerSha": a1["inner_sha256"][:16],
        "eOneOrderBCutOffset": grp(b1["inner_size"]),

        # ---- E2: B-LTA under a test PKI ----
        "eTwoHybridSize": grp(a2["hybrid_size"]),
        "eTwoInnerSize": grp(a2["inner_size"]),
        "eTwoDiscarded": grp(a2["bytes_discarded"]),
        "eTwoBoundaries": str(a2["boundaries"]),
        "eTwoCutPointsA": str(a2["cut_points"]),
        "eTwoValidCutsA": str(a2["cuts_valid_document"]),
        "eTwoClassicalOnlyA": str(a2["cuts_classical_only"]),
        "eTwoCutPointsB": str(b2["cut_points"]),
        "eTwoValidCutsB": str(b2["cuts_valid_document"]),
        "eTwoClassicalOnlyB": str(b2["cuts_classical_only"]),
        "eTwoPqOnlyB": str(b2["cuts_pq_only"]),
        "eTwoInnerSha": a2["inner_sha256"][:16],

        # ---- E3: the t2 adversary ----
        "eThreeHonestBCoverage": tex(honestB["coverage"]),
        "eThreeForgedBCoverage": tex(forgedB["coverage"]),
        "eThreeHonestBModLevel": tex(honestB["modification_level"]),
        "eThreeForgedBModLevel": tex(forgedB["modification_level"]),
        "eThreeForgedAPresent": "present" if forgedA["present"] else "absent",
        "eThreeOrderBClassicalOnlyCuts": str(E3["orderB_cuts_classical_only"]),

        # ---- E4: the verifier rule, measured ----
        "eFourAttacks": str(E4["n_attacks"]),
        "eFourLegit": str(E4["n_legitimate"]),
        "eFourNaiveMissed": str(E4["naive"]["missed_attacks"]),
        "eFourNaiveDetection": f"{E4['naive']['detection_rate']:.0%}".replace("%", "\\%"),
        "eFourProposedMissed": str(E4["proposed"]["missed_attacks"]),
        "eFourProposedRejected": str(E4["proposed"]["rejected_attacks"]),
        "eFourProposedDetection": f"{E4['proposed']['detection_rate']:.0%}".replace("%", "\\%"),
        "eFourProposedFP": str(E4["proposed"]["rejected_honest"]),
        "eFourBenignLevels": ", ".join(tex(x) for x in E4["benign_levels"]),

        # ---- E5: cost ----
        "eFiveReps": str(E5["reps"]),
        "eFiveTimeA": f"{E5['time_ms']['A']['median']:.0f}",
        "eFiveTimeB": f"{E5['time_ms']['B']['median']:.0f}",
        "eFiveDelta": f"{E5['time_delta_ms']:+.1f}",
        "eFiveDeltaLo": f"{E5['time_delta_ci95'][0]:+.1f}",
        "eFiveDeltaHi": f"{E5['time_delta_ci95'][1]:+.1f}",
        "eFiveSizeDelta": grp(abs(int(E5["size_delta_bytes"]))),

        # ---- DSS cross-check (from run_dss.ps1; "??" if it has not been run) ----
        "dssTotal": _dss(res, "total"),
        "dssAttacks": _dss(res, "attacks"),
        "dssLegit": _dss(res, "legitimate"),
        "dssNaiveAccepted": _dss(res, "naive_attacks_accepted"),
        "dssNaiveRejectedLegit": _dss(res, "naive_legitimate_rejected"),
        "dssDecidable": _dss(res, "rule_decidable"),
        "dssUndecidable": _dss(res, "rule_undecidable"),
        "dssRuleMissed": _dss(res, "rule_attacks_missed"),
        "dssRuleFP": _dss(res, "rule_false_positives"),

        # ---- audit ----
        "auditPassed": str(AU["checks_passed"]),
        "auditTotal": str(AU["checks_total"]),
        "pqOid": AU["pq_oid"] or "?",
        "pqSigLen": grp(AU["pq_sig_len"] or 0),

        # ---- C1: control ----
        "cOneClassicalOnlyA": str(C1["orders"]["A"]["cuts_classical_only"]),
        "cOneClassicalOnlyB": str(C1["orders"]["B"]["cuts_classical_only"]),
        "cOneOrderBCutOffset": grp(C1["orders"]["B"]["inner_size"]),
    }
    if d1:
        m["eOneDecisiveCut"] = str(d1["index"])
    if d2:
        m["eTwoDecisiveCut"] = str(d2["index"])
        m["eTwoDecisiveOffset"] = grp(d2["offset"])

    m.update(signal_cells(res))

    e7c, e8c = res["E7"]["cases"], res["E8"]["cases"]
    h7 = _find(e7c, "case", "form order-B, honest")
    f8 = _find(e8c, "case", "form order-B, t2 field-fill")
    v1 = _find(res["E6"]["variants"], "label", "V1")

    m["eSixFillLevel"] = tex(v1["modification_level"]) if v1 else "??"
    m["eSixFillAccepted"] = ("accepted" if v1 and v1["rule_accepts"]
                             else "rejected")
    m["eSevenHonestChanged"] = (", ".join(tex(x) for x in h7["changed_fields"])
                                if h7 and h7["changed_fields"] else "??")
    m["eSevenHonestRejected"] = str(sum(
        1 for r in e7c if r["legitimate"] and r["refined_accepts"] is False))
    m["eEightCorpus"] = str(len(e8c))
    m["eEightAttacksMissed"] = str(sum(
        1 for r in e8c if not r["legitimate"] and r["accepts"] is True))
    m["eEightHonestRejected"] = str(sum(
        1 for r in e8c if r["legitimate"] and r["accepts"] is False))
    if f8 and f8.get("moved"):
        name, (before, after) = sorted(f8["moved"].items())[0]
        m["eEightMovedField"] = tex(name)
        m["eEightMovedBefore"] = tex(before)
        m["eEightMovedAfter"] = tex(after)

    r9 = res["E9"]["rows"]
    m["eNineSpoofsCaught"] = str(sum(
        1 for r in r9 if r.get("built") and not r["legitimate"]
        and r["case"].startswith("B1") and r["r1_oid"] is False))
    m["eNineSpoofsTotal"] = str(sum(
        1 for r in r9 if r.get("built") and r["case"].startswith("B1")))
    m["eNineHonestKept"] = str(sum(
        1 for r in r9 if r.get("built") and r["legitimate"]
        and r["r1_oid"] is True))
    b2 = _find(r9, "case", "B2")
    m["eNineApRenders"] = tex(b2["note"]) if b2 and b2.get("note") else "??"
    return m


def write_numbers_tex(m, path):
    lines = [
        "% numbers.tex -- GENERATED by run_all.py. Do not edit by hand.",
        f"% generated {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "%",
        "% Every experimental figure the paper cites is defined here, so that a",
        "% number can only come from the run that actually produced it.",
        "",
    ]
    for k, v in m.items():
        lines.append(f"\\newcommand{{\\{k}}}{{{v}}}")
    lines.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def main():
    paths.ensure()
    t0 = time.time()
    res = {}

    print("\n" + "#" * 74)
    print("#  Reproducing every experimental figure in the paper")
    print("#" * 74)

    # the audit runs FIRST: if the post-quantum layer is not genuinely
    # post-quantum, nothing downstream is worth measuring
    res["AUDIT"] = audit_crypto.run()
    if not res["AUDIT"]["all_passed"]:
        print("\n  !! cryptographic audit FAILED — refusing to generate numbers")
        sys.exit(1)

    res["E1"] = e1.run()
    res["E2"] = e2.run()
    res["E3"] = e3.run()
    res["E4"] = e4.run()
    res["E5"] = e5.run()
    res["C1"] = c1.run()
    res["E6"] = e6.run()
    res["E7"] = {"name": "E7 refined rule (changed-field set)",
                 "cases": e7.run()}
    res["E8"] = {"name": "E8 value-stability rule",
                 "cases": e8.run()}
    res["E9"] = e9.run()

    # produced by run_dss.ps1, which needs a JDK and so runs separately
    dss_path = paths.result("dss_rule.json")
    if os.path.exists(dss_path):
        with open(dss_path, encoding="utf-8") as f:
            res["DSS"] = json.load(f)
        print(f"\n  folded in DSS cross-check from {os.path.basename(dss_path)}")
    else:
        print("\n  no results/dss_rule.json — run run_dss.ps1 for the DSS figures")

    res["meta"] = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "python": sys.version.split()[0],
        "elapsed_seconds": round(time.time() - t0, 1),
    }
    # pyHanko 0.37 has no __version__ attribute; the installed distribution
    # metadata is the reliable source.
    try:
        from importlib.metadata import version
        res["meta"]["pyhanko"] = version("pyHanko")
    except Exception:
        res["meta"]["pyhanko"] = "unknown"

    jpath = paths.result("numbers.json")
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)

    m = macros(res)
    tpath = write_numbers_tex(m, os.path.join(paths.GENERATED, "numbers.tex"))

    print("\n" + "#" * 74)
    print("#  SUMMARY — these are the figures the paper will cite")
    print("#" * 74)
    for k, v in m.items():
        print(f"  \\{k:32s} {v}")
    print(f"\n  full record -> {os.path.relpath(jpath, paths.ROOT)}")
    print(f"  LaTeX macros -> {os.path.relpath(tpath, paths.ROOT)}")
    print(f"  elapsed {res['meta']['elapsed_seconds']}s")


if __name__ == "__main__":
    main()
