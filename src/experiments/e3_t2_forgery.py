#!/usr/bin/env python3
"""
E3 — the adversary at t2, once the classical algorithm is actually forgeable.

E1 counts truncation points, so it speaks only to t1: the adversary cannot yet
forge anything and can only cut. At t2 it is no longer confined to cutting. It
can APPEND a revision that overrides the page content and carries a freshly
forged classical signature. Truncation cannot reach the post-quantum layer under
order B, but appending does not need to.

We simulate t2 exactly by handing the adversary the classical private key --
precisely the capability a broken ECDSA confers. The ML-DSA key is never given.

    S1  order A: truncate the PQ layer away, then forge
    S2  order B: no cut reaches the PQ layer, so forge by appending on top
    S3  either order: ignore the original, sign fabricated content from scratch

The decisive measurement is NOT coverage. In the honest order-B document and in
the forged one the post-quantum signature reports the same coverage,
ENTIRE_REVISION. What separates them is the modification level pyHanko derives
by differencing the covered revision against the final state of the file.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pyhanko_certvalidator import ValidationContext

from hybridpdf import paths, pki, pdfdoc, revisions, verify

CLASSICAL, PQ, FORGED = "ClassicalLayer", "PQLayer", "ForgedClassical"


def _pq_state(rows):
    r = verify.find(rows, PQ)
    if r is None:
        return {"present": False, "intact": False, "coverage": None,
                "modification_level": None, "covers_rendered": False}
    return {
        "present": True,
        "intact": r["intact"],
        "coverage": r["coverage"],
        "modification_level": r["modification_level"],
        # the PQ signature still stands over what the file renders only if no
        # later revision changed page content
        "covers_rendered": r["modification_level"] in ("NONE", "LTA_UPDATES", "FORM_FILLING"),
    }


def run(verbose=True):
    classical = pki.selfsigned("_e3_c", "Classical Signer", "ec")
    pq = pki.selfsigned("_e3_q", "PQ Signer", "mldsa")
    vc = ValidationContext(trust_roots=[classical.asn1, pq.asn1],
                           allow_fetching=False, revocation_mode="soft-fail")

    out = {
        "name": "E3 t2 append-forgery",
        "classical_algo": classical.algo,
        "pq_algo": pq.algo,
        "honest_amount": pdfdoc.HONEST_AMOUNT,
        "forged_amount": pdfdoc.FORGED_AMOUNT,
        "scenarios": {},
    }

    # ---------------- order A: truncate, then forge ----------------
    baseA = pdfdoc.make_pdf(paths.art("_e3_A_plain.pdf"))
    a1 = pdfdoc.sign(baseA, paths.art("_e3_A_1.pdf"), classical, CLASSICAL)
    fullA = pdfdoc.sign(a1, paths.art("_e3_A_2.pdf"), pq, PQ)
    out["honest_A"] = {"rows": verify.inspect(fullA, vc),
                       "size": os.path.getsize(fullA)}

    dataA = open(fullA, "rb").read()
    cutA = revisions.cut_points(dataA)[-1]
    truncA = paths.art("_e3_A_trunc.pdf")
    open(truncA, "wb").write(dataA[:cutA])
    forgeA = pdfdoc.append_forged_revision(truncA, paths.art("_e3_A_forged.pdf"),
                                           classical, FORGED)
    rowsA = verify.inspect(forgeA, vc)
    out["scenarios"]["S1_orderA_truncate_then_forge"] = {
        "rows": rowsA, "pq": _pq_state(rowsA),
        "size": os.path.getsize(forgeA), "cut_offset": cutA}

    # ---------------- order B: cannot truncate, so append ----------------
    baseB = pdfdoc.make_pdf(paths.art("_e3_B_plain.pdf"))
    b1 = pdfdoc.sign(baseB, paths.art("_e3_B_1.pdf"), pq, PQ)
    fullB = pdfdoc.sign(b1, paths.art("_e3_B_2.pdf"), classical, CLASSICAL)
    rowsHB = verify.inspect(fullB, vc)
    out["honest_B"] = {"rows": rowsHB, "pq": _pq_state(rowsHB),
                       "size": os.path.getsize(fullB)}

    # confirm no cut reaches the PQ layer
    reach = []
    for idx, off, fp in revisions.write_cuts(fullB, paths.art("_e3_B")):
        good = verify.good_signatures(verify.inspect(fp, vc))
        reach.append({"index": idx, "offset": off, "surviving": good,
                      "classical_only": CLASSICAL in good and PQ not in good})
    out["orderB_cuts"] = reach
    out["orderB_cuts_classical_only"] = sum(c["classical_only"] for c in reach)

    forgeB = pdfdoc.append_forged_revision(fullB, paths.art("_e3_B_forged.pdf"),
                                           classical, FORGED)
    rowsB = verify.inspect(forgeB, vc)
    out["scenarios"]["S2_orderB_append_and_forge"] = {
        "rows": rowsB, "pq": _pq_state(rowsB), "size": os.path.getsize(forgeB)}

    # ---------------- from scratch, available under either order ----------
    scratch = pdfdoc.make_pdf(paths.art("_e3_scratch_plain.pdf"),
                              amount=pdfdoc.FORGED_AMOUNT)
    forgeS = pdfdoc.sign(scratch, paths.art("_e3_scratch_forged.pdf"),
                         classical, FORGED)
    rowsS = verify.inspect(forgeS, vc)
    out["scenarios"]["S3_either_order_forge_from_scratch"] = {
        "rows": rowsS, "pq": _pq_state(rowsS), "size": os.path.getsize(forgeS)}

    if verbose:
        report(out)
    return out


def _show(title, rows):
    print(f"\n  {title}")
    print(f"    {'field':18s} {'intact':7s} {'coverage':18s} mod-level")
    for r in rows:
        print(f"    {r['field']:18s} {str(r['intact']):7s} "
              f"{str(r['coverage']):18s} {r['modification_level']}")


def report(out):
    print(f"\n{'='*74}\nE3  t2 append-forgery — adversary holds the "
          f"{out['classical_algo']} key, never the {out['pq_algo']} key\n{'='*74}")
    print(f"  honest content: AMOUNT PAYABLE: {out['honest_amount']}")
    print(f"  forged content: AMOUNT PAYABLE: {out['forged_amount']}")

    _show("honest hybrid, order A", out["honest_A"]["rows"])
    _show("honest hybrid, order B", out["honest_B"]["rows"])
    print(f"\n  order B: cuts reaching a classical-only document = "
          f"{out['orderB_cuts_classical_only']}  (the PQ layer sits in the prefix)")
    for c in out["orderB_cuts"]:
        print(f"      cut{c['index']} @{c['offset']:6d} -> {c['surviving'] or 'nothing valid'}")

    for key, sc in out["scenarios"].items():
        _show(key, sc["rows"])

    print(f"\n{'-'*74}\n  post-quantum evidence after the forgery\n{'-'*74}")
    print(f"  {'file':34s} {'PQ layer':10s} {'mod-level':14s} covers rendered")
    rows = [("honest, order B", out["honest_B"]["pq"])] + \
           [(k, v["pq"]) for k, v in out["scenarios"].items()]
    for label, s in rows:
        present = "intact" if s["present"] and s["intact"] else ("present" if s["present"] else "ABSENT")
        print(f"  {label:34s} {present:10s} {str(s['modification_level']):14s} "
              f"{'yes' if s['covers_rendered'] else ('no' if s['present'] else '-')}")

    hb = out["honest_B"]["pq"]
    fb = out["scenarios"]["S2_orderB_append_and_forge"]["pq"]
    print(f"\n  >>> honest and forged order-B files report the SAME coverage "
          f"({hb['coverage']}).")
    print(f"      Only the modification level separates them: "
          f"{hb['modification_level']} vs {fb['modification_level']}.")


if __name__ == "__main__":
    run()
