#!/usr/bin/env python3
"""
E4 — does the proposed verifier rule actually work?

E3 established that order inversion makes the post-quantum evidence unremovable
but does not by itself reject a t2 forgery, and that coverage cannot tell an
honest order-B document from a forged one. The paper therefore proposes a rule.
Until now the paper only *stated* it. This measures it.

    NAIVE RULE (what a verifier does today)
        accept iff every signature in the file is intact

    PROPOSED RULE
        R1  require-PQ : the file carries an intact, valid post-quantum signature
        R2  PQ-covers-rendered : that signature's modification level is benign,
            i.e. no revision after it altered page content
        accept iff R1 and R2

R2 is phrased over the modification level, not coverage, and that is not a
detail. A legitimately archived document appends document timestamps *after*
the post-quantum signature, so its coverage is ENTIRE_REVISION exactly as a
forged file's is. The honest appends report NONE / FORM_FILLING / LTA_UPDATES;
only a content override reports OTHER.

The false-positive cases matter more than the true positives here. A rule that
rejects forgeries but also rejects every B-LTA archive is useless, so the
benign set deliberately includes archival documents whose later revisions are
legitimate.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pyhanko.sign.timestamps import DummyTimeStamper
from pyhanko_certvalidator import ValidationContext

from hybridpdf import paths, pki, pdfdoc, revisions, verify

CLASSICAL, PQ, FORGED = "ClassicalLayer", "PQLayer", "ForgedClassical"

# modification levels that mean "nothing after this signature touched page content"
BENIGN_LEVELS = {"NONE", "LTA_UPDATES", "FORM_FILLING"}


# ---------------------------------------------------------------- the rules
def naive_rule(rows):
    """Accept iff every signature present is intact. What tooling does today."""
    if not rows:
        return False, "no signature"
    bad = [r["field"] for r in rows if not r["intact"]]
    return (not bad), ("all signatures intact" if not bad else f"not intact: {bad}")


def proposed_rule(rows, pq_field=PQ):
    """R1 require-PQ, and R2 nothing after it altered page content."""
    pq = verify.find(rows, pq_field)
    if pq is None:
        return False, "R1 fails: no post-quantum signature present"
    if not (pq["intact"] and pq["valid"]):
        return False, f"R1 fails: PQ intact={pq['intact']} valid={pq['valid']}"
    lvl = pq["modification_level"]
    if lvl not in BENIGN_LEVELS:
        return False, f"R2 fails: a later revision altered page content ({lvl})"
    return True, f"R1 and R2 hold (PQ modification level {lvl})"


# ---------------------------------------------------------------- scenarios
def _plain_setup():
    classical = pki.selfsigned("_e4_c", "Classical Signer", "ec")
    pq = pki.selfsigned("_e4_q", "PQ Signer", "mldsa")
    vc = ValidationContext(trust_roots=[classical.asn1, pq.asn1],
                           allow_fetching=False, revocation_mode="soft-fail")
    return classical, pq, vc


def _lta_setup():
    ca = pki.TestPKI("e4")
    classical, _ = ca.issue("_e4l_c", "Classical Signer", "ec")
    pq, _ = ca.issue("_e4l_q", "PQ Signer", "mldsa")
    tsa, tsa_key = ca.issue("_e4l_t", "Test TSA", "rsa", tsa=True)
    stamper = DummyTimeStamper(tsa_cert=tsa.asn1,
                               tsa_key=pki.TestPKI.private_key_info(tsa_key),
                               certs_to_embed=None)
    vc = ValidationContext(trust_roots=[pki.to_a1(ca.root_cert)], crls=[ca.crl()],
                           allow_fetching=False, revocation_mode="hard-fail")
    return ca, classical, pq, stamper, vc


def build_scenarios():
    """Every file the rules are asked to judge, with its ground truth."""
    cases = []
    classical, pq, vc = _plain_setup()

    # ---- plain, order B ----
    base = pdfdoc.make_pdf(paths.art("_e4_B_plain.pdf"))
    b1 = pdfdoc.sign(base, paths.art("_e4_B_1.pdf"), pq, PQ)
    bfull = pdfdoc.sign(b1, paths.art("_e4_B_2.pdf"), classical, CLASSICAL)
    cases.append(("plain order B, honest", bfull, vc, True))

    bforged = pdfdoc.append_forged_revision(
        bfull, paths.art("_e4_B_forged.pdf"), classical, FORGED)
    cases.append(("plain order B, t2 append-forgery", bforged, vc, False))

    # ---- plain, order A ----
    abase = pdfdoc.make_pdf(paths.art("_e4_A_plain.pdf"))
    a1 = pdfdoc.sign(abase, paths.art("_e4_A_1.pdf"), classical, CLASSICAL)
    afull = pdfdoc.sign(a1, paths.art("_e4_A_2.pdf"), pq, PQ)
    cases.append(("plain order A, honest", afull, vc, True))

    data = open(afull, "rb").read()
    cut = revisions.cut_points(data)[-1]
    adown = paths.art("_e4_A_downgraded.pdf")
    open(adown, "wb").write(data[:cut])
    cases.append(("plain order A, truncation-downgraded", adown, vc, False))

    aforged = pdfdoc.append_forged_revision(
        adown, paths.art("_e4_A_forged.pdf"), classical, FORGED)
    cases.append(("plain order A, downgraded then forged", aforged, vc, False))

    # ---- fabricated from scratch ----
    scratch = pdfdoc.make_pdf(paths.art("_e4_scratch.pdf"),
                              amount=pdfdoc.FORGED_AMOUNT)
    sforged = pdfdoc.sign(scratch, paths.art("_e4_scratch_forged.pdf"),
                          classical, FORGED)
    cases.append(("fabricated from scratch, classical only", sforged, vc, False))

    # ---- B-LTA: the false-positive cases that matter ----
    ca, lc, lq, stamper, lvc = _lta_setup()

    lbase = pdfdoc.make_pdf(paths.art("_e4l_B_doc.pdf"), archival=True)
    lb1 = pdfdoc.sign_lta(lbase, paths.art("_e4l_B_inner.pdf"), lq, PQ,
                          stamper, lvc, ca.root_pem)
    lbfull = pdfdoc.sign_lta(lb1, paths.art("_e4l_B_hybrid.pdf"), lc, CLASSICAL,
                             stamper, lvc, ca.root_pem)
    # honest, and its later revisions legitimately append timestamps AFTER the PQ layer
    cases.append(("B-LTA order B, honest (timestamps after PQ)", lbfull, lvc, True))

    lbforged = pdfdoc.append_forged_revision(
        lbfull, paths.art("_e4l_B_forged.pdf"), lc, FORGED,
        chain_pem=ca.root_pem)
    cases.append(("B-LTA order B, t2 append-forgery", lbforged, lvc, False))

    labase = pdfdoc.make_pdf(paths.art("_e4l_A_doc.pdf"), archival=True)
    la1 = pdfdoc.sign_lta(labase, paths.art("_e4l_A_inner.pdf"), lc, CLASSICAL,
                          stamper, lvc, ca.root_pem)
    lafull = pdfdoc.sign_lta(la1, paths.art("_e4l_A_hybrid.pdf"), lq, PQ,
                             stamper, lvc, ca.root_pem)
    cases.append(("B-LTA order A, honest", lafull, lvc, True))

    ldata = open(lafull, "rb").read()
    # the decisive cut: byte-identical to the legitimately archived inner document
    inner_bytes = open(la1, "rb").read()
    dcut = next(c for c in revisions.cut_points(ldata) if ldata[:c] == inner_bytes)
    ladown = paths.art("_e4l_A_downgraded.pdf")
    open(ladown, "wb").write(ldata[:dcut])
    cases.append(("B-LTA order A, truncation-downgraded", ladown, lvc, False))

    return cases


def run(verbose=True):
    cases = build_scenarios()
    rows = []
    for label, path, vc, should_accept in cases:
        sigs = verify.inspect(path, vc)
        n_ok, n_why = naive_rule([r for r in sigs if not r["timestamp"]])
        p_ok, p_why = proposed_rule(sigs)
        rows.append({
            "scenario": label,
            "file": os.path.basename(path),
            "legitimate": should_accept,
            "naive_accepts": n_ok, "naive_why": n_why,
            "proposed_accepts": p_ok, "proposed_why": p_why,
            "naive_correct": n_ok == should_accept,
            "proposed_correct": p_ok == should_accept,
        })

    def matrix(key):
        tp = sum(1 for r in rows if not r["legitimate"] and not r[key])   # forgery rejected
        fn = sum(1 for r in rows if not r["legitimate"] and r[key])       # forgery accepted
        tn = sum(1 for r in rows if r["legitimate"] and r[key])           # honest accepted
        fp = sum(1 for r in rows if r["legitimate"] and not r[key])       # honest rejected
        total = len(rows)
        return {"rejected_attacks": tp, "missed_attacks": fn,
                "accepted_honest": tn, "rejected_honest": fp,
                "detection_rate": tp / (tp + fn) if (tp + fn) else 0.0,
                "false_positive_rate": fp / (fp + tn) if (fp + tn) else 0.0,
                "accuracy": (tp + tn) / total}

    out = {
        "name": "E4 verifier rule: stated, implemented, measured",
        "benign_levels": sorted(BENIGN_LEVELS),
        "cases": rows,
        "naive": matrix("naive_accepts"),
        "proposed": matrix("proposed_accepts"),
        "n_attacks": sum(1 for r in rows if not r["legitimate"]),
        "n_legitimate": sum(1 for r in rows if r["legitimate"]),
    }
    if verbose:
        report(out)
    return out


def report(out):
    print(f"\n{'='*78}\nE4  the proposed verifier rule, implemented and measured\n{'='*78}")
    print(f"  benign modification levels: {', '.join(out['benign_levels'])}")
    print(f"  {out['n_legitimate']} legitimate documents, {out['n_attacks']} attacks\n")
    print(f"  {'scenario':44s} {'truth':10s} {'naive':8s} {'proposed':9s}")
    print(f"  {'-'*44} {'-'*10} {'-'*8} {'-'*9}")
    for r in out["cases"]:
        truth = "legitimate" if r["legitimate"] else "ATTACK"
        n = "accept" if r["naive_accepts"] else "reject"
        p = "accept" if r["proposed_accepts"] else "reject"
        flag = "" if r["proposed_correct"] else "   <-- WRONG"
        print(f"  {r['scenario']:44s} {truth:10s} {n:8s} {p:9s}{flag}")

    print(f"\n  {'':28s} {'naive':>10s} {'proposed':>10s}")
    for k, lbl in (("rejected_attacks", "attacks rejected"),
                   ("missed_attacks", "attacks MISSED"),
                   ("accepted_honest", "honest accepted"),
                   ("rejected_honest", "honest rejected (FP)")):
        print(f"  {lbl:28s} {out['naive'][k]:>10} {out['proposed'][k]:>10}")
    for k, lbl in (("detection_rate", "detection rate"),
                   ("false_positive_rate", "false-positive rate"),
                   ("accuracy", "accuracy")):
        print(f"  {lbl:28s} {out['naive'][k]:>10.0%} {out['proposed'][k]:>10.0%}")

    print(f"\n  >>> the naive rule misses {out['naive']['missed_attacks']} of "
          f"{out['n_attacks']} attacks; the proposed rule misses "
          f"{out['proposed']['missed_attacks']}, with "
          f"{out['proposed']['rejected_honest']} false positives on archival documents.")


if __name__ == "__main__":
    run()
