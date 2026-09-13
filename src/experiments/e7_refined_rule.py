#!/usr/bin/env python3
"""
E7 — the refined rule: which field changed, not how coarsely it changed.

E6 showed the rule of Section VI accepts a forgery. An adversary holding the
broken classical key at t2 sets /V on an existing AcroForm field; pyHanko
classifies that as FORM_FILLING; FORM_FILLING is in the benign set; the document
renders a forged amount and the rule accepts it.

FORM_FILLING cannot simply be removed from the benign set. Both honest order-B
documents -- the order the paper recommends -- report FORM_FILLING too, because
appending the outer signature means creating a signature field, and creating a
field is a form modification. At the granularity of `modification_level` the
honest act and the hostile one are the same event.

So the rule must ask a finer question. pyHanko already answers it: a successful
diff yields a DiffResult carrying the SET OF FIELD NAMES that changed. The
refined rule:

    R1  require-PQ        an intact, valid post-quantum signature is present
    R2' field-restricted  if the level is FORM_FILLING, every field changed
                          after the post-quantum signature must be a SIGNATURE
                          field. Any ordinary field whose value moved is a
                          rejection.

    NONE and LTA_UPDATES are accepted as before; anything else is rejected.

Expected discrimination, which this script measures rather than assumes:

    honest order B      changed = {ClassicalLayer}            all sig fields -> accept
    honest B-LTA        changed = {ClassicalLayer, DocTimeStamp} sig fields -> accept
    V1/V2 form forgery  changed = {ForgedClassical, amount}   'amount' is not -> REJECT
    V3/V4               level OTHER                                          -> reject

The script prints the raw DiffResult contents for every case before applying any
rule, so that if the attribute carrying the field names is named differently in
this pyHanko build, the output still says what is available instead of failing
silently.

Run from the repository root:  python src/experiments/e7_refined_rule.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

from hybridpdf import paths, pki, pdfdoc
from experiments import e6_formfill_probe as e6

PQ, CLASSICAL, FORGED = "PQLayer", "ClassicalLayer", "ForgedClassical"

COARSE_BENIGN = {"NONE", "LTA_UPDATES"}          # accepted outright
FIELD_GATED = "FORM_FILLING"                      # accepted only under R2'


def _enum(v):
    return None if v is None else str(v).split(".")[-1]


def signature_fields(path):
    """Names of every AcroForm field of type /Sig in the final document.

    Document timestamps occupy signature fields too, so this covers the
    legitimate B-LTA appends without special-casing them.
    """
    names = set()
    with open(path, "rb") as f:
        reader = PdfFileReader(f)
        try:
            acro = reader.root["/AcroForm"]
            acro = acro.get_object() if hasattr(acro, "get_object") else acro
            fields = acro.get("/Fields")
            fields = fields.get_object() if hasattr(fields, "get_object") else fields
            for ref in (fields or []):
                obj = ref.get_object()
                ft = obj.get("/FT")
                t = obj.get("/T")
                if ft is not None and str(ft) == "/Sig" and t is not None:
                    names.add(str(t))
        except Exception:
            pass
        # whatever AcroForm traversal missed, an embedded signature proves
        for s in reader.embedded_signatures:
            if s.field_name:
                names.add(str(s.field_name))
    return names


def pq_status(path, vc, field=PQ):
    """Validate the post-quantum signature and extract the diff detail."""
    with open(path, "rb") as f:
        reader = PdfFileReader(f)
        for s in reader.embedded_signatures:
            if s.field_name != field:
                continue
            st = validate_pdf_signature(s, vc)
            dr = getattr(st, "diff_result", None)
            changed = getattr(dr, "changed_form_fields", None)
            return {
                "present": True,
                "intact": bool(getattr(st, "intact", False)),
                "valid": bool(getattr(st, "valid", False)),
                "coverage": _enum(getattr(st, "coverage", None)),
                "level": _enum(getattr(st, "modification_level", None)),
                "diff_type": type(dr).__name__ if dr is not None else None,
                "diff_attrs": [a for a in dir(dr) if not a.startswith("_")][:12]
                              if dr is not None else [],
                "changed_fields": (sorted(str(x) for x in changed)
                                   if changed is not None else None),
            }
    return {"present": False, "intact": False, "valid": False, "coverage": None,
            "level": None, "diff_type": None, "diff_attrs": [],
            "changed_fields": None}


# ------------------------------------------------------------------ the rules
def rule_current(st):
    """Section VI as published: level in {NONE, LTA_UPDATES, FORM_FILLING}."""
    if not st["present"]:
        return False, "R1 fails: no post-quantum signature"
    if not (st["intact"] and st["valid"]):
        return False, "R1 fails: post-quantum signature does not verify"
    if st["level"] in COARSE_BENIGN or st["level"] == FIELD_GATED:
        return True, f"level {st['level']} is benign"
    return False, f"R2 fails: level {st['level']}"


def rule_refined(st, sig_fields):
    """R1 + R2': FORM_FILLING allowed only for signature fields."""
    if not st["present"]:
        return False, "R1 fails: no post-quantum signature"
    if not (st["intact"] and st["valid"]):
        return False, "R1 fails: post-quantum signature does not verify"

    lvl = st["level"]
    if lvl in COARSE_BENIGN:
        return True, f"R2' holds: level {lvl}, no form change"
    if lvl != FIELD_GATED:
        return False, f"R2' fails: level {lvl}"

    changed = st["changed_fields"]
    if changed is None:
        # the rule is undecidable rather than satisfied; say so instead of
        # defaulting to accept, which is the failure mode this paper is about
        return None, "R2' undecidable: pyHanko exposed no changed-field set"

    intruders = [c for c in changed if c not in sig_fields]
    if intruders:
        return False, ("R2' fails: non-signature field(s) changed after the "
                       f"post-quantum signature: {', '.join(intruders)}")
    return True, f"R2' holds: only signature fields changed ({', '.join(changed)})"


# -------------------------------------------------------------------- corpus
def build_corpus():
    """The E6 variants plus an honest order-A document, all plain (no B-LTA).

    Ground truth is recorded per case so the two rules can be scored, not just
    described.
    """
    paths.ensure()
    classical = pki.selfsigned("_e7_c", "Classical Signer", "ec")
    pq = pki.selfsigned("_e7_q", "PQ Signer", "mldsa")
    vc = ValidationContext(trust_roots=[classical.asn1, pq.asn1],
                           allow_fetching=False, revocation_mode="soft-fail")

    cases = []

    # --- form document, order B ------------------------------------------
    fbase = e6.make_form_pdf(paths.art("_e7_form_plain.pdf"))
    f1 = pdfdoc.sign(fbase, paths.art("_e7_form_1.pdf"), pq, PQ)
    formB = pdfdoc.sign(f1, paths.art("_e7_form_2.pdf"), classical, CLASSICAL)
    cases.append(("form order-B, honest", formB, True))

    for tag, need_ap in (("form order-B, t2 field-fill forgery", False),
                         ("form order-B, field-fill + NeedAppearances", True)):
        dst = paths.art(f"_e7_fill_{int(need_ap)}.pdf")
        try:
            p = e6.fill_existing_field(formB, dst, classical, FORGED,
                                       need_appearances=need_ap)
            cases.append((tag, p, False))
        except Exception as ex:
            print(f"  [could not build] {tag}: {type(ex).__name__}: {ex}")

    # --- plain document, order B -----------------------------------------
    pbase = pdfdoc.make_pdf(paths.art("_e7_plain.pdf"))
    p1 = pdfdoc.sign(pbase, paths.art("_e7_plain_1.pdf"), pq, PQ)
    plainB = pdfdoc.sign(p1, paths.art("_e7_plain_2.pdf"), classical, CLASSICAL)
    cases.append(("plain order-B, honest", plainB, True))

    try:
        p = e6.create_field_then_fill(plainB, paths.art("_e7_newfield.pdf"),
                                      classical, FORGED)
        cases.append(("plain order-B, t2 field-creation forgery", p, False))
    except Exception as ex:
        print(f"  [could not build] field creation: {type(ex).__name__}: {ex}")

    p = pdfdoc.append_forged_revision(plainB, paths.art("_e7_override.pdf"),
                                      classical, FORGED)
    cases.append(("plain order-B, t2 /Contents override", p, False))

    # --- plain document, order A (honest) --------------------------------
    abase = pdfdoc.make_pdf(paths.art("_e7_A_plain.pdf"))
    a1 = pdfdoc.sign(abase, paths.art("_e7_A_1.pdf"), classical, CLASSICAL)
    plainA = pdfdoc.sign(a1, paths.art("_e7_A_2.pdf"), pq, PQ)
    cases.append(("plain order-A, honest", plainA, True))

    return cases, vc


# -------------------------------------------------------------------- report
def run(verbose=True):
    cases, vc = build_corpus()
    rows = []

    for name, path, legitimate in cases:
        st = pq_status(path, vc)
        sigf = signature_fields(path)
        cur_ok, cur_why = rule_current(st)
        ref_ok, ref_why = rule_refined(st, sigf)
        rows.append({
            "case": name, "legitimate": legitimate, "file": os.path.basename(path),
            "level": st["level"], "coverage": st["coverage"],
            "diff_type": st["diff_type"], "diff_attrs": st["diff_attrs"],
            "changed_fields": st["changed_fields"],
            "signature_fields": sorted(sigf),
            "current_accepts": cur_ok, "current_why": cur_why,
            "refined_accepts": ref_ok, "refined_why": ref_why,
        })

    if verbose:
        report(rows)
    return rows


def _score(rows, key):
    """(attacks missed, honest rejected, undecidable)."""
    missed = sum(1 for r in rows if not r["legitimate"] and r[key] is True)
    fp = sum(1 for r in rows if r["legitimate"] and r[key] is False)
    und = sum(1 for r in rows if r[key] is None)
    return missed, fp, und


def report(rows):
    print(f"\n{'='*92}")
    print("E7  refined rule -- accept FORM_FILLING only for signature fields")
    print(f"{'='*92}")

    # diagnostics first: if the API differs, this is what tells us
    dt = {r["diff_type"] for r in rows if r["diff_type"]}
    print(f"  DiffResult types seen: {', '.join(sorted(dt)) or 'none'}")
    for r in rows:
        if r["changed_fields"] is None and r["diff_attrs"]:
            print(f"  !! no changed-field set on {r['file']}; "
                  f"available attributes: {r['diff_attrs']}")
            break

    print(f"\n  {'case':44s} {'level':14s} {'changed fields':28s} cur  ref")
    print(f"  {'-'*44} {'-'*14} {'-'*28} ---  ---")
    for r in rows:
        ch = ", ".join(r["changed_fields"]) if r["changed_fields"] is not None else "-"
        cur = "ACC" if r["current_accepts"] else "rej"
        ref = "ACC" if r["refined_accepts"] else ("rej" if r["refined_accepts"] is False else "UND")
        print(f"  {r['case']:44s} {str(r['level']):14s} {ch[:28]:28s} {cur:4s} {ref}")

    n_att = sum(1 for r in rows if not r["legitimate"])
    n_leg = sum(1 for r in rows if r["legitimate"])
    cm, cf, cu = _score(rows, "current_accepts")
    rm, rf, ru = _score(rows, "refined_accepts")

    print(f"\n{'-'*92}")
    print(f"  corpus: {n_att} attacks, {n_leg} legitimate documents")
    print(f"  {'rule':26s} {'attacks missed':16s} {'honest rejected':17s} undecidable")
    print(f"  {'current (Section VI)':26s} {cm:<16d} {cf:<17d} {cu}")
    print(f"  {'refined (R2-prime)':26s} {rm:<16d} {rf:<17d} {ru}")

    print()
    for r in rows:
        if r["current_accepts"] and not r["legitimate"]:
            print(f"  current rule accepts an attack: {r['case']}")
            print(f"      {r['current_why']}")
    for r in rows:
        if r["refined_accepts"] is False and r["legitimate"]:
            print(f"  refined rule rejects an honest document: {r['case']}")
            print(f"      {r['refined_why']}")

    print(f"\n{'-'*92}")
    if rm == 0 and rf == 0 and ru == 0 and cm > 0:
        print("  RESULT: R2' closes the hole E6 opened, with no false positive")
        print("  and nothing left undecidable. Section VI should state the rule")
        print("  over the changed-field set, and report the coarse version as")
        print("  the natural formulation that fails.")
    elif ru:
        print("  RESULT: undecidable cases remain -- pyHanko did not expose the")
        print("  changed-field set for every document. Read the diagnostics above")
        print("  before drawing any conclusion.")
    else:
        print("  RESULT: R2' does not cleanly separate the corpus. The numbers")
        print("  above are the finding; do not tune the rule to improve them.")
    print(f"{'-'*92}\n")


if __name__ == "__main__":
    run()
