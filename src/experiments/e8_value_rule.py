#!/usr/bin/env python3
"""
E8 — the rule stated over what the document says, not over how it was edited.

Three abstractions have now failed to separate an honest order-B document from a
t2 forgery, each for the same reason:

    coverage             both report ENTIRE_REVISION            (E3)
    modification_level   both report FORM_FILLING               (E6)
    changed_form_fields  both list 'amount' as changed          (E7)

Every one of them is a library's taxonomy of STRUCTURAL EDITS. The claim the
paper makes is about RENDERED CONTENT. E7 settled that these are not the same
question: signing a form document legitimately puts the form's own field in the
changed set, so a rule keyed on field identity rejects honest documents.

Field VALUES answer the actual question. This module reads the value of every
non-signature form field twice -- once in the revision the post-quantum
signature covers, once in the final file -- and requires them to agree:

    R1   require-PQ     an intact, valid post-quantum signature is present
    R2'' value-stable   no ordinary form field's /V differs between the revision
                        the post-quantum signature covers and the final document

This is deliberately NOT phrased over pyHanko's diff taxonomy. It reads two PDF
states and compares them, so an independent validator -- DSS included -- can
implement the same check without sharing pyHanko's classification of edits.

The covered revision is recovered from the signature's own byte range. For
/ByteRange [0 a b c] the signed bytes are [0,a) and [b, b+c); b+c is therefore
the end of the revision the signature attests to, and truncating the file there
yields exactly the document the signer saw.

Run from the repository root:  python src/experiments/e8_value_rule.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature

from hybridpdf import paths
from experiments import e7_refined_rule as e7

PQ = "PQLayer"
COARSE_BENIGN = {"NONE", "LTA_UPDATES"}
FIELD_GATED = "FORM_FILLING"


def _enum(v):
    return None if v is None else str(v).split(".")[-1]


def _walk_fields(node, prefix, out, depth=0):
    """Collect (qualified name -> (field type, value)) over the field tree."""
    if depth > 8:
        return
    obj = node.get_object() if hasattr(node, "get_object") else node
    if not hasattr(obj, "get"):
        return
    t = obj.get("/T")
    name = f"{prefix}.{t}" if (prefix and t is not None) else (
        str(t) if t is not None else prefix)
    kids = obj.get("/Kids")
    kids = kids.get_object() if hasattr(kids, "get_object") else kids
    if kids:
        for k in kids:
            _walk_fields(k, name, out, depth + 1)
        return
    if t is None:
        return
    ft = obj.get("/FT")
    v = obj.get("/V")
    v = v.get_object() if hasattr(v, "get_object") else v
    out[str(name)] = (str(ft) if ft is not None else None,
                      None if v is None else str(v))


def field_values(path):
    """{field name: value} for every non-signature form field, or {} if none."""
    table = {}
    try:
        with open(path, "rb") as f:
            reader = PdfFileReader(f)
            root = reader.root
            if "/AcroForm" not in root:
                return {}
            acro = root["/AcroForm"]
            acro = acro.get_object() if hasattr(acro, "get_object") else acro
            fields = acro.get("/Fields")
            fields = fields.get_object() if hasattr(fields, "get_object") else fields
            raw = {}
            for ref in (fields or []):
                _walk_fields(ref, "", raw, 0)
            for name, (ft, v) in raw.items():
                if ft == "/Sig":
                    continue          # signature fields are expected to appear
                table[name] = v
    except Exception as e:
        return {"__error__": f"{type(e).__name__}: {e}"}
    return table


def covered_revision(path, out_path, field=PQ):
    """Write the document as it stood when `field` was signed.

    Returns (path, end_offset) or (None, None) if the signature is absent.
    """
    with open(path, "rb") as f:
        reader = PdfFileReader(f)
        br = None
        for s in reader.embedded_signatures:
            if s.field_name == field:
                br = list(s.byte_range)
                break
    if br is None or len(br) != 4:
        return None, None
    end = br[2] + br[3]
    data = open(path, "rb").read()
    open(out_path, "wb").write(data[:end])
    return out_path, end


def pq_state(path, vc, field=PQ):
    with open(path, "rb") as f:
        reader = PdfFileReader(f)
        for s in reader.embedded_signatures:
            if s.field_name != field:
                continue
            st = validate_pdf_signature(s, vc)
            return {"present": True,
                    "intact": bool(getattr(st, "intact", False)),
                    "valid": bool(getattr(st, "valid", False)),
                    "level": _enum(getattr(st, "modification_level", None))}
    return {"present": False, "intact": False, "valid": False, "level": None}


# ------------------------------------------------------------------- the rule
def rule_value_stable(path, vc, tag):
    """R1 + R2'': no ordinary field's value moved after the PQ signature."""
    st = pq_state(path, vc)
    if not st["present"]:
        return False, "R1 fails: no post-quantum signature", {}
    if not (st["intact"] and st["valid"]):
        return False, "R1 fails: post-quantum signature does not verify", {}

    lvl = st["level"]
    if lvl in COARSE_BENIGN:
        return True, f"R2'' holds: level {lvl}, no form change at all", {}
    if lvl != FIELD_GATED:
        return False, f"R2'' fails: level {lvl}", {}

    prefix = paths.art(f"_e8_{tag}_covered.pdf")
    rev, end = covered_revision(path, prefix)
    if rev is None:
        return None, "R2'' undecidable: no byte range for the PQ signature", {}

    before, after = field_values(rev), field_values(path)
    if "__error__" in before or "__error__" in after:
        return None, ("R2'' undecidable: could not read fields "
                      f"({before.get('__error__') or after.get('__error__')})"), {}

    moved = {}
    for name in sorted(set(before) | set(after)):
        b, a = before.get(name, "<absent>"), after.get(name, "<absent>")
        if b != a:
            moved[name] = (b, a)

    if moved:
        detail = "; ".join(f"{k}: {v[0]!r} -> {v[1]!r}" for k, v in moved.items())
        return False, f"R2'' fails: field value changed -- {detail}", moved
    return True, (f"R2'' holds: {len(after)} ordinary field(s) unchanged "
                  f"across the covered revision"), {}


def run(verbose=True):
    cases, vc = e7.build_corpus()
    rows = []
    for i, (name, path, legitimate) in enumerate(cases):
        ok, why, moved = rule_value_stable(path, vc, f"c{i}")
        st = pq_state(path, vc)
        rows.append({"case": name, "file": os.path.basename(path),
                     "legitimate": legitimate, "level": st["level"],
                     "accepts": ok, "why": why, "moved": moved})
    if verbose:
        report(rows)
    return rows


def report(rows):
    print(f"\n{'='*94}")
    print("E8  rule over form field VALUES across the post-quantum covered revision")
    print(f"{'='*94}")
    print(f"  {'case':46s} {'level':14s} {'truth':11s} verdict")
    print(f"  {'-'*46} {'-'*14} {'-'*11} -------")
    for r in rows:
        truth = "legitimate" if r["legitimate"] else "ATTACK"
        v = "accept" if r["accepts"] else ("reject" if r["accepts"] is False else "UNDECIDED")
        print(f"  {r['case']:46s} {str(r['level']):14s} {truth:11s} {v}")

    print(f"\n{'-'*94}\n  evidence\n{'-'*94}")
    for r in rows:
        print(f"  {r['case']}")
        print(f"      {r['why']}")

    att = [r for r in rows if not r["legitimate"]]
    leg = [r for r in rows if r["legitimate"]]
    missed = sum(1 for r in att if r["accepts"] is True)
    fp = sum(1 for r in leg if r["accepts"] is False)
    und = sum(1 for r in rows if r["accepts"] is None)

    print(f"\n{'-'*94}")
    print(f"  corpus: {len(att)} attacks, {len(leg)} legitimate documents")
    print(f"  attacks missed {missed}   honest rejected {fp}   undecided {und}")
    print(f"{'-'*94}")
    if missed == 0 and fp == 0 and und == 0:
        print("  RESULT: R2'' separates the corpus cleanly. The rule the paper")
        print("  should state is over field values, not over a diff taxonomy;")
        print("  E6 and E7 become the two natural formulations that fail, which")
        print("  is why the working one has to be stated where it is.")
    else:
        print("  RESULT: R2'' does not separate the corpus. These numbers are the")
        print("  finding. Do NOT adjust the rule to improve them -- report them.")
    print(f"{'-'*94}\n")


if __name__ == "__main__":
    run()
