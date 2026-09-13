#!/usr/bin/env python3
"""
E9 — two bypasses nobody has tried against the rules of E4, E7 and E8.

E6 broke E4 by asking what the rule actually checks instead of what the paper
says it checks. This file asks the same question of two assumptions all three
rules still share.

B1  FIELD-NAME SPOOFING
    Every rule locates "the post-quantum signature" with
        s.field_name == "PQLayer"
    A field name is attacker-chosen text. At t2 the adversary holds the classical
    key, so it can sign fabricated content with ECDSA in a field it names
    "PQLayer". R1 ("an intact, valid post-quantum signature is present") is then
    satisfied by a classical signature.

        B1a  fabricated from scratch, one ECDSA signature named PQLayer
        B1b  order-A document truncated to classical-only, then a content
             override appended and signed with ECDSA under the name PQLayer

    Fix measured here: R1 must identify the post-quantum signature by the
    algorithm OID in its CMS SignerInfo (id-ml-dsa-*), never by its field name.

B2  APPEARANCE-ONLY FORGERY
    E8 compares form field VALUES (/V). A viewer does not render /V; it renders
    the widget's appearance stream (/AP /N) whenever one is present and
    /NeedAppearances is not set. So the adversary rewrites /AP to draw a forged
    amount and leaves /V untouched.

        B2   form order-B document, /AP /N replaced, /V unchanged

    If pyHanko calls this FORM_FILLING and /V is unchanged, E8 accepts a document
    that renders 100,000 USD over a post-quantum signature on 1,000 USD.

Nothing here is tuned. Each variant is built, validated, and scored by the
rules exactly as the other modules define them.

Run from the repository root:  python src/experiments/e9_rule_bypass_probe.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.fields import SigFieldSpec, append_signature_field
from pyhanko_certvalidator import ValidationContext

from hybridpdf import paths, pki, pdfdoc, revisions, verify
from experiments import e4_verifier_rule as e4
from experiments import e6_formfill_probe as e6
from experiments import e7_refined_rule as e7
from experiments import e8_value_rule as e8

PQ, CLASSICAL, FORGED = "PQLayer", "ClassicalLayer", "ForgedClassical"

# id-ml-dsa-44 / -65 / -87 (NIST CSOR, FIPS 204)
ML_DSA_OIDS = {"2.16.840.1.101.3.4.3.17",
               "2.16.840.1.101.3.4.3.18",
               "2.16.840.1.101.3.4.3.19"}


# ------------------------------------------------------------------ helpers
def signature_oids(path):
    """{field name: signature algorithm OID} straight from each CMS SignerInfo."""
    out = {}
    with open(path, "rb") as f:
        reader = PdfFileReader(f)
        for s in reader.embedded_signatures:
            if s.sig_object.get("/Type") == "/DocTimeStamp":
                continue
            try:
                out[s.field_name] = s.signer_info["signature_algorithm"]["algorithm"].dotted
            except Exception:
                out[s.field_name] = None
    return out


def r1_by_oid(path, rows):
    """R1 done properly: a valid signature whose ALGORITHM is ML-DSA."""
    oids = signature_oids(path)
    for r in rows:
        if r["timestamp"]:
            continue
        if oids.get(r["field"]) in ML_DSA_OIDS and r["intact"] and r["valid"]:
            return True, f"ML-DSA signature present in field {r['field']!r}"
    named = [f for f in oids if f == PQ]
    if named:
        return False, (f"R1 fails: field {PQ!r} exists but its algorithm is "
                       f"{oids[PQ]}, not ML-DSA")
    return False, "R1 fails: no ML-DSA signature"


# ------------------------------------------------------------------ B1 builds
def spoof_from_scratch(classical):
    base = pdfdoc.make_pdf(paths.art("_e9_B1a_plain.pdf"), amount=pdfdoc.FORGED_AMOUNT)
    return pdfdoc.sign(base, paths.art("_e9_B1a_spoof.pdf"), classical, PQ)


def spoof_after_truncation(classical, pq):
    base = pdfdoc.make_pdf(paths.art("_e9_B1b_plain.pdf"))
    a1 = pdfdoc.sign(base, paths.art("_e9_B1b_1.pdf"), classical, CLASSICAL)
    full = pdfdoc.sign(a1, paths.art("_e9_B1b_2.pdf"), pq, PQ)
    data = open(full, "rb").read()
    cut = revisions.cut_points(data)[-1]
    trunc = paths.art("_e9_B1b_trunc.pdf")
    open(trunc, "wb").write(data[:cut])
    # content override + an ECDSA signature the adversary names "PQLayer"
    return pdfdoc.append_forged_revision(trunc, paths.art("_e9_B1b_spoof.pdf"),
                                         classical, PQ)


# ------------------------------------------------------------------ B2 build
def _first_font_key(res):
    res = res.get_object() if hasattr(res, "get_object") else res
    fonts = res.get("/Font") if res is not None else None
    fonts = fonts.get_object() if hasattr(fonts, "get_object") else fonts
    return list(fonts.keys())[0] if fonts else None


def appearance_only_forgery(src, dst, signer, amount=pdfdoc.FORGED_AMOUNT):
    """Replace the amount widget's normal appearance; leave /V alone."""
    with open(src, "rb") as inf:
        w = IncrementalPdfFileWriter(inf)
        ref, fobj = e6._find_field(w, e6.FIELD)
        if fobj is None:
            raise RuntimeError("no amount field")

        ap = fobj.get("/AP")
        ap = ap.get_object() if hasattr(ap, "get_object") else ap
        old_n = ap["/N"].get_object() if ap is not None and "/N" in ap else None
        if old_n is None:
            raise RuntimeError("field carries no normal appearance to replace")

        bbox = old_n.get("/BBox")
        resources = old_n.get("/Resources")
        font = _first_font_key(resources) if resources is not None else None
        if font is None:
            raise RuntimeError("existing appearance has no font resource")

        body = (f"/Tx BMC q BT {font} 14 Tf 2 5 Td ({amount}) Tj ET Q EMC"
                ).encode("ascii")
        new_n = generic.StreamObject(
            dict_data={
                generic.NameObject("/Type"): generic.NameObject("/XObject"),
                generic.NameObject("/Subtype"): generic.NameObject("/Form"),
                generic.NameObject("/BBox"): bbox,
                generic.NameObject("/Resources"): resources,
            },
            stream_data=body)
        new_ref = w.add_object(new_n)

        fobj[generic.NameObject("/AP")] = generic.DictionaryObject(
            {generic.NameObject("/N"): new_ref})
        w.update_container(fobj)

        append_signature_field(w, SigFieldSpec(sig_field_name=FORGED))
        sg = signers.SimpleSigner.load(signer.key_path, signer.cert_path)
        with open(dst, "wb") as outf:
            signers.sign_pdf(w, signers.PdfSignatureMetadata(field_name=FORGED),
                             signer=sg, output=outf)
    return dst


def rendered_amount_in_ap(path):
    """The literal text drawn by the amount widget's /AP /N, if any."""
    with open(path, "rb") as f:
        r = PdfFileReader(f)
        acro = r.root["/AcroForm"].get_object()
        for ref in acro["/Fields"]:
            obj = ref.get_object()
            if str(obj.get("/T")) == e6.FIELD:
                n = obj["/AP"].get_object()["/N"].get_object()
                data = n.data
                for amt in (pdfdoc.FORGED_AMOUNT, pdfdoc.HONEST_AMOUNT):
                    if amt.encode() in data:
                        return amt
                return "<other>"
    return None


# ------------------------------------------------------------------ candidate fix for B2
def appearance_digests(path):
    """{field name: sha256 of its decoded /AP /N stream} for non-signature fields."""
    import hashlib
    out = {}
    try:
        with open(path, "rb") as f:
            r = PdfFileReader(f)
            if "/AcroForm" not in r.root:
                return out
            acro = r.root["/AcroForm"].get_object()
            for ref in (acro.get("/Fields") or []):
                obj = ref.get_object()
                if str(obj.get("/FT")) == "/Sig":
                    continue
                ap = obj.get("/AP")
                ap = ap.get_object() if hasattr(ap, "get_object") else ap
                if ap is None or "/N" not in ap:
                    out[str(obj.get("/T"))] = None
                    continue
                n = ap["/N"].get_object()
                out[str(obj.get("/T"))] = hashlib.sha256(n.data).hexdigest()
    except Exception as e:
        out["__error__"] = f"{type(e).__name__}: {e}"
    return out


def rule_rendered_stable(path, vc, tag, rows):
    """R1 by algorithm + E8's value check + appearance streams unchanged."""
    ok1, why1 = r1_by_oid(path, rows)
    if not ok1:
        return False, why1
    ok8, why8, _ = e8.rule_value_stable(path, vc, tag)
    if ok8 is not True:
        return ok8, why8
    rev, _ = e8.covered_revision(path, paths.art(f"_e9_{tag}_cov.pdf"))
    if rev is None:
        return True, why8            # level NONE / LTA path: no covered-form check needed
    before, after = appearance_digests(rev), appearance_digests(path)
    if "__error__" in before or "__error__" in after:
        return None, "undecidable: could not read appearance streams"
    moved = [k for k in sorted(set(before) | set(after)) if before.get(k) != after.get(k)]
    if moved:
        return False, f"appearance stream changed after the PQ signature: {', '.join(moved)}"
    return True, f"values and {len(after)} appearance stream(s) unchanged"


# ------------------------------------------------------------------ run
def run(verbose=True):
    paths.ensure()
    classical = pki.selfsigned("_e9_c", "Classical Signer", "ec")
    pq = pki.selfsigned("_e9_q", "PQ Signer", "mldsa")
    vc = ValidationContext(trust_roots=[classical.asn1, pq.asn1],
                           allow_fetching=False, revocation_mode="soft-fail")

    cases = []

    # honest controls: a fixed R1 must not reject these
    pbase = pdfdoc.make_pdf(paths.art("_e9_hB_plain.pdf"))
    hb1 = pdfdoc.sign(pbase, paths.art("_e9_hB_1.pdf"), pq, PQ)
    honestB = pdfdoc.sign(hb1, paths.art("_e9_hB_2.pdf"), classical, CLASSICAL)
    cases.append(("honest plain order-B", honestB, True, None))

    fbase = e6.make_form_pdf(paths.art("_e9_form_plain.pdf"))
    f1 = pdfdoc.sign(fbase, paths.art("_e9_form_1.pdf"), pq, PQ)
    formB = pdfdoc.sign(f1, paths.art("_e9_form_2.pdf"), classical, CLASSICAL)
    cases.append(("honest form order-B", formB, True, None))

    # B1
    cases.append(("B1a spoof: scratch, ECDSA named PQLayer",
                  spoof_from_scratch(classical), False, None))
    cases.append(("B1b spoof: truncate A, override, ECDSA named PQLayer",
                  spoof_after_truncation(classical, pq), False, None))

    # B2
    try:
        b2 = appearance_only_forgery(formB, paths.art("_e9_B2_apforge.pdf"), classical)
        cases.append(("B2 appearance-only forgery (/V unchanged)", b2, False,
                      rendered_amount_in_ap(b2)))
    except Exception as ex:
        cases.append(("B2 appearance-only forgery (/V unchanged)", None, False,
                      f"could not build: {type(ex).__name__}: {ex}"))

    rows = []
    for i, (name, path, legit, note) in enumerate(cases):
        if path is None:
            rows.append({"case": name, "legitimate": legit, "note": note,
                         "built": False})
            continue
        sig_rows = verify.inspect(path, vc)
        pqrow = verify.find(sig_rows, PQ)
        e4_ok, e4_why = e4.proposed_rule(sig_rows)
        e7_ok, e7_why = e7.rule_refined(
            e7.pq_status(path, vc), e7.signature_fields(path))
        e8_ok, e8_why, _ = e8.rule_value_stable(path, vc, f"e9c{i}")
        oid_ok, oid_why = r1_by_oid(path, sig_rows)
        # E8 with R1 done by algorithm: both halves must hold
        e8_fixed = (e8_ok is True) and oid_ok
        rend_ok, rend_why = rule_rendered_stable(path, vc, f"r{i}", sig_rows)
        rows.append({
            "rendered": rend_ok, "rendered_why": rend_why,
            "case": name, "legitimate": legit, "built": True,
            "note": note,
            "oids": signature_oids(path),
            "pq_level": pqrow["modification_level"] if pqrow else None,
            "e4": e4_ok, "e4_why": e4_why,
            "e7": e7_ok, "e7_why": e7_why,
            "e8": e8_ok, "e8_why": e8_why,
            "r1_oid": oid_ok, "r1_oid_why": oid_why,
            "e8_with_oid_r1": e8_fixed,
        })

    out = {"name": "E9 rule bypass probe", "rows": rows}
    if verbose:
        report(out)
    return out


def _v(x):
    return "ACCEPT" if x is True else ("reject" if x is False else "undec.")


def report(out):
    print(f"\n{'='*100}")
    print("E9  bypasses of the verifier rules: field-name spoofing, appearance-only forgery")
    print(f"{'='*100}")
    print(f"  {'case':52s} {'truth':7s} {'E4':7s} {'E8':7s} {'E8+R1(oid)':11s} {'+AP check':9s}")
    print(f"  {'-'*52} {'-'*7} {'-'*7} {'-'*7} {'-'*11} {'-'*9}")
    for r in out["rows"]:
        truth = "legit" if r["legitimate"] else "ATTACK"
        if not r["built"]:
            print(f"  {r['case']:52s} {truth:7s} -- {r['note']}")
            continue
        flag = ""
        if not r["legitimate"] and r["rendered"] is True:
            flag = "   <-- STILL ACCEPTED"
        if r["legitimate"] and r["rendered"] is not True:
            flag = "   <-- honest REJECTED"
        print(f"  {r['case']:52s} {truth:7s} {_v(r['e4']):7s} {_v(r['e8']):7s} "
              f"{_v(r['e8_with_oid_r1']):11s} {_v(r['rendered']):9s}{flag}")

    print(f"\n{'-'*100}\n  evidence\n{'-'*100}")
    for r in out["rows"]:
        if not r["built"]:
            continue
        print(f"  {r['case']}")
        print(f"      signature algorithms : {r['oids']}")
        print(f"      PQLayer mod-level    : {r['pq_level']}")
        if r["note"]:
            print(f"      /AP /N draws         : {r['note']}")
        print(f"      E8                   : {r['e8_why']}")
        print(f"      R1 by algorithm      : {r['r1_oid_why']}")
        print(f"      +AP check            : {r['rendered_why']}")
    print()


if __name__ == "__main__":
    run()
