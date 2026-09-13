#!/usr/bin/env python3
"""
E6 — probe: can the t2 adversary land inside the rule's benign set?

E4 accepts a document when the post-quantum signature's modification level is in
{NONE, LTA_UPDATES, FORM_FILLING}. That set is not a convenience: numbers.json
shows BOTH honest order-B documents -- plain and B-LTA, the very order the paper
recommends -- report FORM_FILLING, because the later revision adds the classical
signature field. Drop FORM_FILLING from the set and the rule rejects its own
recommendation.

So FORM_FILLING must stay. But FORM_FILLING permits changing the VALUE of a form
field, and a form field value is rendered. None of E4's six attacks lands there:
four are caught by R1 (no PQ layer at all) and two by R2 with level OTHER, which
is what a /Contents override produces. The rule has never been tested against an
adversary who changes what the page shows WITHOUT touching /Contents.

That adversary is realistic. Real signed contracts are frequently AcroForm
documents. An adversary holding the broken classical key at t2 does not need to
paint over the page -- it can fill the field the page was built around.

This script does not assume an answer. It builds three variants and reports the
modification level pyHanko assigns to each:

    V1  form document, adversary sets /V on an EXISTING field
    V2  same, plus /NeedAppearances so a viewer re-renders the value
    V3  non-form document, adversary CREATES a field  (expected harsher)

Read the output as follows:

    any variant reporting FORM_FILLING  -> the E4 rule is defeated; R2 as stated
                                           in the paper ("no revision altered
                                           page content") is not what the code
                                           enforces, and the 0-missed result is
                                           an artifact of the attack set
    all variants reporting OTHER        -> the rule survives a real probe, and
                                           this becomes a strengthening result
                                           rather than a correction

Either outcome is publishable. Only leaving it unmeasured is not.

Run from the repository root:   python src/experiments/e6_formfill_probe.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reportlab.pdfgen import canvas as rl_canvas

from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
from pyhanko.sign.fields import SigFieldSpec, append_signature_field
from pyhanko_certvalidator import ValidationContext

from hybridpdf import paths, pki, pdfdoc, verify

CLASSICAL, PQ, FORGED = "ClassicalLayer", "PQLayer", "ForgedClassical"
FIELD = "amount"

# the set E4 treats as benign; kept here verbatim so this file is self-contained
BENIGN_LEVELS = {"NONE", "LTA_UPDATES", "FORM_FILLING"}


# --------------------------------------------------------------- documents
def make_form_pdf(path, amount=pdfdoc.HONEST_AMOUNT):
    """A contract whose amount lives in an AcroForm field, not in /Contents.

    This is the shape of a great many real signed documents, and it is the shape
    E4 never tested.
    """
    c = rl_canvas.Canvas(path)
    c.setFont("Helvetica", 14)
    c.drawString(72, 760, "CONTRACT")
    c.drawString(72, 730, "AMOUNT PAYABLE:")
    c.acroForm.textfield(
        name=FIELD, value=amount,
        x=220, y=724, width=220, height=22,
        fontName="Helvetica", fontSize=14,
        borderWidth=0, forceBorder=False,
    )
    c.showPage()
    c.save()
    return path


def _find_field(writer, name):
    """The field dictionary and its reference, or (None, None)."""
    root = writer.root
    if "/AcroForm" not in root:
        return None, None
    acro = root["/AcroForm"]
    acro = acro.get_object() if hasattr(acro, "get_object") else acro
    fields = acro.get("/Fields")
    fields = fields.get_object() if hasattr(fields, "get_object") else fields
    if not fields:
        return None, None
    for ref in fields:
        obj = ref.get_object()
        t = obj.get("/T")
        if t is not None and str(t) == name:
            return ref, obj
    return None, None


# ----------------------------------------------------------------- attacks
def fill_existing_field(src, dst, signer, sigfield,
                        amount=pdfdoc.FORGED_AMOUNT, need_appearances=False):
    """V1/V2 — set /V on a field that already exists, then sign.

    /Contents is never touched. If pyHanko classifies this as FORM_FILLING, the
    document renders a different amount while sitting inside E4's benign set.
    """
    with open(src, "rb") as inf:
        w = IncrementalPdfFileWriter(inf)

        ref, fobj = _find_field(w, FIELD)
        if fobj is None:
            raise RuntimeError(f"no AcroForm field named {FIELD!r} in {src}")

        fobj["/V"] = generic.TextStringObject(amount)
        w.update_container(fobj)

        if need_appearances:
            acro = w.root["/AcroForm"]
            acro = acro.get_object() if hasattr(acro, "get_object") else acro
            acro["/NeedAppearances"] = generic.BooleanObject(True)
            w.update_container(acro)

        append_signature_field(w, SigFieldSpec(sig_field_name=sigfield))
        sg = signers.SimpleSigner.load(signer.key_path, signer.cert_path)
        with open(dst, "wb") as outf:
            signers.sign_pdf(w, signers.PdfSignatureMetadata(field_name=sigfield),
                             signer=sg, output=outf)
    return dst


def create_field_then_fill(src, dst, signer, sigfield,
                           amount=pdfdoc.FORGED_AMOUNT):
    """V3 — no field exists, so the adversary adds one over the honest amount.

    Creating a field is a larger structural change than filling one, so this is
    the variant most likely to be classified OTHER. Included as the contrast
    case: if V1 is FORM_FILLING and V3 is OTHER, the boundary is exactly where
    the paper's rule breaks.
    """
    with open(src, "rb") as inf:
        w = IncrementalPdfFileWriter(inf)
        page = w.root["/Pages"]["/Kids"][0]

        widget = generic.DictionaryObject({
            generic.NameObject("/Type"): generic.NameObject("/Annot"),
            generic.NameObject("/Subtype"): generic.NameObject("/Widget"),
            generic.NameObject("/FT"): generic.NameObject("/Tx"),
            generic.NameObject("/T"): generic.TextStringObject("injected"),
            generic.NameObject("/V"): generic.TextStringObject(amount),
            generic.NameObject("/Ff"): generic.NumberObject(1),  # read-only
            generic.NameObject("/Rect"): generic.ArrayObject([
                generic.NumberObject(60), generic.NumberObject(718),
                generic.NumberObject(420), generic.NumberObject(748)]),
        })
        wref = w.add_object(widget)

        annots = page.get("/Annots")
        if annots is None:
            page[generic.NameObject("/Annots")] = generic.ArrayObject([wref])
        else:
            annots = annots.get_object() if hasattr(annots, "get_object") else annots
            annots.append(wref)
            w.update_container(annots)
        w.update_container(page)

        root = w.root
        if "/AcroForm" in root:
            acro = root["/AcroForm"]
            acro = acro.get_object() if hasattr(acro, "get_object") else acro
            flds = acro["/Fields"]
            flds = flds.get_object() if hasattr(flds, "get_object") else flds
            flds.append(wref)
            acro[generic.NameObject("/NeedAppearances")] = generic.BooleanObject(True)
            w.update_container(flds)
            w.update_container(acro)
        else:
            acro = generic.DictionaryObject({
                generic.NameObject("/Fields"): generic.ArrayObject([wref]),
                generic.NameObject("/NeedAppearances"): generic.BooleanObject(True),
            })
            root[generic.NameObject("/AcroForm")] = w.add_object(acro)
            w.update_container(root)

        append_signature_field(w, SigFieldSpec(sig_field_name=sigfield))
        sg = signers.SimpleSigner.load(signer.key_path, signer.cert_path)
        with open(dst, "wb") as outf:
            signers.sign_pdf(w, signers.PdfSignatureMetadata(field_name=sigfield),
                             signer=sg, output=outf)
    return dst


# -------------------------------------------------------------------- rule
def proposed_rule(rows):
    """E4's rule, reproduced exactly."""
    pq = verify.find(rows, PQ)
    if pq is None:
        return False, "R1 fails: no post-quantum signature present"
    if not (pq["intact"] and pq["valid"]):
        return False, f"R1 fails: PQ intact={pq['intact']} valid={pq['valid']}"
    lvl = pq["modification_level"]
    if lvl not in BENIGN_LEVELS:
        return False, f"R2 fails: level {lvl}"
    return True, f"R1 and R2 hold (level {lvl})"


def _row(label, path, vc):
    rows = verify.inspect(path, vc)
    pq = verify.find(rows, PQ)
    accept, why = proposed_rule(rows)
    return {
        "label": label,
        "pq_present": pq is not None,
        "pq_intact": bool(pq and pq["intact"]),
        "coverage": pq["coverage"] if pq else None,
        "modification_level": pq["modification_level"] if pq else None,
        "rule_accepts": accept,
        "why": why,
    }


def run(verbose=True):
    paths.ensure()
    classical = pki.selfsigned("_e6_c", "Classical Signer", "ec")
    pq = pki.selfsigned("_e6_q", "PQ Signer", "mldsa")
    vc = ValidationContext(trust_roots=[classical.asn1, pq.asn1],
                           allow_fetching=False, revocation_mode="soft-fail")

    out = {"name": "E6 form-fill probe", "variants": [], "errors": []}

    # ---- order B over a FORM document -----------------------------------
    formbase = make_form_pdf(paths.art("_e6_form_plain.pdf"))
    f1 = pdfdoc.sign(formbase, paths.art("_e6_form_1.pdf"), pq, PQ)
    formB = pdfdoc.sign(f1, paths.art("_e6_form_2.pdf"), classical, CLASSICAL)
    out["variants"].append(_row("V0 honest order-B form document", formB, vc))

    for tag, need_ap in (("V1 fill existing field", False),
                         ("V2 fill existing field + NeedAppearances", True)):
        dst = paths.art(f"_e6_{tag.split()[0]}_forged.pdf")
        try:
            p = fill_existing_field(formB, dst, classical, FORGED,
                                    need_appearances=need_ap)
            out["variants"].append(_row(tag, p, vc))
        except Exception as e:
            out["errors"].append(f"{tag}: {type(e).__name__}: {e}")

    # ---- order B over a PLAIN document, adversary creates the field ------
    plainbase = pdfdoc.make_pdf(paths.art("_e6_plain.pdf"))
    p1 = pdfdoc.sign(plainbase, paths.art("_e6_plain_1.pdf"), pq, PQ)
    plainB = pdfdoc.sign(p1, paths.art("_e6_plain_2.pdf"), classical, CLASSICAL)
    out["variants"].append(_row("V0b honest order-B plain document", plainB, vc))

    try:
        p = create_field_then_fill(plainB, paths.art("_e6_V3_forged.pdf"),
                                   classical, FORGED)
        out["variants"].append(_row("V3 create field then fill", p, vc))
    except Exception as e:
        out["errors"].append(f"V3 create field: {type(e).__name__}: {e}")

    # ---- contrast: the /Contents override E4 already tests ---------------
    p = pdfdoc.append_forged_revision(plainB, paths.art("_e6_V4_forged.pdf"),
                                      classical, FORGED)
    out["variants"].append(_row("V4 /Contents override (E4's attack)", p, vc))

    if verbose:
        report(out)
    return out


def report(out):
    print(f"\n{'='*82}")
    print("E6  can a t2 adversary change what the page shows and stay benign?")
    print(f"{'='*82}")
    print(f"  {'variant':44s} {'level':16s} rule")
    print(f"  {'-'*44} {'-'*16} {'-'*10}")
    for v in out["variants"]:
        verdict = "ACCEPTS" if v["rule_accepts"] else "rejects"
        print(f"  {v['label']:44s} {str(v['modification_level']):16s} {verdict}")

    for e in out["errors"]:
        print(f"  [could not build] {e}")

    attacks = [v for v in out["variants"]
               if v["label"][:2] in ("V1", "V2", "V3", "V4")]
    escaped = [v for v in attacks if v["rule_accepts"]]

    print(f"\n{'-'*82}")
    if escaped:
        print("  RESULT: the rule is DEFEATED by " + ", ".join(
            v["label"].split()[0] for v in escaped))
        print("  The page renders a forged amount while the post-quantum")
        print("  signature sits inside the benign set. Section VI's R2 must be")
        print("  restated: 'benign modification level' is weaker than 'no")
        print("  revision altered page content', and E4's 0-missed figure is")
        print("  scoped to /Contents overrides only.")
    else:
        print("  RESULT: every form-based variant lands OUTSIDE the benign set.")
        print("  The rule survives a probe designed to break it, which is worth")
        print("  one sentence in Section VI and a row in the E4 table.")
    print(f"{'-'*82}\n")


if __name__ == "__main__":
    run()
