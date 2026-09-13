"""
Documents: how they are made, signed, and forged.

`sign` places an ordinary signature; `sign_lta` places one at PAdES-B-LTA with
validation material and a document timestamp. Both add the signature as an
incremental update, which is the mechanism the whole paper is about.

`append_forged_revision` is the t2 adversary: one appended revision that both
overrides the rendered page content and carries a signature made with a key the
adversary now controls. Content override and signature go into the SAME
revision, because that is what a real forger would emit.
"""
from reportlab.pdfgen import canvas as rl_canvas

from pyhanko.sign import signers
from pyhanko.sign.fields import SigFieldSpec, append_signature_field
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

HONEST_AMOUNT = "1,000 USD"
FORGED_AMOUNT = "100,000 USD"


def make_pdf(path, amount=HONEST_AMOUNT, archival=False):
    c = rl_canvas.Canvas(path)
    c.setFont("Helvetica", 14)
    c.drawString(72, 760, "NOTARISED CONTRACT" if archival else "CONTRACT")
    c.drawString(72, 730, f"AMOUNT PAYABLE: {amount}")
    if archival:
        c.drawString(72, 700, "Archived under PAdES-B-LTA, hybrid signing policy.")
    c.showPage()
    c.save()
    return path


def sign(src, dst, signer, field):
    """An ordinary PDF signature, appended as an incremental update."""
    sg = signers.SimpleSigner.load(signer.key_path, signer.cert_path)
    with open(src, "rb") as inf:
        w = IncrementalPdfFileWriter(inf)
        append_signature_field(w, SigFieldSpec(sig_field_name=field))
        with open(dst, "wb") as outf:
            signers.sign_pdf(w, signers.PdfSignatureMetadata(field_name=field),
                             signer=sg, output=outf)
    return dst


def sign_lta(src, dst, signer, field, stamper, vc, chain_pem):
    """PAdES-B-LTA: embedded validation material plus a document timestamp."""
    sg = signers.SimpleSigner.load(signer.key_path, signer.cert_path,
                                   ca_chain_files=(chain_pem,))
    with open(src, "rb") as inf:
        w = IncrementalPdfFileWriter(inf)
        append_signature_field(w, SigFieldSpec(sig_field_name=field))
        meta = signers.PdfSignatureMetadata(
            field_name=field,
            subfilter=signers.constants.SigSeedSubFilter.PADES,
            embed_validation_info=True,
            use_pades_lta=True,
            validation_context=vc)
        with open(dst, "wb") as outf:
            signers.sign_pdf(w, meta, signer=sg, timestamper=stamper, output=outf)
    return dst


def _first_font(page):
    """A font already in the page resources, so the overlay reuses it rather
    than embedding one."""
    res = page.get("/Resources")
    if res is None:
        return None
    res = res.get_object() if hasattr(res, "get_object") else res
    fonts = res.get("/Font")
    if fonts is None:
        return None
    fonts = fonts.get_object() if hasattr(fonts, "get_object") else fonts
    keys = list(fonts.keys())
    return keys[0] if keys else None


def append_forged_revision(src, dst, signer, field, amount=FORGED_AMOUNT,
                           chain_pem=None):
    """The t2 adversary's single appended revision.

    Paints over the honest amount, writes a new one, and signs the result with
    `signer` -- whose key a broken classical algorithm would hand the adversary.
    """
    with open(src, "rb") as inf:
        w = IncrementalPdfFileWriter(inf)

        page = w.root["/Pages"]["/Kids"][0]
        fname = _first_font(page)
        if fname is None:
            raise RuntimeError("page carries no font resource to reuse")

        overlay = (
            "q\n"
            "1 1 1 rg\n"
            "60 718 360 30 re f\n"          # paint over the honest amount
            "0 0 0 rg\n"
            f"BT {fname} 14 Tf 72 730 Td (AMOUNT PAYABLE: {amount}) Tj ET\n"
            "Q\n"
        ).encode("ascii")
        new_ref = w.add_object(generic.StreamObject(stream_data=overlay))

        orig = page.raw_get("/Contents")
        resolved = orig.get_object()
        if isinstance(resolved, generic.ArrayObject):
            resolved.append(new_ref)
            w.update_container(resolved)
        else:
            page["/Contents"] = generic.ArrayObject([orig, new_ref])
            w.update_container(page)

        append_signature_field(w, SigFieldSpec(sig_field_name=field))
        sg = (signers.SimpleSigner.load(signer.key_path, signer.cert_path,
                                        ca_chain_files=(chain_pem,))
              if chain_pem else
              signers.SimpleSigner.load(signer.key_path, signer.cert_path))
        with open(dst, "wb") as outf:
            signers.sign_pdf(w, signers.PdfSignatureMetadata(field_name=field),
                             signer=sg, output=outf)
    return dst
