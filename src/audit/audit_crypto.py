#!/usr/bin/env python3
"""
AUDIT — is the post-quantum layer genuinely post-quantum?

An earlier generation of these scripts named a field `PQLayer` while signing it
with ECDSA. Reading code did not catch that; only opening the certificate did.
So this audit asserts the property at the level that actually matters -- the
algorithm OID inside the CMS SignerInfo embedded in the signed PDF -- and then
proves the verifier really exercises it.

Four checks, each of which must pass:

  A1  certificate key algorithm        ML-DSA-44 public key in the PQ signer cert
  A2  CMS signature algorithm OID      id-ml-dsa-44 = 2.16.840.1.101.3.4.3.17
  A3  signature length                 ML-DSA-44 signatures are 2420 bytes
  A4  NEGATIVE CONTROL                 corrupt the PQ signature -> must FAIL

A4 is the one that cannot be faked. If pyHanko were silently skipping the
post-quantum signature, corrupting its bytes would change nothing and the file
would still validate. A result is only evidence if its negation is detectable.

A5 additionally corrupts the signed *content* rather than the signature, to show
the byte-range binding is real, and A6 asserts that the control experiment is
NOT post-quantum, so it can never be mistaken for one.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography import x509
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko_certvalidator import ValidationContext

from hybridpdf import paths, pki, pdfdoc, verify

ML_DSA_44_OID = "2.16.840.1.101.3.4.3.17"
ML_DSA_44_SIG_LEN = 2420
ECDSA_SHA256_OID = "1.2.840.10045.4.3.2"

PASS, FAIL = "PASS", "FAIL"


def cms_facts(path, field):
    """Algorithm OID and signature length as they actually sit in the PDF."""
    with open(path, "rb") as f:
        reader = PdfFileReader(f)
        for s in reader.embedded_signatures:
            if s.field_name != field:
                continue
            si = s.signer_info
            alg = si["signature_algorithm"]["algorithm"]
            try:
                dotted = alg.dotted
            except Exception:
                dotted = str(alg)
            try:
                named = alg.native
            except Exception:
                named = "<unmapped>"
            return {"oid": dotted, "name": str(named),
                    "sig_len": len(si["signature"].native),
                    "byte_range": list(s.byte_range)}
    return None


def corrupt_signature(src, dst, byte_range):
    """Flip one hex digit inside the /Contents gap, i.e. inside the signature.

    byte_range is [0, a, b, c]: the covered bytes are [0,a) and [b, b+c), so the
    gap (a, b) is exactly the hex-encoded signature. Nothing the signature
    covers is touched -- only the signature itself.
    """
    data = bytearray(open(src, "rb").read())
    a, b = byte_range[1], byte_range[2]
    mid = (a + b) // 2
    old = data[mid:mid + 1]
    data[mid:mid + 1] = b"0" if old != b"0" else b"1"
    open(dst, "wb").write(bytes(data))
    return dst, mid


def corrupt_content(src, dst, byte_range):
    """Change a byte the signature covers, without touching the signature.

    ReportLab compresses the page content stream, so the visible text is not
    present as plain bytes. We flip a byte inside the first `stream ... endstream`
    payload instead: still page content, still inside the covered range, and the
    surrounding PDF structure is left intact so the file remains parseable.
    """
    data = bytearray(open(src, "rb").read())
    covered_end = byte_range[1]
    i = data.find(b"stream")
    while i != -1 and i < covered_end:
        j = i + len(b"stream")
        while data[j:j + 1] in (b"\r", b"\n"):
            j += 1
        end = data.find(b"endstream", j)
        if end > j + 8 and end < covered_end:
            mid = (j + end) // 2
            data[mid] ^= 0xFF
            open(dst, "wb").write(bytes(data))
            return dst, mid
        i = data.find(b"stream", i + 1)
    raise RuntimeError("no content stream found inside the covered range")


def check(label, ok, detail):
    print(f"  [{PASS if ok else FAIL}] {label:46s} {detail}")
    return ok


def run():
    print(f"\n{'='*78}\nAUDIT — is the post-quantum layer genuinely post-quantum?\n{'='*78}")
    results = []

    classical = pki.selfsigned("_au_c", "Classical Signer", "ec")
    pq = pki.selfsigned("_au_q", "PQ Signer", "mldsa")
    vc = ValidationContext(trust_roots=[classical.asn1, pq.asn1],
                           allow_fetching=False, revocation_mode="soft-fail")

    base = pdfdoc.make_pdf(paths.art("_au_plain.pdf"))
    inner = pdfdoc.sign(base, paths.art("_au_1.pdf"), classical, "ClassicalLayer")
    hybrid = pdfdoc.sign(inner, paths.art("_au_2.pdf"), pq, "PQLayer")

    # ---- A1  certificate key algorithm -------------------------------------
    cert = x509.load_pem_x509_certificate(open(pq.cert_path, "rb").read())
    kind = type(cert.public_key()).__name__
    results.append(check("A1 PQ certificate public key", kind == "MLDSA44PublicKey", kind))

    cert_c = x509.load_pem_x509_certificate(open(classical.cert_path, "rb").read())
    kind_c = type(cert_c.public_key()).__name__
    results.append(check("A1b classical certificate public key",
                         "EC" in kind_c or "EllipticCurve" in kind_c, kind_c))

    # ---- A2/A3  what is actually inside the PDF ----------------------------
    pqf = cms_facts(hybrid, "PQLayer")
    clf = cms_facts(hybrid, "ClassicalLayer")

    results.append(check("A2 PQ CMS signature algorithm OID",
                         pqf and pqf["oid"] == ML_DSA_44_OID,
                         f"{pqf['oid']} ({pqf['name']})" if pqf else "not found"))
    results.append(check("A2b classical CMS signature algorithm OID",
                         clf and clf["oid"] == ECDSA_SHA256_OID,
                         f"{clf['oid']} ({clf['name']})" if clf else "not found"))
    results.append(check("A3 PQ signature length = 2420 B",
                         pqf and pqf["sig_len"] == ML_DSA_44_SIG_LEN,
                         f"{pqf['sig_len']} B" if pqf else "-"))
    if clf:
        print(f"        (classical signature is {clf['sig_len']} B, DER-variable)")

    # ---- baseline: the intact document must verify -------------------------
    rows = verify.inspect(hybrid, vc)
    pq_row = verify.find(rows, "PQLayer")
    results.append(check("A0 intact PQ signature verifies",
                         bool(pq_row and pq_row["intact"] and pq_row["valid"]),
                         f"intact={pq_row['intact']} valid={pq_row['valid']}" if pq_row else "-"))

    # ---- A4  NEGATIVE CONTROL: corrupt the PQ signature --------------------
    bad, off = corrupt_signature(hybrid, paths.art("_au_badsig.pdf"), pqf["byte_range"])
    rows_bad = verify.inspect(bad, vc)
    pq_bad = verify.find(rows_bad, "PQLayer")
    cl_bad = verify.find(rows_bad, "ClassicalLayer")
    pq_broken = (pq_bad is None) or not (pq_bad["intact"] and pq_bad["valid"])
    results.append(check("A4 corrupt PQ signature -> PQ FAILS", pq_broken,
                         f"byte@{off}: intact={pq_bad['intact']} valid={pq_bad['valid']}"
                         if pq_bad else "signature no longer parsed"))
    # and the classical layer, which does not cover the PQ signature, survives
    results.append(check("A4b classical layer unaffected by that corruption",
                         bool(cl_bad and cl_bad["intact"]),
                         f"intact={cl_bad['intact']}" if cl_bad else "-"))

    # ---- A5  NEGATIVE CONTROL: corrupt signed content ----------------------
    badc, offc = corrupt_content(hybrid, paths.art("_au_badcontent.pdf"),
                                 pqf["byte_range"])
    rows_bc = verify.inspect(badc, vc)
    pq_bc = verify.find(rows_bc, "PQLayer")
    cl_bc = verify.find(rows_bc, "ClassicalLayer")
    results.append(check("A5 corrupt signed content -> PQ FAILS",
                         (pq_bc is None) or not (pq_bc["intact"] and pq_bc["valid"]),
                         f"byte@{offc}: intact={pq_bc['intact']}" if pq_bc else "-"))
    results.append(check("A5b corrupt signed content -> classical FAILS too",
                         (cl_bc is None) or not (cl_bc["intact"] and cl_bc["valid"]),
                         f"intact={cl_bc['intact']}" if cl_bc else "-"))

    # ---- A6  the control experiment must NOT look post-quantum -------------
    role = pki.selfsigned("_au_r", "Role-Sim PQ (ECDSA)", "ec")
    vcr = ValidationContext(trust_roots=[classical.asn1, role.asn1],
                            allow_fetching=False, revocation_mode="soft-fail")
    rbase = pdfdoc.make_pdf(paths.art("_au_r_plain.pdf"))
    r1 = pdfdoc.sign(rbase, paths.art("_au_r_1.pdf"), classical, "ClassicalLayer")
    r2 = pdfdoc.sign(r1, paths.art("_au_r_2.pdf"), role, "RoleSimPQ")
    rf = cms_facts(r2, "RoleSimPQ")
    results.append(check("A6 control's RoleSimPQ is NOT ML-DSA",
                         rf and rf["oid"] != ML_DSA_44_OID,
                         f"{rf['oid']} ({rf['name']})" if rf else "-"))
    _ = verify.inspect(r2, vcr)

    print(f"\n{'-'*78}")
    ok = all(results)
    print(f"  {sum(results)}/{len(results)} checks passed — "
          f"{'the post-quantum layer is genuine and verified' if ok else 'AUDIT FAILED'}")
    return {"checks_passed": sum(results), "checks_total": len(results),
            "pq_oid": pqf["oid"] if pqf else None,
            "pq_sig_len": pqf["sig_len"] if pqf else None,
            "classical_oid": clf["oid"] if clf else None,
            "negative_controls_ok": bool(pq_broken),
            "all_passed": ok}


if __name__ == "__main__":
    r = run()
    sys.exit(0 if r["all_passed"] else 1)
