#!/usr/bin/env python3
"""
E1 — format-layer downgrade of a plain (non-archival) sequential hybrid.

    classical layer   ECDSA P-256
    post-quantum      ML-DSA-44 (FIPS 204), genuine, via pyHanko's CMS path

Both signing orders are built and every revision boundary is truncated:

    order A   classical first, PQ appended   -> a cut yields CLASSICAL-only
    order B   PQ first, classical appended   -> a cut yields PQ-only

The adversary wants a document that verifies under the classical algorithm
alone, because that is the component a future quantum computer can forge. The
count of cuts reaching that state is the headline number: 1 under order A,
0 under order B.

Nothing here reads a signature byte. The attack is `data[:cut]`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pyhanko_certvalidator import ValidationContext

from hybridpdf import paths, pki, pdfdoc, revisions, verify

CLASSICAL, PQ = "ClassicalLayer", "PQLayer"


def _run_order(label, first, second, first_field, second_field, vc, tag):
    base = pdfdoc.make_pdf(paths.art(f"_e1_{tag}_plain.pdf"))
    inner = pdfdoc.sign(base, paths.art(f"_e1_{tag}_1.pdf"), first, first_field)
    hybrid = pdfdoc.sign(inner, paths.art(f"_e1_{tag}_2.pdf"), second, second_field)

    intact = verify.inspect(hybrid, vc)
    data = open(hybrid, "rb").read()

    cuts = []
    for idx, off, fp in revisions.write_cuts(hybrid, paths.art(f"_e1_{tag}")):
        rows = verify.inspect(fp, vc)
        good = verify.good_signatures(rows)
        cuts.append({
            "index": idx, "offset": off, "size": off,
            "surviving": good,
            "valid_document": bool(good),
            "classical_only": CLASSICAL in good and PQ not in good,
            "pq_only": PQ in good and CLASSICAL not in good,
            "identical_to_inner": revisions.identical(fp, inner),
        })

    return {
        "label": label,
        "first_signed": {"field": first_field, "algo": first.algo},
        "second_signed": {"field": second_field, "algo": second.algo},
        "inner_path": os.path.basename(inner), "inner_size": os.path.getsize(inner),
        "inner_sha256": revisions.sha256(inner),
        "hybrid_path": os.path.basename(hybrid), "hybrid_size": os.path.getsize(hybrid),
        "hybrid_sha256": revisions.sha256(hybrid),
        "boundaries": len(revisions.eof_offsets(data)),
        "cut_points": len(revisions.cut_points(data)),
        "intact_signatures": intact,
        "cuts": cuts,
        "cuts_valid_document": sum(c["valid_document"] for c in cuts),
        "cuts_classical_only": sum(c["classical_only"] for c in cuts),
        "cuts_pq_only": sum(c["pq_only"] for c in cuts),
        "bytes_discarded": (os.path.getsize(hybrid) - os.path.getsize(inner)),
    }


def run(verbose=True):
    classical = pki.selfsigned("_e1_c", "Classical Signer", "ec")
    pq = pki.selfsigned("_e1_q", "PQ Signer", "mldsa")
    vc = ValidationContext(trust_roots=[classical.asn1, pq.asn1],
                           allow_fetching=False, revocation_mode="soft-fail")

    out = {
        "name": "E1 plain sequential hybrid downgrade",
        "classical_algo": classical.algo,
        "pq_algo": pq.algo,
        "orders": {
            "A": _run_order("order A (conventional): classical inner, PQ outer",
                            classical, pq, CLASSICAL, PQ, vc, "A"),
            "B": _run_order("order B (proposed): PQ inner, classical outer",
                            pq, classical, PQ, CLASSICAL, vc, "B"),
        },
    }

    if verbose:
        report(out)
    return out


def report(out):
    print(f"\n{'='*74}\nE1  plain hybrid — {out['classical_algo']} + {out['pq_algo']}\n{'='*74}")
    for key in ("A", "B"):
        o = out["orders"][key]
        print(f"\n  {o['label']}")
        print(f"    signed first (prefix, survives): {o['first_signed']['field']:15s} {o['first_signed']['algo']}")
        print(f"    signed last  (suffix, removed) : {o['second_signed']['field']:15s} {o['second_signed']['algo']}")
        print(f"    hybrid {o['hybrid_size']} B, inner {o['inner_size']} B, "
              f"discarded {o['bytes_discarded']} B")
        print(f"    {o['boundaries']} revision boundaries -> {o['cut_points']} candidate cuts")
        for c in o["cuts"]:
            mark = "  <-- byte-identical to the inner document" if c["identical_to_inner"] else ""
            print(f"      cut{c['index']} @{c['offset']:6d} -> {c['surviving'] or 'nothing valid'}{mark}")
        print(f"    cuts yielding a valid signed document : {o['cuts_valid_document']}")
        print(f"    cuts yielding a CLASSICAL-ONLY document: {o['cuts_classical_only']}")
    a = out["orders"]["A"]["cuts_classical_only"]
    b = out["orders"]["B"]["cuts_classical_only"]
    print(f"\n  >>> adversary's goal reachable: order A = {a}, order B = {b}")


if __name__ == "__main__":
    run()
