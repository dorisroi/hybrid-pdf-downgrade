#!/usr/bin/env python3
"""
C1 — CONTROL: the outcome does not depend on the algorithm.

    !!  BOTH LAYERS HERE ARE ECDSA P-256.  !!

The field named `RoleSimPQ` is NOT a post-quantum signature. It is an ECDSA key
standing in for one, so that the container structure can be held fixed while the
algorithm is varied. Nothing in this file may be cited as a post-quantum result;
E1 and E2 are the experiments that use genuine ML-DSA-44.

This control exists because the paper claims the downgrade is invariant under
the choice of post-quantum algorithm: the adversary never parses a signature
object, so only the revision structure can matter. Run against E1, the two give
the same 1-vs-0 outcome while the order-B truncation offset differs several-fold
(the stand-in PQ revision is a few kB, a real ML-DSA one is a few tens of kB).
That divergence in bytes with identical outcomes is the measurement.

The earlier scripts `signing_order.py` and `pades_lta_downgrade.py` did exactly
this but labelled the stand-in field `PQLayer`, which is how figures from an
ECDSA-only run ended up quoted in the paper under an ML-DSA description.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pyhanko_certvalidator import ValidationContext

from hybridpdf import paths, pki, pdfdoc, revisions, verify

CLASSICAL, ROLE_PQ = "ClassicalLayer", "RoleSimPQ"


def _run_order(label, first, second, first_field, second_field, vc, tag):
    base = pdfdoc.make_pdf(paths.art(f"_c1_{tag}_plain.pdf"))
    inner = pdfdoc.sign(base, paths.art(f"_c1_{tag}_1.pdf"), first, first_field)
    hybrid = pdfdoc.sign(inner, paths.art(f"_c1_{tag}_2.pdf"), second, second_field)

    cuts = []
    for idx, off, fp in revisions.write_cuts(hybrid, paths.art(f"_c1_{tag}")):
        good = verify.good_signatures(verify.inspect(fp, vc))
        cuts.append({
            "index": idx, "offset": off, "surviving": good,
            "valid_document": bool(good),
            "classical_only": CLASSICAL in good and ROLE_PQ not in good,
            "identical_to_inner": revisions.identical(fp, inner),
        })

    return {
        "label": label,
        "first_signed": {"field": first_field, "algo": first.algo},
        "second_signed": {"field": second_field, "algo": second.algo},
        "inner_size": os.path.getsize(inner),
        "hybrid_size": os.path.getsize(hybrid),
        "boundaries": len(revisions.eof_offsets(open(hybrid, "rb").read())),
        "cuts": cuts,
        "cuts_valid_document": sum(c["valid_document"] for c in cuts),
        "cuts_classical_only": sum(c["classical_only"] for c in cuts),
    }


def run(verbose=True):
    classical = pki.selfsigned("_c1_c", "Classical Signer", "ec")
    rolepq = pki.selfsigned("_c1_q", "Role-Sim PQ Signer (ECDSA!)", "ec")
    vc = ValidationContext(trust_roots=[classical.asn1, rolepq.asn1],
                           allow_fetching=False, revocation_mode="soft-fail")

    out = {
        "name": "C1 control: algorithm invariance (both layers ECDSA)",
        "warning": "RoleSimPQ is ECDSA P-256, NOT post-quantum. Control only.",
        "classical_algo": classical.algo,
        "rolepq_algo": rolepq.algo,
        "orders": {
            "A": _run_order("order A: classical inner, role-sim PQ outer",
                            classical, rolepq, CLASSICAL, ROLE_PQ, vc, "A"),
            "B": _run_order("order B: role-sim PQ inner, classical outer",
                            rolepq, classical, ROLE_PQ, CLASSICAL, vc, "B"),
        },
    }
    if verbose:
        report(out)
    return out


def report(out):
    print(f"\n{'='*74}\nC1  CONTROL — both layers {out['classical_algo']}; "
          f"'RoleSimPQ' is NOT post-quantum\n{'='*74}")
    for key in ("A", "B"):
        o = out["orders"][key]
        print(f"\n  {o['label']}")
        print(f"    hybrid {o['hybrid_size']} B, inner {o['inner_size']} B, "
              f"{o['boundaries']} boundaries")
        for c in o["cuts"]:
            print(f"      cut{c['index']} @{c['offset']:6d} -> {c['surviving'] or 'nothing valid'}")
        print(f"    cuts yielding a CLASSICAL-ONLY document: {o['cuts_classical_only']}")
    a = out["orders"]["A"]["cuts_classical_only"]
    b = out["orders"]["B"]["cuts_classical_only"]
    print(f"\n  >>> order A = {a}, order B = {b} — same as E1, with a different algorithm")


if __name__ == "__main__":
    run()
