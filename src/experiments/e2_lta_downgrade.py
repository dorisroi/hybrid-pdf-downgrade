#!/usr/bin/env python3
"""
E2 — the same downgrade against PAdES-B-LTA, under a real test PKI.

B-LTA exists to give a document long-lived evidentiary value, so it is the
natural candidate mitigation. It is not one: a document timestamp is itself an
incremental update, removed by the same truncation that removes the PQ layer.
A timestamp attests that a state existed at time T; it cannot attest that no
later state was removed.

This supersedes the earlier archival run, which used self-signed certificates
and ECDSA for *both* layers. Here:

    Test Root CA (RSA 2048)
      +- Classical Signer   ECDSA P-256
      +- PQ Signer          ML-DSA-44 (FIPS 204)      <- genuinely post-quantum
      +- Test TSA           RSA 2048, EKU timeStamping (critical)
    + an empty CRL from the root, so revocation data exists and B-LT is reachable

Both signing orders are run, and -- unlike the earlier script -- every truncated
file is actually validated, so the count of cuts yielding a valid signed
document is measured here rather than imported from another experiment.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pyhanko.sign.timestamps import DummyTimeStamper
from pyhanko_certvalidator import ValidationContext

from hybridpdf import paths, pki, pdfdoc, revisions, verify

CLASSICAL, PQ = "ClassicalLayer", "PQLayer"


def _run_order(label, first, second, first_field, second_field,
               stamper, vc, root_pem, tag):
    base = pdfdoc.make_pdf(paths.art(f"_e2_{tag}_doc.pdf"), archival=True)
    inner = pdfdoc.sign_lta(base, paths.art(f"_e2_{tag}_inner.pdf"),
                            first, first_field, stamper, vc, root_pem)
    hybrid = pdfdoc.sign_lta(inner, paths.art(f"_e2_{tag}_hybrid.pdf"),
                             second, second_field, stamper, vc, root_pem)

    intact = verify.inspect(hybrid, vc)
    data = open(hybrid, "rb").read()

    cuts = []
    for idx, off, fp in revisions.write_cuts(hybrid, paths.art(f"_e2_{tag}")):
        rows = verify.inspect(fp, vc)
        good = verify.good_signatures(rows)
        ts_ok = [r for r in rows if r["timestamp"] and r["intact"] and r["valid"]]
        cuts.append({
            "index": idx, "offset": off, "size": off,
            "surviving": good,
            "surviving_timestamps": len(ts_ok),
            "valid_document": verify.is_valid_signed_document(rows),
            "classical_only": CLASSICAL in good and PQ not in good,
            "pq_only": PQ in good and CLASSICAL not in good,
            "identical_to_inner": revisions.identical(fp, inner),
            # the credibility-lending case: PQ gone, yet a timestamp still
            # covers the whole remaining file
            "timestamp_entire_file": any(
                r["timestamp"] and r["coverage"] == "ENTIRE_FILE"
                and r["intact"] and r["valid"] for r in rows),
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
    ca = pki.TestPKI("e2")
    classical, _ = ca.issue("_e2_c", "Classical Signer", "ec")
    pq, _ = ca.issue("_e2_q", "PQ Signer", "mldsa")
    tsa, tsa_key = ca.issue("_e2_t", "Test TSA", "rsa", tsa=True)

    stamper = DummyTimeStamper(tsa_cert=tsa.asn1,
                               tsa_key=pki.TestPKI.private_key_info(tsa_key),
                               certs_to_embed=None)
    vc = ValidationContext(trust_roots=[pki.to_a1(ca.root_cert)], crls=[ca.crl()],
                           allow_fetching=False, revocation_mode="hard-fail")

    out = {
        "name": "E2 PAdES-B-LTA downgrade under a test PKI",
        "classical_algo": classical.algo,
        "pq_algo": pq.algo,
        "tsa_algo": tsa.algo,
        "root_pem": os.path.basename(ca.root_pem),
        "orders": {
            "A": _run_order("order A (conventional): classical inner, PQ outer",
                            classical, pq, CLASSICAL, PQ,
                            stamper, vc, ca.root_pem, "A"),
            "B": _run_order("order B (proposed): PQ inner, classical outer",
                            pq, classical, PQ, CLASSICAL,
                            stamper, vc, ca.root_pem, "B"),
        },
    }
    if verbose:
        report(out)
    return out


def report(out):
    print(f"\n{'='*74}\nE2  PAdES-B-LTA under a test PKI — "
          f"{out['classical_algo']} + {out['pq_algo']}, TSA {out['tsa_algo']}\n{'='*74}")
    for key in ("A", "B"):
        o = out["orders"][key]
        print(f"\n  {o['label']}")
        print(f"    hybrid {o['hybrid_size']} B, archived-inner {o['inner_size']} B, "
              f"discarded {o['bytes_discarded']} B")
        print("    intact document:")
        for r in o["intact_signatures"]:
            print(f"      {r['field']:16s} intact={r['intact']} valid={r['valid']} "
                  f"trusted={r['trusted']} coverage={r['coverage']}")
        print(f"    {o['boundaries']} revision boundaries -> {o['cut_points']} candidate cuts")
        for c in o["cuts"]:
            flags = []
            if c["identical_to_inner"]:
                flags.append("byte-identical to the archived inner document")
            if c["timestamp_entire_file"] and not c["surviving"].count(PQ):
                flags.append("timestamp still covers ENTIRE_FILE")
            tail = ("  <-- " + "; ".join(flags)) if flags else ""
            print(f"      cut{c['index']} @{c['offset']:6d} -> "
                  f"{c['surviving'] or 'nothing valid'} "
                  f"(+{c['surviving_timestamps']} ts){tail}")
        print(f"    cuts yielding a valid signed document  : {o['cuts_valid_document']}")
        print(f"    cuts yielding a CLASSICAL-ONLY document: {o['cuts_classical_only']}")
    a = out["orders"]["A"]["cuts_classical_only"]
    b = out["orders"]["B"]["cuts_classical_only"]
    print(f"\n  >>> adversary's goal reachable at B-LTA: order A = {a}, order B = {b}")


if __name__ == "__main__":
    run()
