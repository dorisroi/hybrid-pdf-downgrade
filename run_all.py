#!/usr/bin/env python3
"""Run the cryptographic audit and E1-E9/C1 experiments; save results as JSON."""
import io
import json
import os
import sys
import time

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from hybridpdf import paths                                    # noqa: E402
from experiments import e1_plain_downgrade as e1               # noqa: E402
from experiments import e2_lta_downgrade as e2                 # noqa: E402
from experiments import e3_t2_forgery as e3                    # noqa: E402
from experiments import e4_verifier_rule as e4                 # noqa: E402
from experiments import e5_cost as e5                          # noqa: E402
from experiments import e6_formfill_probe as e6                # noqa: E402
from experiments import e7_refined_rule as e7                  # noqa: E402
from experiments import e8_value_rule as e8                    # noqa: E402
from experiments import e9_rule_bypass_probe as e9             # noqa: E402
from controls import c1_algorithm_invariance as c1             # noqa: E402
from audit import audit_crypto                                 # noqa: E402


def main():
    paths.ensure()
    t0 = time.time()
    res = {}

    print("\n" + "#" * 74)
    print("#  Running the cryptographic audit and experiments")
    print("#" * 74)

    # the audit runs FIRST: if the post-quantum layer is not genuinely
    # post-quantum, nothing downstream is worth measuring
    res["AUDIT"] = audit_crypto.run()
    if not res["AUDIT"]["all_passed"]:
        print("\n  !! cryptographic audit FAILED — refusing to generate numbers")
        sys.exit(1)

    res["E1"] = e1.run()
    res["E2"] = e2.run()
    res["E3"] = e3.run()
    res["E4"] = e4.run()
    res["E5"] = e5.run()
    res["C1"] = c1.run()
    res["E6"] = e6.run()
    res["E7"] = {"name": "E7 refined rule (changed-field set)",
                 "cases": e7.run()}
    res["E8"] = {"name": "E8 value-stability rule",
                 "cases": e8.run()}
    res["E9"] = e9.run()

    # produced by run_dss.ps1, which needs a JDK and so runs separately
    dss_path = paths.result("dss_rule.json")
    if os.path.exists(dss_path):
        with open(dss_path, encoding="utf-8") as f:
            res["DSS"] = json.load(f)
        print(f"\n  folded in DSS cross-check from {os.path.basename(dss_path)}")
    else:
        print("\n  no results/dss_rule.json — run run_dss.ps1 for the DSS figures")

    res["meta"] = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "python": sys.version.split()[0],
        "elapsed_seconds": round(time.time() - t0, 1),
    }
    # pyHanko 0.37 has no __version__ attribute; the installed distribution
    # metadata is the reliable source.
    from importlib.metadata import version
    res["meta"]["pyhanko"] = version("pyHanko")

    jpath = paths.result("numbers.json")
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)

    print("\n" + "#" * 74)
    print("#  SUMMARY — experimental results")
    print("#" * 74)
    print(f"\n  full record -> {os.path.relpath(jpath, paths.ROOT)}")
    print(f"  elapsed {res['meta']['elapsed_seconds']}s")


if __name__ == "__main__":
    main()
