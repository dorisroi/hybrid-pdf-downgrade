#!/usr/bin/env python3
"""
reproduce.py -- one command that regenerates E1-E9 and numbers.json, checks the
result against the figures the paper was built from, and answers the questions
reviewers of this kind of paper ask, with evidence taken from the run itself.

    python reproduce.py                 # E1-E9 + C1 + audit, compare, report
    python reproduce.py --with-dss      # also re-validate THIS run's artifacts with DSS 6.5
    python reproduce.py --freeze-reference   # maintainers: pin current numbers as the reference

    make reproduce        |  make reproduce-dss        (Linux / macOS)
    docker build -t hybridpdf-repro . && docker run --rm \
        -v "$PWD/results/reproduce:/work/results/reproduce" hybridpdf-repro

Everything a run produces lands in results/reproduce/<timestamp>/:
    REVIEWER_REPORT.md   the answers, one verdict per question
    compare.txt          compare_runs.py against results/reference/
    numbers.json         the full record of this run
    run_all.log, dss.log

Exit status 0 only if every question is answered PASS and every invariant the
paper relies on reproduced. NOTE verdicts (things a reader should know, not
failures) do not change the exit status.

Two checks deliberately do not trust the pipeline's own bookkeeping:
    - the signature algorithm of each field is read back from the PDF with
      pyHanko's reader, not taken from the audit's record;
    - byte identity is recomputed by cutting the hybrid file on disk and hashing
      it, not taken from the `identical_to_inner` flag.

DSS provenance. run_all.py regenerates every artifact with fresh keys, so the
classic cycle (run_all -> run_dss -> run_all) always folds in DSS figures that
were measured on the previous run's files. With --with-dss this script runs
DSS on this run's artifacts and folds the figures in WITHOUT regenerating
them, and records that in numbers.json meta.dss_on_artifacts_of.
"""
import argparse
import contextlib
import glob
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

from hybridpdf import paths  # noqa: E402

REFERENCE_DIR = os.path.join(RESULTS := paths.RESULTS, "reference")
REFERENCE_JSON = os.path.join(REFERENCE_DIR, "numbers.reference.json")
NUMBERS_JSON = os.path.join(RESULTS, "numbers.json")
DSS_JSON = os.path.join(RESULTS, "dss_rule.json")

PASS, FAIL, NOTE = "PASS", "FAIL", "NOTE"


# ------------------------------------------------------------------ helpers
def say(msg=""):
    print(msg, flush=True)


def banner(msg):
    say("\n" + "=" * 78)
    say("  " + msg)
    say("=" * 78)


def sha256_file(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def run_logged(cmd, log_path, cwd=ROOT):
    """Run a command, stream its output to the console and to a log file."""
    env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    with open(log_path, "w", encoding="utf-8") as log:
        proc = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, env=env)
        for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace")
            log.write(line)
            sys.stdout.write(line)
        return proc.wait()


# ------------------------------------------------------------- environment
def environment():
    from importlib.metadata import version, PackageNotFoundError
    pins = {}
    with open(os.path.join(ROOT, "requirements.txt"), encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if "==" in line and not line.startswith("#"):
                name, ver = line.split("==", 1)
                pins[name.strip()] = ver.strip()
    installed, mismatches = {}, []
    for name, want in pins.items():
        try:
            have = version(name)
        except PackageNotFoundError:
            have = None
        installed[name] = have
        if have != want:
            mismatches.append(f"{name} pinned {want}, installed {have}")
    return {
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.release()}",
        "pins": pins, "installed": installed, "mismatches": mismatches,
    }


# --------------------------------------------------------------------- DSS
def run_dss(log_path):
    """Validate the artifacts currently in results/artifacts with DSS 6.5."""
    dssval = os.path.join(ROOT, "dssval")
    lib = os.path.join(dssval, "target", "lib")
    if os.path.isdir(lib) and glob.glob(os.path.join(lib, "*.jar")):
        # portable path: dependencies resolved by
        #   mvn -f dssval/pom.xml dependency:copy-dependencies -DoutputDirectory=target/lib
        java, javac = shutil.which("java"), shutil.which("javac")
        if not (java and javac):
            return False, "java/javac not on PATH"
        jars = sorted(glob.glob(os.path.join(lib, "*.jar")))
        classes = os.path.join("target", "classes")
        os.makedirs(os.path.join(dssval, classes), exist_ok=True)
        cp = os.pathsep.join([classes] + jars)
        rc = run_logged([javac, "-cp", cp, "-d", classes, "-encoding", "UTF-8",
                         os.path.join("src", "main", "java", "vn", "nckh", "DssRule.java")],
                        log_path + ".javac", cwd=dssval)
        if rc != 0:
            return False, f"javac exited {rc}"
        if os.path.exists(DSS_JSON):
            os.remove(DSS_JSON)
        rc = run_logged([java, "-Dorg.slf4j.simpleLogger.defaultLogLevel=error",
                         "-cp", cp, "vn.nckh.DssRule", "../results/artifacts"],
                        log_path, cwd=dssval)
        shutil.copyfile(log_path, os.path.join(RESULTS, "dss_rule_report.txt"))
    elif os.name == "nt" and os.path.exists(os.path.join(ROOT, "run_dss.ps1")):
        # the Windows harness builds its classpath from the local ~/.m2 cache
        if os.path.exists(DSS_JSON):
            os.remove(DSS_JSON)
        rc = run_logged(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                         "-File", os.path.join(ROOT, "run_dss.ps1")], log_path)
    else:
        return False, ("no DSS classpath: run `mvn -f dssval/pom.xml "
                       "dependency:copy-dependencies -DoutputDirectory=target/lib` "
                       "or build the image with --build-arg WITH_DSS=1")
    if not os.path.exists(DSS_JSON):
        return False, f"DSS produced no dss_rule.json (exit {rc})"
    return True, "ok"


def fold_dss_without_regenerating():
    """Put this run's DSS figures into numbers.json in place.

    Re-running run_all.py would regenerate every artifact with fresh keys and
    leave the DSS figures describing files that no longer exist.
    """
    with open(NUMBERS_JSON, encoding="utf-8") as f:
        res = json.load(f)
    with open(DSS_JSON, encoding="utf-8") as f:
        res["DSS"] = json.load(f)
    res["meta"]["dss_on_artifacts_of"] = res["meta"]["generated"]
    with open(NUMBERS_JSON, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)


# ----------------------------------------------------- independent re-reads
def field_oids(pdf_path):
    """{field name: (signature algorithm OID, signature length)} read from the PDF."""
    from pyhanko.pdf_utils.reader import PdfFileReader
    out = {}
    with open(pdf_path, "rb") as f:
        r = PdfFileReader(f)
        for s in r.embedded_regular_signatures:
            si = s.signer_info
            out[s.field_name] = (si["signature_algorithm"]["algorithm"].dotted,
                                 len(si["signature"].native))
    return out


def recompute_identity(order):
    """Cut the hybrid on disk at each claimed-identical offset; hash; compare."""
    hyb = paths.art(order["hybrid_path"])
    inner = paths.art(order["inner_path"])
    if not (os.path.exists(hyb) and os.path.exists(inner)):
        return None, "artifact missing on disk"
    on_disk_ok = (sha256_file(hyb) == order["hybrid_sha256"]
                  and sha256_file(inner) == order["inner_sha256"])
    with open(hyb, "rb") as f:
        data = f.read()
    claimed = [c for c in order["cuts"] if c.get("identical_to_inner")]
    if not claimed:
        return False, "no cut claimed identical"
    inner_sha = sha256_file(inner)
    for c in claimed:
        cut = data[:c["offset"]]
        if hashlib.sha256(cut).hexdigest() != inner_sha:
            return False, f"cut {c['index']} at {c['offset']} does not hash to the inner document"
    return on_disk_ok, (f"cut {claimed[0]['index']} at offset {claimed[0]['offset']} "
                        f"re-hashed: SHA-256 {inner_sha[:16]}... equals the classical-only "
                        f"document; artifacts on disk match the recorded hashes: {on_disk_ok}")


# ------------------------------------------------------------ the questions
def find(rows, key, prefix):
    hits = [r for r in rows if str(r.get(key, "")).startswith(prefix)]
    return hits[0] if len(hits) == 1 else None


def answer_questions(d, env, cmp_ok, cmp_text, dss_same_run):
    Q = []

    def q(num, question, verdict, evidence, where):
        Q.append({"n": num, "q": question, "v": verdict, "e": evidence, "where": where})

    au = d.get("AUDIT", {})
    e1, e2 = d["E1"]["orders"], d["E2"]["orders"]

    # R1 -- genuine post-quantum layer
    try:
        oids = field_oids(paths.art(e1["A"]["hybrid_path"]))
        pq_oid, pq_len = oids.get("PQLayer", (None, None))
        cl_oid, _ = oids.get("ClassicalLayer", (None, None))
        reread = (pq_oid == au.get("pq_oid") == "2.16.840.1.101.3.4.3.17"
                  and pq_len == au.get("pq_sig_len")
                  and cl_oid == au.get("classical_oid"))
        rr = f"re-read from the PDF: PQLayer {pq_oid} ({pq_len}-byte signature), ClassicalLayer {cl_oid}"
    except Exception as ex:
        reread, rr = False, f"re-read failed: {type(ex).__name__}: {ex}"
    ok = au.get("all_passed") and au.get("negative_controls_ok") and reread
    q("R1", "Is the post-quantum layer genuinely ML-DSA-44, or a classical signature under a post-quantum name?",
      PASS if ok else FAIL,
      f"audit {au.get('checks_passed')}/{au.get('checks_total')} checks, negative control "
      f"(corrupt the PQ signature -> validation fails) {au.get('negative_controls_ok')}; {rr}. "
      "ML-DSA-44 OID is 2.16.840.1.101.3.4.3.17 (FIPS 204).", "§III, §VII")

    # R2 -- byte identity, recomputed
    ok1, ev1 = recompute_identity(e1["A"])
    ok2, ev2 = recompute_identity(e2["A"])
    q("R2", "Is the truncated file really byte-identical to a legitimately classical-only document, or does it merely validate?",
      PASS if (ok1 and ok2) else FAIL,
      f"plain: {ev1}. B-LTA: {ev2}.", "§III, §IV")

    # R3 -- exhaustive enumeration, order effect
    def enum_ok(o):
        return o["cut_points"] == len(o["cuts"]) == o["boundaries"] - 1
    ok = (all(enum_ok(e[o]) for e in (e1, e2) for o in "AB")
          and e1["A"]["cuts_classical_only"] > 0 and e1["B"]["cuts_classical_only"] == 0
          and e2["A"]["cuts_classical_only"] > 0 and e2["B"]["cuts_classical_only"] == 0
          and e1["A"]["cuts_valid_document"] == e1["B"]["cuts_valid_document"]
          and e2["A"]["cuts_valid_document"] == e2["B"]["cuts_valid_document"])
    q("R3", "Was every truncation point tried, and does signing the post-quantum layer first remove every classical-only outcome?",
      PASS if ok else FAIL,
      f"every %%EOF boundary cut (cut points = boundaries - 1). Classical-only cuts, order A -> B: "
      f"plain {e1['A']['cuts_classical_only']} -> {e1['B']['cuts_classical_only']}, "
      f"B-LTA {e2['A']['cuts_classical_only']} -> {e2['B']['cuts_classical_only']}. "
      f"Valid cuts unchanged by the order (plain {e1['A']['cuts_valid_document']}/{e1['B']['cuts_valid_document']}, "
      f"B-LTA {e2['A']['cuts_valid_document']}/{e2['B']['cuts_valid_document']}); "
      f"order B instead yields {e2['B']['cuts_pq_only']} post-quantum-only cuts at B-LTA.",
      "§V, Table I")

    # R4 -- archival profile
    ts_cut = [c for c in e2["A"]["cuts"] if c.get("classical_only") and c.get("timestamp_entire_file")]
    ok = e2["A"]["cuts_classical_only"] > 0 and bool(ts_cut)
    q("R4", "Doesn't PAdES-B-LTA (document timestamps, validation data) already prevent this?",
      PASS if ok else FAIL,
      f"no: {e2['A']['cuts_classical_only']} of {e2['A']['cut_points']} cuts of the B-LTA hybrid are classical-only; "
      + (f"at cut {ts_cut[0]['index']} a surviving document timestamp still covers the entire remaining file."
         if ts_cut else "no cut retains a whole-file timestamp."),
      "§IV")

    # R5 -- algorithm invariance (control, not a PQ result)
    c1 = d["C1"]["orders"]
    ok = (c1["A"]["cuts_classical_only"] == e1["A"]["cuts_classical_only"]
          and c1["B"]["cuts_classical_only"] == e1["B"]["cuts_classical_only"])
    q("R5", "Is the outcome an artefact of ML-DSA (its size, encoding) rather than of the container?",
      PASS if ok else FAIL,
      f"control C1 replaces ML-DSA with a second ECDSA key and reproduces the same classical-only counts "
      f"(A {c1['A']['cuts_classical_only']}, B {c1['B']['cuts_classical_only']}) with a different byte layout. "
      "C1 is an ablation and is never cited as a post-quantum result.", "§III")

    # R6 -- cost
    e5 = d["E5"]
    lo, hi = e5["time_delta_ci95"]
    ok = e5.get("interleaved") and lo <= 0 <= hi and e5["size_delta_bytes"] <= 0
    q("R6", "Does the mitigation cost anything, and is the timing comparison sound?",
      PASS if ok else FAIL,
      f"{e5['reps']} fixed A-then-B blocks; no randomisation or counterbalancing, so order bias remains. "
      f"95% independent-bootstrap CI for median(B)-median(A): [{lo:+.1f}, {hi:+.1f}] ms. "
      "An interval containing zero is not an equivalence test. "
      f"Observed size delta B-A: {e5['size_delta_bytes']:+.0f} B (run-specific).", "§V")

    # R7 -- order B is not sufficient
    e3 = d["E3"]
    hb, s2 = e3["honest_B"]["pq"], e3["scenarios"]["S2_orderB_append_and_forge"]["pq"]
    r9 = d["E9"]["rows"]
    b2 = find(r9, "case", "B2")
    ok = (hb["coverage"] == s2["coverage"] and s2["intact"] and not s2["covers_rendered"]
          and b2 is not None and b2.get("built") and b2.get("e8") is True and b2.get("e4") is True)
    q("R7", "Once the classical algorithm is broken, does order B still protect the document?",
      PASS if ok else FAIL,
      f"not by itself (the paper's negative result, reproduced): an append-forgery keeps the PQ signature intact "
      f"(coverage {s2['coverage']} for both honest and forged, covers rendered content: {s2['covers_rendered']}); "
      + (f"the appearance-only forgery renders {b2.get('note')} and is accepted by the modification-level rule "
         f"(E4: {b2.get('e4')}) and the value-stability rule (E8: {b2.get('e8')})." if b2 else "B2 row missing."),
      "§VI, Table II")

    # R8 -- spoofing the rule's subject
    spoofs = [r for r in r9 if str(r["case"]).startswith("B1")]
    honest = [r for r in r9 if r["legitimate"]]
    ok = (len(spoofs) == 2 and all(r["e4"] and r["e7"] and r["e8"] and r["r1_oid"] is False for r in spoofs)
          and all(r["r1_oid"] is True for r in honest))
    q("R8", "Can a 'require post-quantum' rule be satisfied by a classical signature placed in a field named for the PQ layer?",
      PASS if ok else FAIL,
      f"yes when the rule locates the PQ signature by field name: all {len(spoofs)} spoofs pass E4, E7 and E8. "
      f"Bound to the ML-DSA OID in the CMS SignerInfo, it rejects "
      f"{sum(r['r1_oid'] is False for r in spoofs)}/{len(spoofs)} spoofs and keeps "
      f"{sum(r['r1_oid'] is True for r in honest)}/{len(honest)} legitimate documents.", "§VI")

    # R9 -- appearance check, with its scope
    rend_ok = (b2 is not None and b2.get("rendered") is False
               and all(r.get("rendered") is True for r in honest))
    q("R9", "Would checking the widget appearance streams close the gap?",
      NOTE if rend_ok else FAIL,
      (f"it rejects the one appearance-rewrite forgery tested ({b2.get('rendered_why')}) and accepts "
       f"{sum(r.get('rendered') is True for r in honest)}/{len(honest)} legitimate documents. "
       "Scope: a single attack case; fonts, annotations and optional-content visibility are untested, "
       "and no PAdES validator implements the check. It is evidence the gap is narrowable, not closed.")
      if b2 else "B2 row missing.", "§VI (not yet reported in the paper)")

    # R10 -- second validator, provenance
    dss = d.get("DSS")
    if not dss:
        q("R10", "Is this specific to pyHanko?", NOTE,
          "no DSS figures in this run; re-run with --with-dss (needs JDK 17 + DSS 6.5).", "§VII")
    else:
        prov = ("measured on THIS run's artifacts" if dss_same_run
                else "carried over from an earlier run's artifacts (re-run with --with-dss)")
        ok = (dss["rule_attacks_missed"] == 0 and dss["naive_legitimate_rejected"] == dss["legitimate"]
              and dss["naive_attacks_accepted"] > 0)
        q("R10", "Is this specific to pyHanko? What does an independent validator say?",
          (PASS if ok else FAIL) if dss_same_run else NOTE,
          f"EU DSS 6.5, {prov}: today's rule (every signature intact) accepts "
          f"{dss['naive_attacks_accepted']}/{dss['attacks']} attacks and rejects "
          f"{dss['naive_legitimate_rejected']}/{dss['legitimate']} legitimate documents; the modification-level "
          f"rule decides {dss['rule_decidable']}/{dss['total']} (DSS cannot parse ML-DSA) and misses "
          f"{dss['rule_attacks_missed']}. Its false-positive half is untested by DSS (no decidable legitimate file).",
          "§IV-A, §VII")

    # R11 -- reproducibility with fresh keys
    q("R11", "Do the figures reproduce on a fresh run with new keys?",
      PASS if cmp_ok else FAIL,
      cmp_text, "all")

    # R12 -- environment
    q("R12", "Does the environment match the pinned toolchain?",
      PASS if not env["mismatches"] else NOTE,
      (f"Python {env['python']} on {env['platform']}; "
       + ", ".join(f"{k} {v}" for k, v in env["installed"].items())
       + ("" if not env["mismatches"] else " -- MISMATCH: " + "; ".join(env["mismatches"]))),
      "requirements.txt")

    return Q


def write_report(path, Q, d, env, compare_output, dss_same_run):
    fails = [x for x in Q if x["v"] == FAIL]
    lines = [
        "# Reproduction report",
        "",
        f"- Run generated: {d['meta'].get('generated')}  (elapsed {d['meta'].get('elapsed_seconds')} s)",
        f"- Python {env['python']}, pyHanko {d['meta'].get('pyhanko')}, {env['platform']}",
        f"- DSS figures: {'this run' if dss_same_run else ('carried over' if d.get('DSS') else 'absent')}",
        f"- **Overall: {'REPRODUCED' if not fails else 'NOT REPRODUCED -- ' + ', '.join(x['n'] for x in fails)}**",
        "",
        "| # | Reviewer question | Verdict | Evidence from this run | Paper |",
        "|---|---|---|---|---|",
    ]
    for x in Q:
        ev = x["e"].replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {x['n']} | {x['q']} | **{x['v']}** | {ev} | {x['where']} |")
    lines += [
        "",
        "PASS: the paper's claim holds in this run. FAIL: it does not; the paper may state something this run "
        "does not show. NOTE: a scope or provenance fact a reader should know.",
        "",
    ]
    lines += [
        "",
        "## What this reproduction does not establish",
        "",
        "- That deployed signing products use order A. No product survey was performed.",
        "- Behaviour of validators other than pyHanko 0.37, DSS 6.5 and (manually, not re-run here) "
        "Adobe Acrobat Reader 26.002.",
        "- ML-DSA-65 or SHA-384, which TS 119 312 recommends; these change offsets and sizes, not "
        "the revision boundaries the attack uses.",
        "- Completeness of the t2 analysis: three append attacks were built, not every structural "
        "manipulation PDF allows.",
        "",
        "## compare_runs.py output",
        "",
        "```",
        compare_output.rstrip(),
        "```",
        "",
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# --------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--with-dss", action="store_true",
                    help="re-validate this run's artifacts with DSS 6.5 (JDK 17 required)")
    ap.add_argument("--reference", default=REFERENCE_JSON,
                    help="numbers.json from the reference experimental run")
    ap.add_argument("--freeze-reference", action="store_true",
                    help="copy the current results/numbers.json to results/reference/ and exit")
    args = ap.parse_args()

    if args.freeze_reference:
        os.makedirs(REFERENCE_DIR, exist_ok=True)
        shutil.copyfile(NUMBERS_JSON, REFERENCE_JSON)
        with open(REFERENCE_JSON, encoding="utf-8") as f:
            gen = json.load(f)["meta"]["generated"]
        say(f"reference frozen from run {gen} -> {os.path.relpath(REFERENCE_DIR, ROOT)}")
        return 0

    if not os.path.exists(args.reference):
        say(f"no reference at {args.reference}; run `python reproduce.py --freeze-reference` "
            "on the reference experimental run")
        return 2

    stamp = time.strftime("%Y%m%d_%H%M%S")
    out = os.path.join(RESULTS, "reproduce", stamp)
    os.makedirs(out)
    env = environment()

    banner("1/5  environment")
    say(f"  Python {env['python']} on {env['platform']}")
    for k, v in env["installed"].items():
        say(f"  {k:24s} {v}   (pinned {env['pins'][k]})")
    if env["mismatches"]:
        say("  WARNING: " + "; ".join(env["mismatches"]))

    banner("2/5  run_all.py -- audit gate, E1-E5, C1, E6-E9")
    # a stale dss_rule.json would be folded in silently; move it aside unless
    # this run re-measures it
    if not args.with_dss and os.path.exists(DSS_JSON):
        say("  existing dss_rule.json will be folded in as CARRIED OVER (not measured on this run)")
    rc = run_logged([sys.executable, os.path.join(ROOT, "run_all.py")],
                    os.path.join(out, "run_all.log"))
    if rc != 0:
        say(f"\n  run_all.py exited {rc}; see {os.path.join(out, 'run_all.log')}")
        return 1

    dss_same_run = False
    banner("3/5  DSS 6.5 on this run's artifacts" if args.with_dss else "3/5  DSS skipped (--with-dss not given)")
    if args.with_dss:
        ok, why = run_dss(os.path.join(out, "dss.log"))
        if not ok:
            say(f"  DSS failed: {why}")
            return 1
        fold_dss_without_regenerating()
        dss_same_run = True
        say("  DSS figures folded into numbers.json without regenerating artifacts")

    banner("4/5  compare against the reference build")
    import compare_runs
    with open(args.reference, encoding="utf-8") as f:
        ref = json.load(f)
    with open(NUMBERS_JSON, encoding="utf-8") as f:
        d = json.load(f)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cmp_ok = compare_runs.compare(ref, d)
    compare_output = buf.getvalue()
    say(compare_output)
    n_inv = len(set(compare_runs.invariants(ref)) & set(compare_runs.invariants(d)))
    cmp_text = (f"{n_inv} invariants compared with the reference run {ref['meta'].get('generated')}: "
                + ("none differ; size drift within tolerance." if cmp_ok else
                   "DIFFERENCES FOUND -- see compare.txt."))

    banner("5/5  reviewer questions")
    Q = answer_questions(d, env, cmp_ok, cmp_text, dss_same_run)
    report = os.path.join(out, "REVIEWER_REPORT.md")
    write_report(report, Q, d, env, compare_output, dss_same_run)
    with open(os.path.join(out, "compare.txt"), "w", encoding="utf-8") as f:
        f.write(compare_output)
    shutil.copyfile(NUMBERS_JSON, os.path.join(out, "numbers.json"))

    for x in Q:
        say(f"  [{x['v']:4s}] {x['n']:3s} {x['q']}")
    fails = [x for x in Q if x["v"] == FAIL]
    say(f"\n  report -> {os.path.relpath(report, ROOT)}")
    say(f"  RESULT: {'REPRODUCED' if not fails and cmp_ok else 'NOT REPRODUCED'}")
    return 0 if (not fails and cmp_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
