package vn.nckh;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import java.io.File;
import java.util.List;

/**
 * Is the proposed verifier rule pyHanko-specific?
 *
 * E4 implements the rule using pyHanko's `modification_level`, which is that
 * library's own API. If no other validator exposes the same information, the
 * rule is a proposal no deployed verifier could adopt, and the paper should say
 * so. This asks DSS 6.5 -- the European Commission's reference implementation
 * for eIDAS -- whether it exposes an equivalent.
 *
 * It does. DSS classifies the object modifications introduced by revisions
 * appended after a signature:
 *
 *     getPdfExtensionChanges()          archival / DSS-store growth   benign
 *     getPdfSignatureOrFormFillChanges() a signature field was added   benign
 *     getPdfAnnotationChanges()          annotations                   benign-ish
 *     getPdfUndefinedChanges()           everything else               NOT benign
 *
 * which lines up with pyHanko's LTA_UPDATES / FORM_FILLING / ANNOTATIONS /
 * OTHER. The rule can therefore be stated without naming a library: reject when
 * the revision carrying the post-quantum signature is followed by UNDEFINED
 * object modifications.
 *
 * One caveat this program also measures: DSS 6.5 does not parse ML-DSA, so it
 * may not see the post-quantum signature at all. Where that happens the rule's
 * require-PQ half cannot be evaluated by DSS today, which is the same
 * transition-period gap Section V-A reports.
 */
public class DssRule {

    /** Ground truth, mirroring src/experiments/e4_verifier_rule.py. */
    private static final String[][] CASES = {
        {"_e4_B_2.pdf",            "plain order B, honest",                 "LEGIT"},
        {"_e4_B_forged.pdf",       "plain order B, t2 append-forgery",      "ATTACK"},
        {"_e4_A_2.pdf",            "plain order A, honest",                 "LEGIT"},
        {"_e4_A_downgraded.pdf",   "plain order A, truncation-downgraded",  "ATTACK"},
        {"_e4_A_forged.pdf",       "plain order A, downgraded then forged", "ATTACK"},
        {"_e4_scratch_forged.pdf", "fabricated from scratch",               "ATTACK"},
        {"_e4l_B_hybrid.pdf",      "B-LTA order B, honest",                 "LEGIT"},
        {"_e4l_B_forged.pdf",      "B-LTA order B, t2 append-forgery",      "ATTACK"},
        {"_e4l_A_hybrid.pdf",      "B-LTA order A, honest",                 "LEGIT"},
        {"_e4l_A_downgraded.pdf",  "B-LTA order A, truncation-downgraded",  "ATTACK"},
    };

    private static String scopeOf(SignatureWrapper s) {
        List<XmlSignatureScope> scopes = s.getSignatureScopes();
        if (scopes == null || scopes.isEmpty()) return "(none)";
        StringBuilder sb = new StringBuilder();
        for (XmlSignatureScope x : scopes) {
            if (sb.length() > 0) sb.append(",");
            sb.append(x.getScope());
        }
        return sb.toString();
    }

    private static int size(List<?> l) { return l == null ? 0 : l.size(); }

    private static String fieldsOf(PDFRevisionWrapper r) {
        if (r == null) return "(no pdf revision)";
        List<String> f = r.getSignatureFieldNames();
        return (f == null || f.isEmpty()) ? "(unnamed)" : String.join("+", f);
    }

    /**
     * Three outcomes, not two. Collapsing "DSS cannot parse the post-quantum
     * layer" into "rejected" would charge DSS's ML-DSA blindness to the rule and
     * report false positives the rule does not have.
     */
    private static class Verdict {
        boolean naiveAccept = true;
        boolean pqFieldPresent = false;   // a field named PQLayer exists
        boolean pqValidated = false;      // ...and DSS could actually verify it
        boolean undefinedAnywhere = false;
        boolean readable = true;          // DSS produced a report at all
        int sigs = 0;

        /** Reject when the require-PQ half fails or any revision shows
         *  unclassifiable object modifications. Undecidable when DSS could not
         *  read the file, or saw the PQ field but could not verify it. */
        String ruleOutcome() {
            if (!readable) return "UNDECIDABLE";
            if (!pqFieldPresent) return "REJECT";        // require-PQ fails
            if (undefinedAnywhere) return "REJECT";      // content changed later
            if (!pqValidated) return "UNDECIDABLE";      // DSS cannot check R1
            return "ACCEPT";
        }
    }

    private static Verdict report(File f) {
        Verdict v = new Verdict();
        System.out.printf("%n  --- %s (%d B)%n", f.getName(), f.length());
        try {
            DSSDocument doc = new FileDocument(f);
            SignedDocumentValidator val = SignedDocumentValidator.fromDocument(doc);
            val.setCertificateVerifier(new CommonCertificateVerifier());
            Reports reports = val.validateDocument();
            DiagnosticData dd = reports.getDiagnosticData();

            List<SignatureWrapper> sigs = dd.getSignatures();
            v.sigs = sigs.size();
            if (sigs.isEmpty()) {
                System.out.println("      DSS recognised NO signature");
                v.naiveAccept = false;
                v.readable = false;
                return v;
            }
            for (SignatureWrapper s : sigs) {
                String who = "(unknown)";
                try {
                    var c = s.getSigningCertificate();
                    if (c != null) who = c.getCommonName();
                } catch (Exception ignored) { }

                PDFRevisionWrapper r = s.getPDFRevision();
                String fields = fieldsOf(r);
                int ext = 0, sff = 0, ann = 0, und = 0;
                boolean objMods = false;
                if (r != null) {
                    objMods = r.arePdfObjectModificationsDetected();
                    ext = size(r.getPdfExtensionChanges());
                    sff = size(r.getPdfSignatureOrFormFillChanges());
                    ann = size(r.getPdfAnnotationChanges());
                    und = size(r.getPdfUndefinedChanges());
                }

                boolean intact = s.isSignatureIntact();
                if (!intact) v.naiveAccept = false;

                if (und > 0) v.undefinedAnywhere = true;
                if (fields != null && fields.contains("PQLayer")) {
                    v.pqFieldPresent = true;
                    if (intact) v.pqValidated = true;
                }

                System.out.printf("      %-16s signer=%-18s intact=%-5s scope=%-8s "
                                + "objMods=%-5s ext=%d formFill=%d annot=%d UNDEFINED=%d%n",
                        fields, who, intact, scopeOf(s), objMods, ext, sff, ann, und);
            }
        } catch (Exception e) {
            System.out.printf("      ERROR: %s: %s%n",
                    e.getClass().getSimpleName(), e.getMessage());
            v.naiveAccept = false;
            v.readable = false;
        }
        return v;
    }

    public static void main(String[] args) {
        File dir = new File(args.length > 0 ? args[0] : "../results/artifacts");
        System.out.println("==============================================================");
        System.out.println(" DSS 6.5 -- can an independent validator apply the proposed rule?");
        System.out.println(" directory: " + dir.getAbsolutePath());
        System.out.println("==============================================================");

        int attacks = 0, legit = 0;
        int naiveMissed = 0, naiveRejectedLegit = 0;
        int ruleMissed = 0, ruleFp = 0, undecidable = 0, decidable = 0;
        StringBuilder summary = new StringBuilder();

        for (String[] c : CASES) {
            File f = new File(dir, c[0]);
            if (!f.exists()) {
                System.out.printf("%n  --- %s MISSING (run run_all.py first)%n", c[0]);
                continue;
            }
            boolean isAttack = c[2].equals("ATTACK");
            if (isAttack) attacks++; else legit++;

            Verdict v = report(f);
            String outcome = v.ruleOutcome();

            if (isAttack && v.naiveAccept) naiveMissed++;
            if (!isAttack && !v.naiveAccept) naiveRejectedLegit++;

            if (outcome.equals("UNDECIDABLE")) {
                undecidable++;
            } else {
                decidable++;
                if (isAttack && outcome.equals("ACCEPT")) ruleMissed++;
                if (!isAttack && outcome.equals("REJECT")) ruleFp++;
            }

            summary.append(String.format("  %-42s %-7s naive=%-7s rule=%s%n",
                    c[1], c[2], v.naiveAccept ? "accept" : "reject", outcome));
        }

        System.out.println();
        System.out.println("==============================================================");
        System.out.println(" SUMMARY");
        System.out.println("==============================================================");
        System.out.print(summary);
        System.out.printf("%n  %d attacks, %d legitimate documents%n", attacks, legit);
        System.out.println();
        System.out.println("  Today's rule (every signature intact), as DSS applies it:");
        System.out.printf("    attacks accepted        : %d of %d%n", naiveMissed, attacks);
        System.out.printf("    legitimate REJECTED     : %d of %d%n", naiveRejectedLegit, legit);
        System.out.println("    -- DSS marks the unparseable ML-DSA layer not-intact, so it");
        System.out.println("       rejects the protected documents and accepts the attacked");
        System.out.println("       ones. This is the Section V-A inversion, independently.");
        System.out.println();
        System.out.println("  Proposed rule, restricted to what DSS can actually decide:");
        System.out.printf("    decidable files         : %d of %d%n", decidable, attacks + legit);
        System.out.printf("    attacks missed          : %d%n", ruleMissed);
        System.out.printf("    false positives         : %d%n", ruleFp);
        System.out.printf("    UNDECIDABLE (ML-DSA unparseable by DSS 6.5): %d%n", undecidable);
        System.out.println();
        System.out.println("  UNDEFINED > 0 is DSS's equivalent of pyHanko's OTHER:");
        System.out.println("  object modifications it cannot classify as extension,");
        System.out.println("  signature/form fill, or annotation change.");

        // Written so run_all.py can turn these into LaTeX macros. A figure the
        // paper cites must never be retyped from a console.
        File out = new File(dir.getParentFile(), "dss_rule.json");
        try (java.io.PrintWriter w = new java.io.PrintWriter(out, "UTF-8")) {
            w.printf("{%n");
            w.printf("  \"validator\": \"DSS 6.5\",%n");
            w.printf("  \"attacks\": %d,%n", attacks);
            w.printf("  \"legitimate\": %d,%n", legit);
            w.printf("  \"total\": %d,%n", attacks + legit);
            w.printf("  \"naive_attacks_accepted\": %d,%n", naiveMissed);
            w.printf("  \"naive_legitimate_rejected\": %d,%n", naiveRejectedLegit);
            w.printf("  \"rule_decidable\": %d,%n", decidable);
            w.printf("  \"rule_undecidable\": %d,%n", undecidable);
            w.printf("  \"rule_attacks_missed\": %d,%n", ruleMissed);
            w.printf("  \"rule_false_positives\": %d%n", ruleFp);
            w.printf("}%n");
            System.out.printf("%n  wrote %s%n", out.getAbsolutePath());
        } catch (Exception e) {
            System.out.printf("  could not write dss_rule.json: %s%n", e.getMessage());
        }
    }
}
