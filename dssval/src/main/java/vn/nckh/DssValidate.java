package vn.nckh;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;

import java.io.File;
import java.util.List;

/**
 * Independent validation of the downgrade experiments using the European
 * Commission's DSS library -- the reference implementation for eIDAS / PAdES.
 *
 * For each file we report what an independent, standards-conformant validator
 * sees: how many signatures it finds, whether each is cryptographically intact,
 * and -- decisively -- whether the signature covers the WHOLE document or only
 * part of it. The last point is the one that matters: if a truncated document
 * reports full coverage, no validator can tell a layer was removed.
 */
public class DssValidate {

    private static String scopeOf(SignatureWrapper sig) {
        List<XmlSignatureScope> scopes = sig.getSignatureScopes();
        if (scopes == null || scopes.isEmpty()) return "(none)";
        StringBuilder sb = new StringBuilder();
        for (XmlSignatureScope s : scopes) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(s.getScope());              // FULL / PARTIAL
            String d = s.getDescription();
            if (d != null && !d.isBlank()) sb.append(" [").append(d).append("]");
        }
        return sb.toString();
    }

    private static void report(File f) {
        System.out.printf("%n--- %s (%d B)%n", f.getName(), f.length());
        try {
            DSSDocument doc = new FileDocument(f);
            SignedDocumentValidator v = SignedDocumentValidator.fromDocument(doc);
            v.setCertificateVerifier(new CommonCertificateVerifier());
            Reports reports = v.validateDocument();
            DiagnosticData dd = reports.getDiagnosticData();

            List<SignatureWrapper> sigs = dd.getSignatures();
            System.out.printf("    signatures found: %d%n", sigs.size());
            for (SignatureWrapper s : sigs) {
                // Trust is irrelevant here: the certificates are self-signed on
                // purpose. What matters is WHO signed, integrity, and coverage.
                String who = "(unknown)";
                try {
                    var cert = s.getSigningCertificate();
                    if (cert != null) who = cert.getCommonName();
                } catch (Exception ignored) { }
                System.out.printf("      signer=%-24s intact=%-5s coverage=%s%n",
                        who, s.isSignatureIntact(), scopeOf(s));
            }
            if (sigs.isEmpty()) {
                System.out.println("      -> NO SIGNATURE RECOGNISED");
            }
        } catch (Exception e) {
            System.out.printf("    ERROR: %s: %s%n",
                    e.getClass().getSimpleName(), e.getMessage());
        }
    }

    public static void main(String[] args) {
        File dir = new File(args.length > 0 ? args[0] : "..");
        String[] names = {
            // R1 -- plain hybrid, conventional order
            "_doc_inner.pdf", "_doc_hybrid.pdf", "_doc_downgraded.pdf",
            // R2 -- PAdES-B-LTA
            "_lta_inner.pdf", "_lta_hybrid.pdf", "_lta_cut3.pdf", "_lta_cut2.pdf",
            // R3 -- signing order. cut1 is the truncation that removes the
            // last-signed layer; cut0 only strips back to the unsigned document.
            "_ord_A_2.pdf", "_ord_A_cut1.pdf",
            "_ord_B_2.pdf", "_ord_B_cut1.pdf",
        };
        System.out.println("======================================================");
        System.out.println(" EU DSS independent validation");
        System.out.println(" directory: " + dir.getAbsolutePath());
        System.out.println("======================================================");
        for (String n : names) {
            File f = new File(dir, n);
            if (f.exists()) report(f);
        }
        System.out.println();
        System.out.println("coverage FULL  = signature covers the entire document");
        System.out.println("coverage PARTIAL = content exists outside the signed range");
    }
}
