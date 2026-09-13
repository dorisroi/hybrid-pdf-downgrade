package vn.nckh;

import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.io.File;

/**
 * Is DSS 6.2's ML-DSA failure general, or an artefact of how we built the
 * certificates? Probe an intact ML-DSA hybrid against its classical-only
 * counterparts, all produced by the same pipeline.
 */
public class DssProbe {
    public static void main(String[] args) {
        File dir = new File(args.length > 0 ? args[0] : "..");
        String[] names = {
            "_m_A_2.pdf",      // hybrid: ECDSA + ML-DSA
            "_m_A_1.pdf",      // classical only (legitimate)
            "_m_A_cut1.pdf",   // classical only (truncated from the hybrid)
            "_m_B_2.pdf",      // hybrid, reverse order
        };
        for (String n : names) {
            File f = new File(dir, n);
            if (!f.exists()) continue;
            System.out.printf("%-16s (%6d B)  ", n, f.length());
            try {
                var v = SignedDocumentValidator.fromDocument(new FileDocument(f));
                v.setCertificateVerifier(new CommonCertificateVerifier());
                var dd = v.validateDocument().getDiagnosticData();
                System.out.printf("OK, %d chu ky%n", dd.getSignatures().size());
                for (var s : dd.getSignatures()) {
                    String who = "(?)";
                    try {
                        var c = s.getSigningCertificate();
                        if (c != null) who = c.getCommonName();
                    } catch (Exception ignored) { }
                    System.out.printf("        %-18s format=%-20s intact=%s%n",
                            who, s.getSignatureFormat(), s.isSignatureIntact());
                }
            } catch (Exception e) {
                System.out.printf("LOI: %s%n", e.getMessage());
            }
        }
    }
}
