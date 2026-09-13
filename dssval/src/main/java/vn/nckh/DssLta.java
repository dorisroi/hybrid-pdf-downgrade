package vn.nckh;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;

import java.io.File;
import java.util.List;

/**
 * Does DSS certify the archival level once the timestamp authority is anchored?
 *
 * The earlier run used a self-signed TSA, and DSS graded the document
 * PAdES-BASELINE-T: it will not certify an archival level it cannot anchor.
 * Here the same documents are signed against a Test Root CA, and that root is
 * handed to DSS as a trust anchor. If DSS now reports BASELINE-LTA, the archival
 * claim rests on evidence of the same strength as the claim itself.
 */
public class DssLta {

    private static String scopeOf(SignatureWrapper s) {
        List<XmlSignatureScope> sc = s.getSignatureScopes();
        if (sc == null || sc.isEmpty()) return "(none)";
        StringBuilder sb = new StringBuilder();
        for (XmlSignatureScope x : sc) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(x.getScope());
        }
        return sb.toString();
    }

    private static void report(File f, CommonCertificateVerifier cv) {
        System.out.printf("%n--- %s (%d B)%n", f.getName(), f.length());
        try {
            DSSDocument doc = new FileDocument(f);
            SignedDocumentValidator v = SignedDocumentValidator.fromDocument(doc);
            v.setCertificateVerifier(cv);
            Reports reports = v.validateDocument();
            DiagnosticData dd = reports.getDiagnosticData();

            List<SignatureWrapper> sigs = dd.getSignatures();
            System.out.printf("    so chu ky: %d%n", sigs.size());
            for (SignatureWrapper s : sigs) {
                String who = "(?)";
                try {
                    var c = s.getSigningCertificate();
                    if (c != null) who = c.getCommonName();
                } catch (Exception ignored) { }
                System.out.printf("      signer=%-20s format=%-22s intact=%-5s scope=%s%n",
                        who, s.getSignatureFormat(), s.isSignatureIntact(), scopeOf(s));
            }
            if (sigs.isEmpty()) System.out.println("      -> KHONG NHAN DIEN CHU KY NAO");
        } catch (Exception e) {
            System.out.printf("    LOI: %s: %s%n", e.getClass().getSimpleName(), e.getMessage());
        }
    }

    public static void main(String[] args) {
        File dir = new File(args.length > 0 ? args[0] : "..");
        File rootPem = new File(dir, "_pki_root.pem");

        CommonCertificateVerifier cv = new CommonCertificateVerifier();
        if (rootPem.exists()) {
            CertificateToken root = DSSUtils.loadCertificate(rootPem);
            CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
            trusted.addCertificate(root);
            cv.setTrustedCertSources(trusted);
            System.out.println("Neo tin cay: " + root.getSubject().getPrettyPrintRFC2253());
        } else {
            System.out.println("CANH BAO: khong tim thay _pki_root.pem, chay khong co neo tin cay");
        }

        String[] names = {
            "_pki_inner.pdf",      // luu tru hop phap, chi co dien
            "_pki_hybrid.pdf",     // tai lieu lai nguyen ven
            "_pki_cut3.pdf",       // cat ra -> phai giong het _pki_inner.pdf
            "_pki_cut2.pdf",
            "_pki_cut4.pdf",
        };
        System.out.println("======================================================");
        System.out.println(" DSS — kiem chung muc luu tru voi Test PKI");
        System.out.println("======================================================");
        for (String n : names) {
            File f = new File(dir, n);
            if (f.exists()) report(f, cv);
        }
        System.out.println();
        System.out.println("Muc mong doi: PAdES-BASELINE-LTA (khong phai -T)");
    }
}
