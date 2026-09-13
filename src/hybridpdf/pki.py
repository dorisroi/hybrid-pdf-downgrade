"""
The test PKI.

Two grades are available, and the distinction matters for what a result is
allowed to claim:

    selfsigned()  self-signed leaves, no CA. Cheap, but DSS will not grade a
                  document above PAdES-BASELINE-T because it cannot anchor the
                  archival evidence. Used only by the controls.

    TestPKI       a real root CA issuing all three leaves, plus a CRL so that
                  revocation data exists and B-LT is reachable. Required for
                  any claim about archival levels.

`kind` selects the algorithm: "ec" (ECDSA P-256), "mldsa" (ML-DSA-44, FIPS 204)
or "rsa" (used only for the timestamp authority). A signer's `algo` string is
carried through to the results so no report can silently describe an ECDSA key
as post-quantum -- the failure mode that produced the paper's earlier number
mix-up.
"""
import datetime
from dataclasses import dataclass

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, mldsa

from asn1crypto import x509 as a1x, keys as a1k, crl as a1crl

from . import paths

NOW = datetime.datetime.now(datetime.timezone.utc)
FAR = NOW + datetime.timedelta(days=3650)

ALGO_NAME = {"ec": "ECDSA P-256", "mldsa": "ML-DSA-44", "rsa": "RSA 2048"}


@dataclass
class Signer:
    """A usable signing identity plus an honest label for its algorithm."""
    key_path: str
    cert_path: str
    cert: object          # cryptography x509.Certificate
    algo: str             # human-readable, e.g. "ML-DSA-44"
    kind: str             # "ec" | "mldsa" | "rsa"

    @property
    def asn1(self):
        return to_a1(self.cert)


def name(cn):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Hybrid PDF Study"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def to_a1(cert):
    return a1x.Certificate.load(cert.public_bytes(serialization.Encoding.DER))


def _newkey(kind):
    if kind == "ec":
        return ec.generate_private_key(ec.SECP256R1()), hashes.SHA256()
    if kind == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048), hashes.SHA256()
    if kind == "mldsa":
        return mldsa.MLDSA44PrivateKey.generate(), None   # signs the message directly
    raise ValueError(f"unknown key kind {kind!r}")


def _write(tag, key, cert):
    kp = paths.art(f"{tag}_key.pem")
    cp = paths.art(f"{tag}_cert.pem")
    open(kp, "wb").write(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    open(cp, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    return kp, cp


def selfsigned(tag, cn, kind):
    """A self-signed end-entity certificate. Controls only."""
    key, algo = _newkey(kind)
    cert = (x509.CertificateBuilder()
            .subject_name(name(cn)).issuer_name(name(cn))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - datetime.timedelta(days=1))
            .not_valid_after(FAR)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=True,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False), True)
            .sign(key, algo))
    kp, cp = _write(tag, key, cert)
    return Signer(kp, cp, cert, ALGO_NAME[kind], kind)


class TestPKI:
    """Root CA + leaves + CRL, anchored so DSS can grade archival levels."""

    def __init__(self, tag="pki"):
        self.tag = tag
        self.root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.root_cert = (x509.CertificateBuilder()
                          .subject_name(name("Test Root CA"))
                          .issuer_name(name("Test Root CA"))
                          .public_key(self.root_key.public_key())
                          .serial_number(x509.random_serial_number())
                          .not_valid_before(NOW - datetime.timedelta(days=1))
                          .not_valid_after(FAR)
                          .add_extension(x509.BasicConstraints(ca=True, path_length=1), True)
                          .add_extension(x509.KeyUsage(
                              digital_signature=True, content_commitment=False,
                              key_encipherment=False, data_encipherment=False,
                              key_agreement=False, key_cert_sign=True, crl_sign=True,
                              encipher_only=False, decipher_only=False), True)
                          .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                              self.root_key.public_key()), False)
                          .sign(self.root_key, hashes.SHA256()))
        self.root_pem = paths.art(f"_{tag}_root.pem")
        open(self.root_pem, "wb").write(
            self.root_cert.public_bytes(serialization.Encoding.PEM))

    def issue(self, tag, cn, kind, tsa=False):
        key, algo = _newkey(kind)
        b = (x509.CertificateBuilder()
             .subject_name(name(cn)).issuer_name(self.root_cert.subject)
             .public_key(key.public_key())
             .serial_number(x509.random_serial_number())
             .not_valid_before(NOW - datetime.timedelta(days=1))
             .not_valid_after(NOW + datetime.timedelta(days=1825))
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
             .add_extension(x509.KeyUsage(
                 digital_signature=True, content_commitment=not tsa,
                 key_encipherment=False, data_encipherment=False,
                 key_agreement=False, key_cert_sign=False, crl_sign=False,
                 encipher_only=False, decipher_only=False), True)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                 self.root_key.public_key()), False))
        if tsa:
            # RFC 3161 requires this EKU, and requires it critical
            b = b.add_extension(x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.TIME_STAMPING]), True)
        cert = b.sign(self.root_key, hashes.SHA256())
        kp, cp = _write(tag, key, cert)
        return Signer(kp, cp, cert, ALGO_NAME[kind], kind), key

    def crl(self):
        """Empty CRL: nothing revoked, but revocation data now EXISTS, which is
        what a B-LT / B-LTA grading requires."""
        c = (x509.CertificateRevocationListBuilder()
             .issuer_name(self.root_cert.subject)
             .last_update(NOW - datetime.timedelta(hours=1))
             .next_update(NOW + datetime.timedelta(days=365))
             .sign(self.root_key, hashes.SHA256()))
        return a1crl.CertificateList.load(c.public_bytes(serialization.Encoding.DER))

    @staticmethod
    def private_key_info(key):
        return a1k.PrivateKeyInfo.load(key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
