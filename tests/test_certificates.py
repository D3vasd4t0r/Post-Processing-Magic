import ipaddress
import ssl

from cryptography import x509

from forensic_app.certificates import ensure_certificate


def test_generated_certificate_is_reused_and_covers_loopback(tmp_path):
    cert, key = ensure_certificate(tmp_path)
    original = cert.read_bytes()
    certificate = x509.load_pem_x509_certificate(original)
    assert certificate.issuer == certificate.subject
    certificate.verify_directly_issued_by(certificate)
    names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "localhost" in names.get_values_for_type(x509.DNSName)
    assert ipaddress.ip_address("127.0.0.1") in names.get_values_for_type(x509.IPAddress)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    assert ensure_certificate(tmp_path) == (cert, key)
    assert cert.read_bytes() == original
