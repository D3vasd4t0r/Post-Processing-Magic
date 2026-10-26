"""Local self-signed server certificate; no trust-store changes or external services."""

import ipaddress
import socket
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def local_names() -> list[x509.GeneralName]:
    """Collect localhost, host DNS name and resolvable local IP addresses for certificate SANs."""
    names: set[str] = {"localhost", socket.gethostname().lower()}
    addresses = {"127.0.0.1", "::1"}
    try:
        for entry in socket.getaddrinfo(socket.gethostname(), None):
            addresses.add(entry[4][0].split("%")[0])
    except OSError:
        pass
    return [x509.DNSName(name) for name in sorted(names)] + [
        x509.IPAddress(ipaddress.ip_address(value)) for value in sorted(addresses)
    ]


def ensure_certificate(directory: Path) -> tuple[Path, Path]:
    """Return an existing usable TLS identity or generate a local EC self-signed pair.

    An existing pair is reused only if it covers current local names and remains
    valid beyond seven days. Malformed or mismatched files raise instead of silently
    being replaced; generated files replace their targets through temporary paths.
    No system or browser trust store is changed."""
    directory.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = directory / "server.crt", directory / "server.key"
    now = datetime.now(UTC)
    names = local_names()
    if cert_path.exists() and key_path.exists():
        # Fail clearly on damaged or mismatched files; do not silently replace an identity.
        certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        existing_names = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        if (
            certificate.not_valid_after_utc > now + timedelta(days=7)
            and certificate.not_valid_before_utc <= now
            and all(name in existing_names for name in names)
        ):
            return cert_path, key_path
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PostProcessingMagic")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_temp, cert_temp = directory / "server.key.new", directory / "server.crt.new"
    key_temp.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ))
    key_temp.chmod(0o600)
    cert_temp.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_temp.replace(key_path)
    cert_temp.replace(cert_path)
    return cert_path, key_path
