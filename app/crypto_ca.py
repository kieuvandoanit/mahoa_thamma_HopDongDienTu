from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from pathlib import Path
from cryptography.hazmat.primitives.serialization import NoEncryption


CA_DIR = Path("storage/ca"); CA_DIR.mkdir(parents=True, exist_ok=True)

def create_or_load_root_ca():
    key_file = CA_DIR / "rootCA.key"
    cert_file = CA_DIR / "rootCA.pem"
    if key_file.exists() and cert_file.exists():
        key = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
        cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
        return key, cert

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Demo Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Demo Root CA"),
    ])
    cert = (x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(key, hashes.SHA256()))
    key_file.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        NoEncryption())
    )
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert

def issue_user_cert(common_name: str, save_dir: Path):
    save_dir.mkdir(parents=True, exist_ok=True)
    ca_key, ca_cert = create_or_load_root_ca()
    user_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Demo E-Contract"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = (x509.CertificateBuilder()
        .subject_name(subject).issuer_name(ca_cert.subject)
        .public_key(user_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=365*2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,  # This is "non repudiation"
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.oid.ExtendedKeyUsageOID.CODE_SIGNING,
            ]),
            critical=False,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256()))
    key_path  = save_dir / f"{common_name}.key.pem"
    cert_path = save_dir / f"{common_name}.cert.pem"
    key_path.write_bytes(user_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        NoEncryption())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path
