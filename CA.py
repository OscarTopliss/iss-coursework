######################### CA PROGRAM ###########################################
# This program will act as a root CA for the purpose of verifying new
# certificates issued by the server program.
## imports
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509 import NameOID, Certificate
import datetime
from logging import critical

def generate_private_key() -> EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP521R1())

def generate_root_key() -> EllipticCurvePrivateKey:
    return generate_private_key()


# Generate a new root certificate for the CA program.
# This is mostly followed from the cryptography library tutorial:
# https://cryptography.io/en/latest/x509/tutorial/#creating-a-ca-hierarchy
def generate_root_certificate(key: EllipticCurvePrivateKey) -> Certificate:
    root_key = key

    public_key = root_key.public_key()


    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "UK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "West Midlands"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Coventry"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Definitely Real CA Inc."),
        x509.NameAttribute(NameOID.COMMON_NAME, "Definitely Real CA Inc. Root CA"),
    ])

    serial_number = x509.random_serial_number()

    current_date = datetime.datetime.now(datetime.timezone.utc)

    expiry_date = datetime.datetime.now(datetime.timezone.utc) + \
    datetime.timedelta(days=365 * 10)

    root_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        serial_number
    ).not_valid_before(
        current_date
    ).not_valid_after(
        expiry_date
    ).add_extension(
        # https://cryptography.io/en/latest/x509/reference/#cryptography.x509.BasicConstraints.path_length
        # Max path length means subordinate certificates can't sign other certs.
        x509.BasicConstraints(ca=True,path_length=1),
        critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature = True,
            content_commitment = False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical = True
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(
            public_key
        ),
        critical=False
    ).sign(
        root_key,
        hashes.SHA256()
    )

    return root_cert

    # https://cryptography.io/en/latest/x509/tutorial/#creating-a-self-signed-certificate
def generate_and_store_root_certificate():
    key = generate_root_key()

    with open("./HSM-CA/root-key.pem", "wb") as key_file:
        key_file.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            # In reality the passphrase shouldn't be here or in the HSM,
            # This is for expedience.
            encryption_algorithm=serialization.BestAvailableEncryption(
                b"super-secure-passphrase"
            )))

    certificate = generate_root_certificate(key)

    with open("./HSM-CA/root-certificate.pem", "wb") as cert_file:
        cert_file.write(certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        ))


if __name__ == "__main__":
    pass
    # generate_and_store_root_certificate()
