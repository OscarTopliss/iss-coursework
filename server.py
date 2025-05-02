######################### SERVER PROGRAM #######################################
# The server program, which contains most of the functionality of the system.

## Imports
# Cryptography
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509 import NameOID, Certificate
import datetime
# Sockets/SSL
import socket
import ssl

##### PKI
# Generates a new X.509 self-signed certificate, which will be used for TLS
# encryption. Stores the private key in an "HSM". The certificate is stored in
# ./shared-certificates, which is accessible to the client program.
# Mostly followed the tutorial at https://cryptography.io/en/latest/x509/tutorial/#creating-a-self-signed-certificate
def gen_self_signed_cert():
    key = ec.generate_private_key(ec.SECP521R1())
    public_key = key.public_key()

    with open("./HSM-server/private-key.pem", "wb") as keyfile:
        keyfile.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.\
            BestAvailableEncryption(b"super-secure-passphrase"),
        ))

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

    cert = x509.CertificateBuilder().subject_name(
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
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False
    ).sign(key, hashes.SHA512())

    with open("./shared-certiciates", "wb") as certfile:
        certfile.write(cert.public_bytes(serialization.Encoding.PEM))


class Server:
    server_socket = None

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain('./shared-certificates/root-certificate.pem',
        './HSM-server/root-key.pem')

    def start_server_socket(self, backlog: int):
        context = self.ssl_context

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.bind(('localhost', 1234))
            sock.listen(5)
            with context.wrap_socket(sock, server_side=True) as ssock:
                conn, addr = ssock.accept()
        pass

    def accept_client_connection(self):
        pass

    def recv_client_message(self,socketObj) -> bytes:
        pass
        return b''


    def main():
        while True:
            (clientsocket, address) =
