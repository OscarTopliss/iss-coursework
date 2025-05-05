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
            encryption_algorithm=serialization.NoEncryption()
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
    ).sign(key, hashes.SHA256())

    with open("./shared-certificates/root-certificate.pem", "wb") as certfile:
        certfile.write(cert.public_bytes(serialization.Encoding.PEM))

class ClientSession:
    clientSocket = None
    username = None
    userType = None
    authenticated = False
    def __init__(self, clientSocket):
        self.clientSocket = clientSocket


class Server:
    server_socket = None
    test = False
    test_client = None
    client_sockets = []

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain('./shared-certificates/root-certificate.pem',
        './HSM-server/private-key.pem')
    ssl_context.load_verify_locations(
        './shared-certificates/root-certificate.pem'
    )
    hostname = '127.0.0.1'
    port = 1234

    def __init__(self, test=False):
        self.test = test


    def start_server_loop(self, backlog: int):
        context = self.ssl_context

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.bind((self.hostname, self.port))
            sock.listen(backlog)
            with context.wrap_socket(sock, server_side=True) as ssock:
                print("Listener started.")
                while True:
                    client_socket, client_address = ssock.accept()
                    self.client_sockets.append(client_socket)
                    print(f"client accepted. Index: \
                        {len(self.client_sockets) -1}")
        pass


    def recv_client_message(self,socket_index) -> bytes:
        socket = self.client_sockets[socket_index]
        message = socket.recv()
        pass
        return message


if __name__ == "__main__":
    # gen_self_signed_cert()
    server = Server()
    server.start_server_loop(5)
