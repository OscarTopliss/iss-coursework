######################### SERVER PROGRAM #######################################
# The server program, which contains most of the functionality of the system.

## Imports
# Cryptography
from errno import EWOULDBLOCK
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509 import NameOID, Certificate
import datetime
# Sockets/SSL
import socket
import ssl
from enum import Enum

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


# Class to handle client sessions.
# Once a client socket is created, it's passed to an instance of this class.
# Each instance is repsponsible for closing its given clientSocket object, and
# for returning so that the controlling thread/process can be freed.
class ClientSession:
    # Enum which contains the "point" the client is at. E.g. the login menu,
    # financial transaction menu etc.
    class SessionState(Enum):
        START_MENU = 1

    # Enum which contains the possible user types, including unauthenticated.
    class UserType(Enum):
        NOT_AUTHENTICATED = 0
        CLIENT = 1
        FINANCIAL_ADVISOR = 2
        SYSTEM_ADMINISTRATOR = 3


    def __init__(self, clientSocket: ssl.SSLSocket):
        self.username = None
        self.user_type = self.UserType.NOT_AUTHENTICATED
        self.session_state = self.SessionState.START_MENU
        self.client_socket = clientSocket
        self.sessionActive = True

    # Enum to define message codes, used in the recv_message() function.
    class MessageCode(Enum):
        OPEN = 1
        CLOSED = 2
        ERROR = 3
    # Loop which receives a full message. If it receives b'', i.e. the
    # connection is closed, returns (message, MessageCode), with messageCode
    # telling the handler whether the connection has been closed or not.
    def recv_message(self) -> tuple[bytes, MessageCode]:
        message = b''


    # Finds the message to send to the client program based on the status of
    # self.sessionState, which references the SessionState enum.
    def get_message_to_send(self) -> bytes:
        if self.session_state == self.SessionState.START_MENU:
            return b'''\
Welcome to MyFinance.\
'''
        return b''

    # Loop which handles a session until it terminates. Returns 0 if the
    # session ended as espected, 1 if an error occured
    def sessionHandlerLoop(self) -> int:
        while True:
            message_to_send = self.get_message_to_send()
            self.client_socket.sendall(b"Hello, World!")
            message, connectionStatus = self.client_socket.recv()
            print(f"{message!r}")

    # This is the method which will be used by the handling thread/process. It
    # abstracts away the object itself, which lets the thread/process' get freed
    # when it's associated function returns.
    @staticmethod
    def handle_session(clientSocket: ssl.SSLSocket):
        handler = ClientSession(clientSocket)
        handler.sessionHandlerLoop()
        return






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
                    ClientSession.handle_session(client_socket)
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
