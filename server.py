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
import json
# Sockets/SSL
import socket
import ssl
# Multiprocessing
from multiprocessing import Process, Queue, Pipe
# Database
from posix import urandom
from server_database import Database, RequestResponse
from server_database import UserType as DBUserType
import server_database
# Misc
from enum import Enum
from time import sleep
import os

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
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                "Definitely Real CA Inc."
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                "Definitely Real CA Inc. Root CA"
            ),
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

def write_secret_to_hsm(key: str, value: str):
    with open("./HSM-server/secrets.json", "r") as secrets_file:
        secrets = json.load(secrets_file)
        secrets[key] = value
        with open("./HSM-server/secrets.json", "w+") as new_secrets_file:
            json.dump(secrets, new_secrets_file)

# Class to handle client sessions.
# Once a client socket is created, it's passed to an instance of this class.
# Each instance is repsponsible for closing its given clientSocket object, and
# for returning so that the controlling thread/process can be freed.
class ClientSession:
    # Enum which contains the "point" the client is at. E.g. the login menu,
    # financial transaction menu etc.
    class SessionState(Enum):
        START_MENU = 1
        LOGIN_MENU_USERNAME = 2
        LOGIN_MENU_PASSWORD = 3
        CREATE_NEW_USER_USERNAME = 4
        CREATE_NEW_USER_PASSWORD = 5

    # Enum which contains the possible user types, including unauthenticated.
    class UserType(Enum):
        NOT_AUTHENTICATED = 0
        CLIENT = 1
        FINANCIAL_ADVISOR = 2
        SYSTEM_ADMINISTRATOR = 3

    # In cases where the user is
    class ErrorMessage(Enum):
        VALID_INPUT = 0
        INVALID_INPUT_GENERIC = 1
        NEW_USER_NAME_TOO_LONG = 2
        NEW_USER_NAME_INVALID_CHARS = 3
        NEW_USER_ALREADY_EXISTS = 4
        pass



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
        valid_message = False
        while not valid_message:
            new_data = self.client_socket.recv(1024)
            # If there was no data when receiving began, the connection is
            # closed
            if new_data == b'' and message == b'':
                return(message, self.MessageCode.CLOSED)
            # This shouldn't be possible unless the server closes the connection
            # early.
            if new_data == b'':
                return(message, self.MessageCode.ERROR)

            message += new_data
            # Once message is a valid json object, we know we've received all
            # the data.
            try:
                json.loads(message.decode())
            except ValueError:
                pass
            else:
                valid_message = True
        return (message, self.MessageCode.OPEN)

    # Handles a message and it's error code. Returns True if the the message
    # is valid and the connection is still open, False otherwise.
    # This lets the client program safely exit the loop when needed.
    def handle_client_response(self,
        message: tuple[bytes, MessageCode]) -> bool:
        if message[1] == self.MessageCode.ERROR:
            return False
        if message[1] == self.MessageCode.CLOSED:
            return False
        message_json = json.loads(message[0].decode())
        response = message_json["message"]

        if self.session_state == self.SessionState.START_MENU:
            if response == "1":
                self.session_state = self.SessionState.LOGIN_MENU_USERNAME
            elif response == "2":
                self.session_state = self.SessionState.CREATE_NEW_USER_USERNAME
            else:
                self.error_message = self.ErrorMessage.INVALID_INPUT_GENERIC

        if self.session_state == self.SessionState.LOGIN_MENU_USERNAME:
            if response.upper() == "M":
                self.session_state = self.SessionState.START_MENU

        if self.session_state == self.SessionState.CREATE_NEW_USER_USERNAME:
            if response.upper() == "M":
                self.session_state = self.SessionState.START_MENU
                return True
            if len(response) >= 60:
                self.error_message = self.ErrorMessage.NEW_USER_NAME_TOO_LONG
                return True
            if not response.isalnum():
                self.error_message = self.ErrorMessage.\
                    NEW_USER_NAME_INVALID_CHARS
                return True
            socket_conn, db_conn = Pipe()
            request = server_database.Database.DBRDoesUserExist(
                process_conn = db_conn,
                username = response
            )
            request_result = socket_conn.recv()
            if request_result == RequestResponse.USER_EXISTS:
                self.error_message = self.ErrorMessage.NEW_USER_ALREADY_EXISTS
                return True
            if request_result == RequestResponse.USER_DOESNT_EXIST:
                self.session_state = self.SessionState.CREATE_NEW_USER_PASSWORD
                return True

        if self.session_state == self.SessionState.CREATE_NEW_USER_PASSWORD:
            pass

        return True


    # Finds the message to send to the client program based on the status of
    # self.sessionState, which references the SessionState enum.
    def get_message_to_send(self) -> str:
        if self.session_state == self.SessionState.START_MENU:
            return (
                'Welcome to MyFinance.\n'
                '1 Login\n'
                '2 Create Account\n'
                'Q Quit'
                )
        if self.session_state == self.SessionState.LOGIN_MENU_USERNAME:
            return(
                '## Login ##\n'
                'Please enter username:\n'
                'M Main Menu\n'
                'Q Quit'
            )
        if self.session_state == self.SessionState.CREATE_NEW_USER_USERNAME:
            return(
                '## Create new user ##\n'
                'Please enter username for new user:\n'
                'M Main Menu\n'
                'Q Quit'
            )
        return ""

    def reset_error(self, message: str) -> str:
        self.error_message = self.ErrorMessage.VALID_INPUT
        return message

    def get_error_message(self) -> str:
        if self.error_message == self.ErrorMessage.NEW_USER_NAME_TOO_LONG:
            return self.reset_error(
                '#! Invalid Input !#\n'
                'Given username is too long.\n'
                'Please enter a username under 60 characters.'
            )
        if self.error_message == self.ErrorMessage.NEW_USER_NAME_INVALID_CHARS:
            return self.reset_error(
                '#! Invalid Input !#\n'
                'Username must only contain letters and numbers.\n'
            )
        if self.error_message == self.ErrorMessage.NEW_USER_ALREADY_EXISTS:
            return self.reset_error(
                '#! Invalid Input !#\n'
                'That username is taken. Please select another.'
            )
        return self.reset_error('#! Invalid Input !#')

    # Loop which handles a session until it terminates.
    def sessionHandlerLoop(self):
        while True:
            if self.error_message != self.ErrorMessage.VALID_INPUT:
                message_dict = {'message':f'\n{self.get_error_message()}\
                    \n\n{self.get_message_to_send()}'}
            else:
                message_dict = {'message':f'\n{self.get_message_to_send()}'}
            message_json = json.dumps(message_dict).encode()
            self.client_socket.sendall(message_json)
            (message, code) = self.recv_message()
            if not self.handle_client_response((message,code)):
                print("Connection failed or ended by client.")
                self.client_socket.close()
                break



    # This is the method which will be used by the handling thread/process. It
    # abstracts away the object itself, which lets the thread/process' get freed
    # when it's associated function returns.
    @staticmethod
    def handle_sessions(serverSocket: ssl.SSLSocket, queue: Queue):
        while True:
            clientSocket = serverSocket.accept()
            handler = ClientSession(clientSocket[0], queue)
            print(f"client connected, address = {clientSocket[1]}")
            handler.sessionHandlerLoop()

    def __init__(self, clientSocket: ssl.SSLSocket, queue: Queue):
        self.username = None
        self.user_type = self.UserType.NOT_AUTHENTICATED
        self.session_state = self.SessionState.START_MENU
        self.error_message = self.ErrorMessage.VALID_INPUT
        self.client_socket = clientSocket
        self.database_queue = queue
        # Used to contain arguments for multi-stage things like creating a new
        # user. If the request fails at any point, this dictionary is cleared.
        self.current_request_args = {}
        # variable used to send an "Invalid response" message to users







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


    def load_binary_secret_from_HSM(self, secret_name: str):
        with open("./HSM-server/secrets.json") as secrets_file:
            secrets = json.load(secrets_file)
            return bytes.fromhex(secrets[secret_name])



    def start_server_loop(self, backlog: int):
        context = self.ssl_context

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.bind((self.hostname, self.port))
            sock.listen(backlog)

            with context.wrap_socket(sock, server_side=True) as ssock:
                print("Listener started.")
                # This multiprocessing setup is based on this:
                # https://stackoverflow.com/a/8545724
                process_num = 5



                database_queue = Queue
                database_worker = Process(
                    target = Database.start_database,
                    args = (database_queue,)
                )

                socket_worker_pool = [
                    Process(
                        target = ClientSession,
                        args = (ssock, database_queue,)
                    )
                    for x in range(process_num)
                ]

                database_worker.start()


                for worker in socket_worker_pool:
                    worker.daemon = True
                    worker.start()



                while True:
                    sleep(10)


        pass




if __name__ == "__main__":
    # write_secret_to_hsm("pepper", str(os.urandom(16).hex()))
    # gen_self_signed_cert()
    server = Server()
    server.start_server_loop(10)
