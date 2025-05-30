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
        CREATE_USER_SUCCESSFUL = 6
        CLIENT_MENU = 7
        LOGIN_SUCCESSFUL = 8
        ADVISOR_MENU = 9
        ADMIN_MENU = 10
        ADMIN_NEW_USER_TYPE = 11
        ADMIN_NEW_USER_USERNAME = 12
        ADMIN_NEW_USER_PASSWORD = 13
        ADMIN_NEW_USER_SUCCESS = 14
        ADMIN_LOG_MENU = 15
        ADMIN_VIEW_ALL_LOGS = 16
        ADMIN_VIEW_LOGS_BY_ADMIN_USERNAME = 17
        ADMIN_VIEW_LOGS_BY_ADMIN_RESULT = 18
        ACCOUNT_DETAILS_MENU = 19
        VIEW_ACCOUNT_DETAILS = 20
        SET_EMAIL_ADDRESS = 21
        CHANGE_PASSWORD = 22
        INVESTMENT_MENU = 23
        VIEW_PORTFOLIO = 24
        VIEW_COMPANIES = 25
        BUY_SHARES_COMPANY_CODE = 26
        BUY_SHARES_QUANTITY = 27
        BUY_SHARES_SUCCESS = 28

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
        NO_PASSWORD_GIVEN = 5
        NEW_USER_PASSWORD_TOO_SHORT = 6
        NO_USERNAME_GIVEN = 7
        INVALID_CREDENTIALS = 8
        USER_DOESNT_EXIST = 9
        USER_NOT_ADMIN = 10
        INVALID_EMAIL_ADDRESS = 11
        INVALID_COMPANY_CODE = 12
        NOT_POSITIVE_INTEGER = 13



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
    def return_to_start_menu(self):
        self.request_args = {}
        self.session_state = self.SessionState.START_MENU

    def return_to_admin_menu(self):
        self.request_args = {}
        self.session_state = self.SessionState.ADMIN_MENU

    def return_to_client_menu(self):
        self.request_args = {}
        self.session_state = self.SessionState.CLIENT_MENU

    def handle_client_response(self,
        message: tuple[bytes, MessageCode]) -> bool:
        if message[1] == self.MessageCode.ERROR:
            return False
        if message[1] == self.MessageCode.CLOSED:
            return False
        message_json = json.loads(message[0].decode())
        response = message_json["message"]

        ############### UNAUTHENTICATED METHODS ################################
        if self.session_state == self.SessionState.START_MENU:
            if response == "1":
                self.session_state = self.SessionState.LOGIN_MENU_USERNAME
                return True
            elif response == "2":
                self.session_state = self.SessionState.CREATE_NEW_USER_USERNAME
                return True
            else:
                self.error_message = self.ErrorMessage.INVALID_INPUT_GENERIC
                return True

        if self.session_state == self.SessionState.LOGIN_MENU_USERNAME:
            if response.upper() == "M":
                self.return_to_start_menu()
                return True
            if len(response) == 0:
                self.error_message = self.ErrorMessage.NO_USERNAME_GIVEN
                return True
            self.session_state = self.SessionState.LOGIN_MENU_PASSWORD
            self.request_args["username"] = response
            return True

        if self.session_state == self.SessionState.LOGIN_MENU_PASSWORD:
            if response.upper() == "M":
                self.return_to_start_menu()
                return True
            if len(response) == 0:
                self.error_message = self.ErrorMessage.NO_PASSWORD_GIVEN
                self.session_state = self.SessionState.LOGIN_MENU_USERNAME
                return True

            socket_conn, db_conn = Pipe()
            self.request_args["password"] = response
            request = Database.DBRCheckUserCredentials(
                process_conn = db_conn,
                username = self.request_args["username"],
                password = self.request_args["password"]
            )
            self.database_queue.put(request)
            request_response = socket_conn.recv()

            if request_response == RequestResponse.\
            USER_CREDENTIALS_VALID_CLIENT:
                self.session_state = self.SessionState.LOGIN_SUCCESSFUL
                self.username = self.request_args["username"]
                self.user_type = self.UserType.CLIENT
                self.request_args = {}
                return True
            if request_response == RequestResponse.\
            USER_CREDENTIALS_VALID_ADVISOR:
                self.session_state = self.SessionState.LOGIN_SUCCESSFUL
                self.username = self.request_args["username"]
                self.user_type = self.UserType.FINANCIAL_ADVISOR
                self.request_args = {}
                return True
            if request_response == RequestResponse.\
            USER_CREDENTIALS_VALID_ADMIN:
                self.session_state = self.SessionState.LOGIN_SUCCESSFUL
                self.username = self.request_args["username"]
                self.user_type = self.UserType.SYSTEM_ADMINISTRATOR
                process_conn, db_conn = Pipe()
                request = Database.DBRLogAdminLogin(
                    process_conn = db_conn,
                    admin_username = self.username
                )
                self.database_queue.put(request)
                process_conn.recv()

                self.request_args = {}
                return True
            if request_response == RequestResponse.USER_CREDENTIALS_INVALID:
                self.session_state = self.SessionState.LOGIN_MENU_USERNAME
                self.error_message = self.ErrorMessage.INVALID_CREDENTIALS
                return True


        if self.session_state == self.SessionState.LOGIN_SUCCESSFUL:
            if self.user_type == self.UserType.CLIENT:
                self.session_state = self.SessionState.CLIENT_MENU
                return True
            if self.user_type == self.UserType.FINANCIAL_ADVISOR:
                self.session_state = self.SessionState.ADVISOR_MENU
                return True
            if self.user_type == self.UserType.SYSTEM_ADMINISTRATOR:
                self.session_state = self.SessionState.ADMIN_MENU
                return True


        if self.session_state == self.SessionState.CREATE_NEW_USER_USERNAME:
            if response.upper() == "M":
                self.return_to_start_menu()
                return True
            if len(response) >= 60:
                self.error_message = self.ErrorMessage.NEW_USER_NAME_TOO_LONG
                return True
            if len(response) == 0:
                self.error_message = self.ErrorMessage.NO_USERNAME_GIVEN
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
            self.database_queue.put(request)
            request_result = socket_conn.recv()
            socket_conn.close()
            print(request_result)
            if request_result == RequestResponse.USER_EXISTS:
                self.error_message = self.ErrorMessage.NEW_USER_ALREADY_EXISTS
                return True
            if request_result == RequestResponse.USER_DOESNT_EXIST:
                self.session_state = self.SessionState.CREATE_NEW_USER_PASSWORD
                self.request_args["username"] = response
                return True

        if self.session_state == self.SessionState.CREATE_NEW_USER_PASSWORD:
            if response.upper() == "M":
                self.return_to_start_menu()
                return True
            if len(response) == 0:
                self.error_message = self.ErrorMessage.\
                NO_PASSWORD_GIVEN
                self.session_state = self.SessionState.CREATE_NEW_USER_USERNAME
                return True
            if len(response) < 10:
                self.error_message = self.ErrorMessage.\
                NEW_USER_PASSWORD_TOO_SHORT
                self.session_state = self.SessionState.CREATE_NEW_USER_USERNAME
                return True

            self.request_args["password"] = response

            socket_conn, db_conn = Pipe()

            request = server_database.Database.DBRCreateNewUser(
                process_conn = db_conn,
                username = self.request_args["username"],
                password = self.request_args["password"],
                user_type = DBUserType.CLIENT
            )

            self.database_queue.put(request)

            request_response = socket_conn.recv()
            socket_conn.close()

            if request_response == RequestResponse.CREATE_USER_SUCCESSFUL:
                self.username = self.request_args["username"]
                self.user_type = self.UserType.CLIENT
                self.session_state = self.SessionState.CREATE_USER_SUCCESSFUL
                self.request_args = {}
                return True
            if request_response == RequestResponse.CREATE_USER_USER_EXISTS:
                # This *theoretically* shouldn't be possible to reach.
                self.error_message = self.ErrorMessage.NEW_USER_ALREADY_EXISTS
                self.session_state = self.SessionState.CREATE_NEW_USER_USERNAME
                return True

        if self.session_state == self.SessionState.CREATE_USER_SUCCESSFUL:
            self.return_to_client_menu()
            return True

        ############### ADMIN METHODS ##########################################

        if self.session_state == self.SessionState.ADMIN_MENU:
            if response == "1":
                self.session_state = self.SessionState.ADMIN_NEW_USER_TYPE
                return True
            if response == "2":
                self.session_state = self.SessionState.ADMIN_LOG_MENU
                return True
            self.error_message = self.ErrorMessage.INVALID_INPUT_GENERIC
            return True


        if self.session_state == self.SessionState.ADMIN_NEW_USER_TYPE:
            if response.upper() == "M":
                self.return_to_admin_menu()
                return True
            if response == "1":
                self.request_args["type"] = DBUserType.SYSTEM_ADMINISTRATOR
                self.session_state = self.SessionState.ADMIN_NEW_USER_USERNAME
                return True
            if response == "2":
                self.request_args["type"] = DBUserType.FINANCIAL_ADVISOR
                self.session_state = self.SessionState.ADMIN_NEW_USER_USERNAME
                return True
            self.error_message = self.ErrorMessage.INVALID_INPUT_GENERIC
            return True

        if self.session_state == self.SessionState.ADMIN_NEW_USER_USERNAME:
            if response.upper() == "M":
                self.return_to_admin_menu()
                return True
            if len(response) >= 60:
                self.error_message = self.ErrorMessage.NEW_USER_NAME_TOO_LONG
                self.session_state = self.SessionState.ADMIN_NEW_USER_TYPE
                self.request_args = {}
                return True
            if len(response) == 0:
                self.error_message = self.ErrorMessage.NO_USERNAME_GIVEN
                self.session_state = self.SessionState.ADMIN_NEW_USER_TYPE
                self.request_args = {}
                return True
            if not response.isalnum():
                self.error_message = self.ErrorMessage.\
                    NEW_USER_NAME_INVALID_CHARS
                self.session_state = self.SessionState.ADMIN_NEW_USER_TYPE
                self.request_args = {}
                return True
            socket_conn, db_conn = Pipe()
            request = server_database.Database.DBRDoesUserExist(
                process_conn = db_conn,
                username = response
            )
            self.database_queue.put(request)
            request_result = socket_conn.recv()
            socket_conn.close()
            print(request_result)
            if request_result == RequestResponse.USER_EXISTS:
                self.error_message = self.ErrorMessage.NEW_USER_ALREADY_EXISTS
                self.session_state = self.SessionState.ADMIN_NEW_USER_TYPE
                self.request_args = {}
                return True
            if request_result == RequestResponse.USER_DOESNT_EXIST:
                self.session_state = self.SessionState.ADMIN_NEW_USER_PASSWORD
                self.request_args["username"] = response
                return True

        if self.session_state == self.SessionState.ADMIN_NEW_USER_PASSWORD:
            if response.upper() == "M":
                self.return_to_admin_menu()
                return True
            if len(response) == 0:
                self.error_message = self.ErrorMessage.\
                NO_PASSWORD_GIVEN
                self.session_state = self.SessionState.ADMIN_NEW_USER_TYPE
                return True
            if len(response) < 10:
                self.error_message = self.ErrorMessage.\
                NEW_USER_PASSWORD_TOO_SHORT
                self.session_state = self.SessionState.ADMIN_NEW_USER_TYPE
                return True

            self.request_args["password"] = response

            socket_conn, db_conn = Pipe()

            request = server_database.Database.DBRCreateNewUser(
                process_conn = db_conn,
                username = self.request_args["username"],
                password = self.request_args["password"],
                user_type = self.request_args["type"],
                admin = self.username
            )

            self.database_queue.put(request)

            request_response = socket_conn.recv()
            socket_conn.close()

            self.session_state = self.SessionState.ADMIN_NEW_USER_SUCCESS
            return True

        if self.session_state == self.SessionState.ADMIN_NEW_USER_SUCCESS:
            self.return_to_admin_menu()
            return True

        if self.session_state == self.SessionState.ADMIN_LOG_MENU:
            if response.upper() == "M":
                self.return_to_admin_menu()
                return True
            if response == "1":
                self.session_state = self.SessionState.ADMIN_VIEW_ALL_LOGS
                process_conn, db_conn = Pipe()
                request = Database.DBRGetAllAdminLogs(
                    process_conn = db_conn
                )
                self.database_queue.put(request)
                self.request_args["log_string"] = process_conn.recv()
                process_conn.close()
                return True
            if response == "2":
                self.session_state = self.SessionState.\
                ADMIN_VIEW_LOGS_BY_ADMIN_USERNAME
                return True
            self.error_message = self.ErrorMessage.INVALID_INPUT_GENERIC
            return True

        if self.session_state == self.SessionState.ADMIN_VIEW_ALL_LOGS:
            self.return_to_admin_menu()
            return True

        if self.session_state == self.SessionState.\
        ADMIN_VIEW_LOGS_BY_ADMIN_USERNAME:
            if response.upper() == "M":
                self.return_to_admin_menu()
                return True
            if len(response) == 0:
                self.error_message == self.ErrorMessage.NO_USERNAME_GIVEN
                return True
            if len(response) >= 60:
                self.error_message == self.ErrorMessage.NEW_USER_NAME_TOO_LONG
                return True
            socket_conn, db_conn = Pipe()
            request = Database.DBRDoesUserExist(
                process_conn = db_conn,
                username = response
            )
            self.database_queue.put(request)
            request_response = socket_conn.recv()
            if request_response == RequestResponse.USER_DOESNT_EXIST:
                self.error_message = self.ErrorMessage.USER_DOESNT_EXIST
                return True
            socket_conn, db_conn = Pipe()
            print("gets to here")
            request = Database.DBRCheckUserType(
                process_conn = db_conn,
                username = response,
                user_type = DBUserType.SYSTEM_ADMINISTRATOR
            )
            print("and to here")
            self.database_queue.put(request)
            request_response = socket_conn.recv()

            if request_response == RequestResponse.USER_TYPE_INVALID:
                self.error_message = self.ErrorMessage.USER_NOT_ADMIN
                return True

            socket_conn, db_conn = Pipe()
            request = Database.DBRGetLogsByAdmin(
                process_conn = db_conn,
                admin_name = response
            )

            self.database_queue.put(request)
            self.request_args["log_string"] = socket_conn.recv()
            socket_conn.close()
            self.session_state = self.SessionState.\
            ADMIN_VIEW_LOGS_BY_ADMIN_RESULT
            return True

        if self.session_state == self.SessionState.\
        ADMIN_VIEW_LOGS_BY_ADMIN_RESULT:
            self.return_to_admin_menu()
            return True

        ######################### CLIENT METHODS ###############################
        if self.session_state == self.SessionState.CLIENT_MENU:
            if response == "1":
                self.session_state = self.SessionState.ACCOUNT_DETAILS_MENU
                return True
            if response == "2":
                self.session_state = self.SessionState.INVESTMENT_MENU
                return True
            self.error_message = self.ErrorMessage.INVALID_INPUT_GENERIC
            return True

        if self.session_state == self.SessionState.ACCOUNT_DETAILS_MENU:
            print("account details menu")
            if response.upper() == "M":
                self.return_to_client_menu()
                return True
            if response == "1":
                self.session_state = self.SessionState.VIEW_ACCOUNT_DETAILS
                process_conn, db_conn = Pipe()
                request = Database.DBRGetClientAccountDetails(
                    process_conn = db_conn,
                    username = self.username,
                )
                self.database_queue.put(request)
                self.request_args["account_details"] = process_conn.recv()
                process_conn.close()
                return True
            if response == "2":
                self.session_state = self.SessionState.SET_EMAIL_ADDRESS
                return True
            self.error_message = self.ErrorMessage.INVALID_INPUT_GENERIC
            return True

        if self.session_state == self.SessionState.VIEW_ACCOUNT_DETAILS:
            self.return_to_client_menu()
            return True

        # The email checking is very bare here, it just checks for an @
        # symbol and no spaces.
        if self.session_state == self.SessionState.SET_EMAIL_ADDRESS:
            if response.upper() == "M":
                self.return_to_client_menu()
                return True
            if len(response) < 3:
                self.error_message = self.ErrorMessage.INVALID_EMAIL_ADDRESS
                return True
            if not "@" in response:
                self.error_message = self.ErrorMessage.INVALID_EMAIL_ADDRESS
                return True

            process_conn, db_conn = Pipe()
            request = Database.DBRSetClientEmail(
                process_conn = db_conn,
                username = self.username,
                email = response
            )

            self.database_queue.put(request)
            process_conn.recv()
            self.return_to_client_menu()
            return True

        if self.session_state == self.SessionState.INVESTMENT_MENU:
            if response.upper() == "M":
                self.return_to_client_menu()
                return True
            if response == "1":
                self.session_state = self.SessionState.VIEW_PORTFOLIO
                socket_conn, db_conn = Pipe()
                request = Database.DBRGetPortfolio(
                    process_conn = db_conn,
                    username = self.username
                )
                self.database_queue.put(request)

                self.request_args["portfolio_string"] = socket_conn.recv()
                socket_conn.close()
                return True
            if response == "2":
                self.session_state = self.SessionState.VIEW_COMPANIES
                process_conn, db_conn = Pipe()
                request = Database.DBRGetCompanyString(
                    process_conn = db_conn
                )
                self.database_queue.put(request)
                self.request_args["company_string"] = process_conn.recv()
                process_conn.close()
                return True

            if response == "3":
                self.session_state = self.SessionState.BUY_SHARES_COMPANY_CODE
                return True


            self.error_message = self.ErrorMessage.INVALID_INPUT_GENERIC
            return True

        if self.session_state == self.SessionState.VIEW_COMPANIES:
            self.return_to_client_menu()

        if self.session_state == self.SessionState.BUY_SHARES_COMPANY_CODE:
            if response.upper() == "M":
                self.return_to_client_menu()
                return True
            socket_conn, db_conn = Pipe()
            request = Database.DBRCheckCompanyCodeValid(
                process_conn = db_conn,
                company_code = response
            )
            self.database_queue.put(request)
            request_response = socket_conn.recv()
            if request_response == RequestResponse.COMPANY_CODE_INVALID:
                self.error_message = self.ErrorMessage.INVALID_COMPANY_CODE
                return True
            self.request_args["company_code"] = response
            self.session_state = self.SessionState.BUY_SHARES_QUANTITY
            return True

        if self.session_state == self.SessionState.BUY_SHARES_QUANTITY:
            if response.upper() == "M":
                self.return_to_client_menu()
                return True
            if len(response) == 0:
                self.error_message = self.ErrorMessage.INVALID_INPUT_GENERIC
                self.session_state = self.SessionState.BUY_SHARES_COMPANY_CODE
                return True
            try:
                int(response)
            except ValueError:
                self.error_message = self.ErrorMessage.NOT_POSITIVE_INTEGER
                self.session_state = self.SessionState.BUY_SHARES_COMPANY_CODE
                return True
            else:
                shares_to_buy = int(response)
                self.request_args
                socket_conn, db_conn = Pipe()
                request = Database.DBRBuyShares(
                    db_conn,
                    self.username,
                    self.request_args["company_code"],
                    shares_to_buy
                )
                self.database_queue.put(request)
                self.request_args["owned_shares"] = socket_conn.recv()
                self.session_state = self.SessionState.BUY_SHARES_SUCCESS
                return True


        if self.session_state == self.SessionState.BUY_SHARES_SUCCESS:
            self.return_to_client_menu()
            return True

        if self.session_state == self.SessionState.VIEW_PORTFOLIO:
            self.return_to_client_menu()
            return True

        return True
















    # Finds the message to send to the client program based on the status of
    # self.sessionState, which references the SessionState enum.
    ######################### UNAUTHENTICATED STUFF ############################
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
        if self.session_state == self.SessionState.LOGIN_MENU_PASSWORD:
            return(
                '## Login ##\n'
                'Please enter password:\n'
                'M Main Menu\n'
                'Q Quit'
            )
        if self.session_state == self.SessionState.CREATE_NEW_USER_USERNAME:
            return(
                '## Create new user ##\n'
                'Please enter the USERNAME for your new account:\n'
                'M Main Menu\n'
                'Q Quit'
            )
        if self.session_state == self.SessionState.CREATE_NEW_USER_PASSWORD:
            return (
                '## Create new user ##\n'
                'Please enter the PASSWORD for your new account:\n'
                'M Main Menu\n'
                'Q Quit'
            )
        if self.session_state == self.SessionState.CREATE_USER_SUCCESSFUL:
            return (
                '## User Creation Successful ##\n'
                'Successfully created new user.\n'
                f'Now logged in as {self.username}\n'
                '<Enter> Continue\n'
                'Q Quit'
            )
        if self.session_state == self.SessionState.LOGIN_SUCCESSFUL:
            return (
                '## Login successful ##\n'
                f'Now logged in as {self.username}\n'
                '<Enter> continue\n'
                'Q Quit'
            )
        ######################### CLIENT STUFF #################################
        if self.session_state == self.SessionState.CLIENT_MENU:
            return (
                '## Main Menu ##\n'
                '1 Account Details\n'
                '2 Investment Menu\n'
                'Q Quit'
            )
        if self.session_state == self.SessionState.ACCOUNT_DETAILS_MENU:
            return (
                '## Account Details ##\n'
                '1 View Account Details\n'
                '2 Set email address\n'
                'M Main Menu\n'
                'Q Quit'
            )
        if self.session_state == self.SessionState.VIEW_ACCOUNT_DETAILS:
            return (
                '## View Account Details ##\n'
                f'{self.request_args["account_details"]}\n'
                '<Enter> Return to Main Menu\n'
                'Q Quit'
            )

        if self.session_state == self.SessionState.SET_EMAIL_ADDRESS:
            return (
                '## Set Email Address ##\n'
                'Please enter your email address:\n'
                'M Main menu\n'
                'Q Quit'
            )
        if self.session_state == self.SessionState.INVESTMENT_MENU:
            return (
                '## Investment Menu ##\n'
                '1 View Portfolio\n'
                '2 View Companies and share prices\n'
                '3 Buy Shares\n'
                '4 View Messages\n'
                'M Main Menu\n'
                'Q Quit'
            )

        if self.session_state == self.SessionState.VIEW_COMPANIES:
            return (
                '## Companies ##\n'
                f'{self.request_args["company_string"]}\n'
                '<Enter> Return to Main Menu\n'
                'Q Quit'
            )

        if self.session_state == self.SessionState.BUY_SHARES_COMPANY_CODE:
            return (
                '## Buy Shares ##\n'
                'Enter the code for the company you wish\n'
                'to buy shares in:\n'
                'M Main Menu\n'
                'Q Quit'
            )

        if self.session_state == self.SessionState.BUY_SHARES_QUANTITY:
            return (
                '## Buy Shares ##\n'
                'Enter the number of shares in '
                f'{self.request_args["company_code"]}\n'
                'You would like to buy.\n'
                'M Main Menu\n'
                'Q Quit'
            )

        if self.session_state == self.SessionState.BUY_SHARES_SUCCESS:
            return (
                '## Buy Shares - Success ##\n'
                f'You now own {self.request_args["owned_shares"]} shares in '
                f'{self.request_args["company_code"]}\n'
                '<Enter> Return to Main Menu\n'
                'Q Quit'
            )

        if self.session_state == self.SessionState.VIEW_PORTFOLIO:
            return (
                '## View Portfolio ##\n'
                f'{self.request_args["portfolio_string"]}\n'
                '<Enter> Return to Main Menu\n'
                'Q Quit'
            )

        ######################### ADMIN STUFF ##################################
        if self.session_state == self.SessionState.ADVISOR_MENU:
            return (
                '## Financial Advisor Main Menu ##\n'
                'Q Quit'
            )
        if self.session_state == self.SessionState.ADMIN_MENU:
            return (
                '## Administrator Main Menu ##\n'
                '1 Create New User\n'
                '2 View Administrative Action Logs\n'
                'Q Quit'
            )
        if self.session_state == self.SessionState.ADMIN_LOG_MENU:
            return (
                '## Administrator - Admin Log Menu ##\n'
                '1 View All Administrative Logs\n'
                '2 View All Actions by a particular Admin\n'
                'M Main Menu\n'
                'Q Quit'
            )

        if self.session_state == self.SessionState.ADMIN_VIEW_ALL_LOGS:
            return (
                '## Administrator - View All Logs\n'
                f'{self.request_args["log_string"]}\n'
                '<Enter> Return to Main Menu\n'
                'Q Quit'
            )
        if self.session_state == self.SessionState.\
        ADMIN_VIEW_LOGS_BY_ADMIN_USERNAME:
            return (
                '## Administrator - View Logs by Admin\n'
                'Please enter the username of the admin you\'d\n'
                'like to view logs for.\n'
                'M Main Menu\n'
                'Q Quit'
            )
        if self.session_state == self.SessionState.\
        ADMIN_VIEW_LOGS_BY_ADMIN_RESULT:
            return (
                '## Administrator - View Logs For One Admin\n'
                f'{self.request_args["log_string"]}\n'
                '<Enter> Return to Main Menu\n'
                'Q Quit'
            )

        if self.session_state == self.SessionState.ADMIN_NEW_USER_TYPE:
            return (
                '## Administrator - Create User ##\n'
                'Please select a USER TYPE for the new account.\n'
                '1 System Administrator\n'
                '2 Financial Advisor\n'
                'M Main Menu\n'
                'Q Quit'
            )
        if self.session_state == self.SessionState.ADMIN_NEW_USER_USERNAME:
            return (
                '## Administrator - Create User ##\n'
                'Please enter the USERNAME for the new account.\n'
                'M Main Menu\n'
                'Q Quit'
            )
        if self.session_state == self.SessionState.ADMIN_NEW_USER_PASSWORD:
            return (
                '## Administrator - Create User ##\n'
                'Please enter the PASSWORD for the new account.\n'
                'M Main Menu\n'
                'Q Quit'
            )
        if self.session_state == self.SessionState.ADMIN_NEW_USER_SUCCESS:
            if self.request_args["type"] == DBUserType.CLIENT:
                return (
                    '## Administrator - User Creation Successful ##\n'
                    f'New CLIENT account {self.request_args["username"]}\
                    created.\n'
                    '<Enter> Main Menu\n'
                    'Q Quit'
                )
            if self.request_args["type"] == DBUserType.SYSTEM_ADMINISTRATOR:
                return (
                    '## Administrator - User Creation Successful ##\n'
                    f'New ADMIN account {self.request_args["username"]}'
                    ' created.\n'
                    '<Enter> Main Menu\n'
                    'Q Quit'
                )
            if self.request_args["type"] == DBUserType.FINANCIAL_ADVISOR:
                return (
                    '## Administrator - User Creation Successful ##\n'
                    f'New CLIENT account {self.request_args["username"]}'
                    ' created.\n'
                    '<Enter> Main Menu\n'
                    'Q Quit'
                )

        return ''

    # resetting the args if there's an error/invalid input during a user
    # process. Note that this means the user should be sent back to the start
    # of a process if they enter an invalid argument, which isn't the most
    # usable, but greatly simplifies the system and makes bugs less likely.
    def reset_error(self, message: str) -> str:
        self.error_message = self.ErrorMessage.VALID_INPUT
        # resetting request args after handling error.
        self.request_args = {}
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
        if self.error_message == self.ErrorMessage.NO_PASSWORD_GIVEN:
            return self.reset_error(
                '#! Invalid Input !#\n'
                'No password given.'
            )
        if self.error_message == self.ErrorMessage.NEW_USER_PASSWORD_TOO_SHORT:
            return self.reset_error(
                '#! Invalid Input !#\n'
                'Password too short, must be at least 10 characters.'
            )
        if self.error_message == self.ErrorMessage.NO_USERNAME_GIVEN:
            return self.reset_error(
                '#! Invalid Input !#\n'
                'No username given.'
            )

        if self.error_message == self.ErrorMessage.INVALID_CREDENTIALS:
            return self.reset_error(
                '#! Invalid Input !#\n'
                'Username or password were incorrect.'
            )
        if self.error_message == self.ErrorMessage.USER_DOESNT_EXIST:
            return self.reset_error(
                '#! Invalid Input !#\n'
                'No user exists with that username.'
            )
        if self.error_message == self.ErrorMessage.USER_NOT_ADMIN:
            return self.reset_error(
                '#! Invalid Input !#\n'
                'That user is not an admin.'
            )

        if self.error_message == self.ErrorMessage.INVALID_EMAIL_ADDRESS:
            return self.reset_error(
                '#! Invalid Input !#\n'
                'Invalid email address.'
            )

        if self.error_message == self.ErrorMessage.INVALID_COMPANY_CODE:
            return self.reset_error(
                '#! Invalid Input !#\n'
                'Invalid Company Code.'
            )
        if self.error_message == self.ErrorMessage.NOT_POSITIVE_INTEGER:
            return self.reset_error(
                '#! Invalid Input !#\n'
                'Not a positive integer.'
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
        self.request_args = {}
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
                database_queue = Queue()
                socket_worker_pool = [
                    Process(
                        target = ClientSession.handle_sessions,
                        args = (ssock, database_queue,)
                    )
                    for x in range(process_num)
                ]
                database_worker = Process(
                    target = Database.start_database,
                    args = (database_queue,)
                )
                database_worker.start()

                for worker in socket_worker_pool:
                    worker.daemon = True
                    worker.start()

                print("Listener started.")

                while True:
                    sleep(10)


        pass




if __name__ == "__main__":
    # write_secret_to_hsm("pepper", str(os.urandom(16).hex()))
    # gen_self_signed_cert()
    server = Server()
    server.start_server_loop(10)
