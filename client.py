import server
# imports
import subprocess # used for calling pip from the command line
import sys
from subprocess import CalledProcessError
import socket
import ssl
from enum import Enum
from errno import EWOULDBLOCK
import json


######################### Pre-run checks #######################################

# Checks if the program is being run in a virtual environment.
# If the program is not being run in a venv, prints a help message and exits.
def check_if_in_venv(test = False):
    if sys.prefix == sys.base_prefix:
        # Checks if the program is being run in a venv:
        # https://docs.python.org/3/library/venv.html#how-venvs-work
        print("""
            MyFinance needs to be run in a virtual environment!

            please enter the following and try again:
                Linux:
                    source ./venv/bin/activate
                Windows (cmd):
                    .venv\\Scripts\\Activate.bat
                Windows (PowerShell):
                    .venv\\Scripts\\Activate.ps1""")
        if test == True:
            return False
        sys.exit()
    return True

# Checks if there are any updates available, returns true
def check_for_updates() -> bool:
    print("Checking for updates...")
    try:
        upgradeable_packages = subprocess.check_output(
            ["pip",
            "list",
            "--outdated",
            "--require-virtualenv",
            "--local"]
        )
        if upgradeable_packages != b'':
            return True
        print("System up-to-date.")
        return False
    except subprocess.CalledProcessError:
        print("Error! check for update failed :(")
        sys.exit()

# Runs pip from the command line as a sub-process to install any modules which
# need updating, then exits the program and prompts the user to restart it.
# This is a cleaner and easier way of doing it than trying to restart the
# program from within itself.
def install_updates():
    try:
        subprocess.check_call(
            ["pip",
            "install",
            "-r",
            "requirements.txt",
            "--require-virtualenv",
            "--upgrade",
            "--progress-bar=raw"]
        )
    except CalledProcessError:
        print("Error! Updating packages failed :(")
    else:
        print("Packages have been updated, please restart MyFinance")
        sys.exit()



def pre_run_checks():
    check_if_in_venv()

    if check_for_updates():
        install_updates()



    # Checking if packages are up to date
    # If upgradeable_packages = b'', all packages are up-to-date.

class Client:
    class MessageCode(Enum):
        OPEN = 1
        CLOSED = 2
        ERROR = 3

    ssl_context = ssl.create_default_context()
    ssl_context.load_verify_locations(
        "./shared-certificates/root-certificate.pem"
    )
    ssl_context.check_hostname = False
    server_hostname = "127.0.0.1"
    server_port = 1324


    # Messages are simple JSON objects (i.e. only string attributes, no
    # nested objects). This means that using recv(), once the total message
    # is a valid JSON object, you know you've received the full message and
    # can stop using blocking recv() calls.
    def recv_message(self) -> tuple[bytes, MessageCode]:
        message = b''
        valid_message = False
        while not valid_message:
            new_data = self.server_socket.recv(1024)
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
    def handle_message(self, message: tuple[bytes, MessageCode]) -> bool:
        if message[1] == self.MessageCode.ERROR:
            print("""Error in server connection! Connection closed.
                Thank you for using MyFinance.""")
            return False
        if message[1] == self.MessageCode.CLOSED:
            print("Session Closed. Thank you for using MyFinance")
            return False
        message_json = json.loads(message[0].decode())
        print(message_json["message"])
        return True





    def client_session_loop(self):
        while True:
            (message, code) = self.recv_message()
            if not self.handle_message((message, code)):
                break

            response = input("> ")
            if response.lower() == "q":
                print("Thank you for using MyFinance.")
                self.server_socket.close()
                sys.exit(0)
            response_json = json.dumps({'message': response})
            self.server_socket.sendall(response_json.encode())





    def connect_to_server(self) -> bool:
        try:
        # Based on this:
        # https://docs.python.org/3/library/ssl.html#socket-creation
            context = self.ssl_context
            sock = socket.create_connection(
                ("localhost", 1234)
            )
            ssock = context.wrap_socket(
                sock
            )
            self.server_socket = ssock
        except ConnectionRefusedError:
            print("\nError: Connection Failed, please try again.\n")
            return False
        else:
            print("Connected.")
            return True



    def send_to_server(self, message: str):
        pass

    def recv_from_server(self) -> bytes:
        return b''

    def start_menu(self):
        option = input(
"""MyFinance Inc.
1 Connect to MyFinance
Q Quit
> """)
        if option == "1":
            print("connecting...")
            if self.connect_to_server():
                self.client_session_loop()
                self.server_socket.close()
            return
        if option.upper() == "Q":
            print("Quitting...")
            sys.exit()
            return
        print(f"\nInvalid option: {option}\n")



    def client_start_menu_loop(self):
        while True:
            self.start_menu()



# entry point
if __name__ == "__main__":
    #pre_run_checks()
    client = Client()
    client.client_start_menu_loop()
