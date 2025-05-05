import server
# imports
import subprocess # used for calling pip from the command line
import sys
from subprocess import CalledProcessError
import socket
import ssl
from enum import Enum
from errno import EWOULDBLOCK


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


    def recv_message(self) -> tuple[bytes, MessageCode]:
        message = b''
        while True:
            try:
                message += self.server_socket.recv(1024)
            # Logic to see if there's an actual error, or if it's throwing an
            # exception because the socket is in non-blocking mode.
            except socket.error as error:
                if error.errno != EWOULDBLOCK:
                    return (message, self.MessageCode.ERROR)
                if message == b'':
                    return (message, self.MessageCode.CLOSED)
                return (message, self.MessageCode.OPEN)
            except:
                return (message, self.MessageCode.ERROR)


    def client_session_loop(self):
        while True:
            message = self.recv_message()
            print(f"{message[0]!r}")
            response = input("> ")
            if response.lower() == "q":
                print("Thank you for using MyFinance.")
                self.server_socket.close()
                sys.exit(0)
            self.server_socket.sendall(response.encode())





    def connect_to_server(self):
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
            self.server_socket.setblocking(False)
        except ConnectionRefusedError as error:
            print("\nError: Connection Failed.\n")
        else:
            print("Connected.")



    def send_to_server(self, message: str):
        pass

    def recv_from_server(self) -> bytes:
        return b''

    def start_menu(self):
        option = input(
"""MyFinance Inc.
1. Connect to MyFinance
2. Quit
>""")
        if option == "1":
            print("connecting...")
            self.connect_to_server()
            self.client_session_loop()
            return
        if option == "2":
            print("Quitting...")
            sys.exit()
            return
        print(f"\nInvalid option: {option}\n")



    def client_start_menu_loop(self):
        while True:
            self.start_menu()



# entry point
if __name__ == "__main__":
    pre_run_checks()
    client = Client()
    client.client_start_menu_loop()
