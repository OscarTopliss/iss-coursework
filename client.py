import server
# imports
import subprocess # used for calling pip from the command line
import sys
from subprocess import CalledProcessError
import socket
import ssl


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
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_verify_locations(
        "./shared-certificates/root-certificate.pem"
    )
    server_hostname = "localhost"
    server_port = 1324

    server_socket = None

    def connect_to_server(self):
        with socket.create_connection(
            (self.server_hostname, self.server_port)
        ) as sock:
            ssock = self.ssl_context.wrap_socket(sock,
                server_hostname=self.server_hostname)
            self.server_socket = ssock



    def send_to_server(self, message: str):
        pass

    def recv_from_server(self) -> bytes:
        pass
        return b''

    def start_menu(self):
        option = input("""
            MyFinance Inc.
            1. Connect to MyFinance
            2. Quit""")
        if option == "1":
            print("connecting...")
            return
        if option == "2":
            print("Quitting...")
            return
        print(f"Invalid option: {option}")



    def start_client(self):
        while True:
            self.start_menu()



# entry point
if __name__ == "__main__":
    pre_run_checks()
    client = Client()
