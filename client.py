# imports
import subprocess # used for calling pip from the command line
import sys
from subprocess import CalledProcessError



if __name__ == "__main__":
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
        sys.exit()

    # Checking if packages are up to date
    try:
        upgradeable_packages = subprocess.check_output(
            ["pip",
            "list",
            "--outdated",
            "--require-virtualenv",
            "--local"]
        )
        # If upgradeable_packages = b'', all packages are up-to-date.
        if upgradeable_packages != b'':

            # If there are packets to upgrade, upgrade them and prompt the user
            # to restart. This way is cleaner than restarting the script
            # programatically.
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

    except subprocess.CalledProcessError:
        print("Error! check for update failed :(")
        sys.exit()
