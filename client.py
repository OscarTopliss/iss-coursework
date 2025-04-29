from itertools import batched
# imports
import subprocess # used for calling pip from the command line
import sys



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

    try:
        subprocess.check_call("")
    except:
        pass
