######################### TESTS FOR CLIENT PROGRAM #############################
# Note: tests expect a linux environment.

## Imports (for functionality, not functions to test.)
import subprocess
import sys
import pytest

## Importing functions to test
from client import (
    check_if_in_venv,
    check_for_updates,
    install_updates,
    pre_run_checks
)

# Runs a sub-process test. If the sub-process returns 0, the test succeeded,
# if it returns 1, the test failed. Any other return code shouldn't be possible,
# and will prompt this function to print an error and kill the script.
def subprocess_tst(test_name : str, previous_command : list[str] = []) -> bool:
    try:
        subprocess.run(previous_command + ['python3', 'subprocess_tests.py', test_name])
    except subprocess.CalledProcessError as error:

        # This means the test failed.
        if error.returncode == 1:
            return False
        else:
            print("Error! Unknown return code, subprocess test failed to run \
                properly!")
            sys.exit()
    else:
        return True




def test_check_if_in_venv():
    # testing that venv detection can detect when the program **is not** being
    # run in a venv
    assert subprocess_tst(
        test_name = "tst_if_in_venv",
        previous_command = ['deactivate', ';']
    ) == False

    # testing that venv detection can detect when the program **is** being
    # run in a venv
    assert subprocess_tst(
        test_name = "tst_if_in_venv",
        previous_command = ['source', '.venv/bin/activate' ';']
    ) == True
