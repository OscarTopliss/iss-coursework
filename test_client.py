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
def subprocess_tst(test_name : str, previous_command : str = "") -> bool:
    try:
        result =  subprocess.check_output(
            previous_command + 'python3 subprocess_tests.py ' + test_name,
            shell=True)

        print(result.strip())

        if result.strip() == b'True':
            return True
        elif result.strip() == b'False':
            return False
        else:
            print("Error! Unknown output from subprocess test")
            sys.exit(1)


    except subprocess.CalledProcessError:
        # This means the test failed to execute.
        print("Error! Subprocess test failed to run \
                properly!")



# Checks if check_if_in_venv() behaves as expected when called from outside of
# a venv.
def test_if_detect_not_in_venv():
    # testing that venv detection can detect when the program **is not** being
    # run in a venv
    print(subprocess.check_output("source .venv/bin/activate ; deactivate ; which python3", shell=True))
    assert subprocess_tst(
        test_name = "tst_if_in_venv",
        previous_command = 'source .venv/bin/activate ; deactivate ;'
    ) == False

# Checks if check_if_in_venv() behaves as expected when called from inside of a
# a venv.
def test_if_detect_in_venv():
    # testing that venv detection can detect when the program **is** being
    # run in a venv
    assert subprocess_tst(
        test_name = "tst_if_in_venv",
        previous_command = 'source .venv/bin/ ;'
    ) == True
