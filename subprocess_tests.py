######################### SUBPROCESS TESTS #####################################
# These are tests which are much easier to run in a sub-process. Since I'm using
# pytest for test management, it's much easier to put these functions in a
# seperate file and call them from the main test script, rather than pytest
# trying to call them as normal test functions.

# For these functions, the name of the desired test function is passed as an
# argument, and the program will exit with a status code of 0 for a successful
# test, and 1 if not.

# I'm using a tst_*() naming convention so that pytest doesn't call these
# functions automatically


## imports (functionality, not functions to test)
import sys

## imports (functions to test)
from client import check_if_in_venv

# should return True if the process is in a venv, false otherwise.
def tst_if_in_venv():
    return check_if_in_venv(test = True)


if __name__ == '__main__':
    if sys.argv == ['tst_if_in_venv']:
        if tst_if_in_venv():
            sys.exit()
