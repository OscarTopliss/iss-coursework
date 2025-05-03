######################### TESTS FOR CLIENT PROGRAM #############################
# Note: tests expect a linux environment.

## Imports (for functionality, not functions to test.)
import subprocess
import sys
import pytest

## Importing functions to test
from client import Client
from server import Server

class TestSockets:
    def test_client_connect_and_send():
        server = Server()
        client = Client()

        server.start_server_loop(5)

        client.connect_to_server()

        client.send_to_server("Hello World!")

        message = server.recv_client_message(0)

        assert message == b'Hello World!'
