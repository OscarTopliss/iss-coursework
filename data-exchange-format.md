# Data exchange format
The data exchange format between client and server will be simple
Json objects, which contain string values for the inputs a user gives.

This solves a number of problems.


Firstly, because there is only one object without nested objects,
verifying that a received message is a valid JSON object is an easy way to
verify that the client/server has received an entire message.

JSON is also build into the Pyton standard library, is easily serialisable,
and provides simple mechanisms for decoding a serialised JSON string into
what's effectively a dictionary. Creates a very efficient method of passing
values back and fourth between the client program and the server.

The JSON stuff is largely based on this tutorial:
https://labex.io/tutorials/python-how-to-handle-data-serialization-in-python-socket-programming-398000

In order to make the client-side logic as agnostic as possible, I'm only
allowing one input per message.
