######################### SERVER DATABASE ######################################
# This file contains the server database class, which is used to create and
# interact with the in-memory database which houses any data for the server
# which isn't stored in the HSM. I split it off mainly for the sake of space,
# as it'd make the server.py script much longer than it needs to be.

# The format will be:
#   Class
#   method
#   method
# e.g. classes will be used to define tables within the database, and methods
# used to query/create entries/interact with that table will be defined under
# that class.


## Imports
# Database stuff
import sqlalchemy as sql
from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session
from sqlalchemy.sql.sqltypes import LargeBinary

from typing import List
from typing import Optional
# Multiprocessing stuff
from multiprocessing.connection import Connection
# Cryptography stuff
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
import os
## misc
from enum import Enum
from uuid import uuid4 as uuid





class Database():
    class Base(DeclarativeBase):
        pass

    class User(Base):
        __tablename__ = "users"

        id: Mapped[int] = mapped_column(primary_key = True)
        username: Mapped[str] = mapped_column(String(60), unique=True)
        password: Mapped[bytes]  = mapped_column(LargeBinary)
        password_salt: Mapped[bytes] = mapped_column(LargeBinary)

    def create_new_user(self, username: str, password: str, pepper: bytes):
        salt = os.urandom(16)
        # Using the standard recommended parameters as shown here:
        # https://datatracker.ietf.org/doc/html/rfc9106#section-4
        # Usage based on docs:
        # https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/
        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=1,
            lanes=4,
            memory_cost=2 * 1024 * (2 ** 1024), # 2 Gib
            ad=None,
            secret=pepper,
        )

        password_bytes = kdf.derive(password.encode())

        new_user = self.User(
            username = username,
            password = password_bytes,
            password_salt = salt
        )

        with Session(self.engine) as session:
            session.add(new_user)
            session.commit()


    ## Database Request and response classes
    # used to communicate asynchronously with the database process.
    # Database requests are named in the format DBRRequestName.

    # It's the responsibility of the database process to check if a request is
    # valid (i.e., not creating a new user with the same username as another)

    # It's the responsibilty of the **socket** process to send valid data, i.e.
    # the correct data type, as taken from the user.

    # The base class, accepts
    class DatabaseRequest():
        def __init__(self, process_conn: Connection):
            self.conn = process_conn


    class DBRUserExists(DatabaseRequest):
        def __init__(self, process_conn: Connection, username: str):
            with Session(self.engine) as session:










    def __init__(self):
        # Using an in-memory database as it's much easier to test with. If
        # I were writing this as a professional project, I'd use PostgreSQL.
        self.engine = sql.create_engine("sqlite+pysqlite:///:memory:", echo=True)
        self.Base.metadata.create_all(self.engine)
