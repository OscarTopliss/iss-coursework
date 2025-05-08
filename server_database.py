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
from sqlalchemy import String, Select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session
from sqlalchemy.sql.sqltypes import LargeBinary
from sqlalchemy import Enum as SQLEnum

from typing import List
from typing import Optional
# Multiprocessing stuff
from multiprocessing.connection import Connection
from multiprocessing import Queue
# Cryptography stuff
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
# HSM stuff
import server_HSM
import os
## misc
from enum import Enum
from uuid import uuid4 as uuid




class UserType(Enum):
    CLIENT = 0
    FINANCIAL_ADVISOR = 1
    SYSTEM_ADMINISTRATOR = 2

# Enum for the response of success/fail requests. Passed through to the
# requesting worker process via a pipe.
class RequestResponse(Enum):
    USER_EXISTS = 0
    USER_DOESNT_EXIST = 1
    CREATE_USER_SUCCESSFUL = 2
    CREATE_USER_USER_EXISTS = 3


class Database():
    class Base(DeclarativeBase):
        pass

    class User(Base):
        __tablename__ = "users"

        id: Mapped[int] = mapped_column(primary_key = True)
        username: Mapped[str] = mapped_column(String(60), unique=True)
        user_type: Mapped[UserType] = mapped_column(SQLEnum)
        password: Mapped[bytes]  = mapped_column(LargeBinary)
        password_salt: Mapped[bytes] = mapped_column(LargeBinary)

    def create_new_user(self,
        username: str,
        user_type: UserType,
        password: str,
        pepper: bytes
    ):
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

    def check_if_user_exists(self, username: str):
        with Session(self.engine) as session:
            users = Select(self.User)\
            .where(self.User.username.in_([request.username]))
            if len(session.scalars(users).all()) >= 1:
                return True
            return False



    ## Database Request and response classes
    # used to communicate asynchronously with the database process.
    # Database requests are named in the format DBRRequestName.

    # Each DBR class is associated with a handler method in the parent Database
    # class, which enables access to the engine for querying data.

    # It's the responsibility of the database process to check the validity of
    # the **request**, i.e., checking if a user exists before creating a new
    # user.

    # It's the responsibility of the socket process to check the validity of the
    # **data**, i.e. checking that the username is 60 characters or fewer.

    # The base class for database requests. accepts a **connection** object,
    # which greatly simplifies passing the result of the request back to the
    # worker process which made it.
    class DatabaseRequest():
        def __init__(self, process_conn: Connection):
            self.conn = process_conn


    class DBRDoesUserExist(DatabaseRequest):
        def __init__(self, process_conn: Connection, username: str):
            super().__init__(process_conn)
            self.username = username

    def handle_DBRDoesUserExist(self, request: DBRDoesUserExist):
        self.check_if_user_exists(request.username)

    class DBRCreateNewUser(DatabaseRequest):
        def __init__(self,
            process_conn: Connection,
            username: str,
            user_type: UserType,
            password: str):
                super().__init__(process_conn)
                self.username = username
                self.user_type = user_type
                self.password = password

    def handle_DBRCreateNewUser(self, request: DBRCreateNewUser):
        if self.check_if_user_exists(request.username) == False:
            request.conn.send(RequestResponse.CREATE_USER_USER_EXISTS)
            request.conn.close()
            return
        self.create_new_user(
            username = request.username,
            user_type = request.user_type,
            password = request.password,
            pepper = server_HSM.get_pepper()
        )
        request.conn.send(RequestResponse.CREATE_USER_SUCCESSFUL)
        request.conn.close()







    def handle_request(self, request: DatabaseRequest):
        if isinstance(request, self.DBRDoesUserExist):
            self.handle_DBRDoesUserExist(request)
            return
        if isinstance(request, self.DBRCreateNewUser):
            self.handle_DBRCreateNewUser(request)
            return



    @staticmethod
    def start_database(queue: Queue):
        database = Database(queue = queue)
        while True:
            request = database.queue.get()
            database.handle_request(request)



    def __init__(self, queue: Queue):
        # Using an in-memory database as it's much easier to test with. If
        # I were writing this as a professional project, I'd use PostgreSQL.
        self.engine = sql.create_engine("sqlite+pysqlite:///:memory:", echo=True)
        self.Base.metadata.create_all(self.engine)
        self.queue = queue
