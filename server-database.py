######################### SERVER DATABASE ######################################
# This file contains the server database class, which is used to create and
# interact with the in-memory database which houses any data for the server
# which isn't stored in the HSM. I split it off mainly for the sake of space,
# as it'd make the server.py script much longer than it needs to be.


## Imports
import sqlalchemy as sql
from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.sql.sqltypes import LargeBinary

from typing import List
from typing import Optional



class Database():
    class Base(DeclarativeBase):
        pass

    class User(Base):
        __tablename__ = "users"

        id: Mapped[int] = mapped_column(primary_key = True)
        username: Mapped[str] = mapped_column(String(60))
        password: Mapped[bytes]  = mapped_column(LargeBinary)
        password_salt: Mapped[bytes] = mapped_column(LargeBinary)
