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
from sqlalchemy import String, Select, Time, Date, Float, BigInteger,\
ForeignKey, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql.sqltypes import LargeBinary
from sqlalchemy import Enum as SQLEnum

from typing import List
from typing import Optional
# Multiprocessing stuff
from multiprocessing.connection import Connection
from multiprocessing import Queue
# Cryptography stuff
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidKey
# HSM stuff
import server_HSM
import os
## misc
from enum import Enum
from uuid import uuid4 as uuid
import datetime
from prettytable import PrettyTable




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
    USER_CREDENTIALS_VALID_CLIENT = 4
    USER_CREDENTIALS_VALID_ADVISOR = 5
    USER_CREDENTIALS_VALID_ADMIN = 6
    USER_CREDENTIALS_INVALID = 7
    ADMIN_LOGIN_LOGGED_SUCCESSFULLY = 8
    USER_TYPE_VALID = 9
    USER_TYPE_INVALID = 10
    USER_EMAIL_SET = 11
    COMPANY_CODE_VALID = 12
    COMPANY_CODE_INVALID = 13
    BUY_SHARES_SUCCESS = 14

# Types of admin action. This is for the admin actions logging table.
class AdminAction(Enum):
    LOGIN = 0
    CREATE_NEW_ADMIN = 1
    CREATE_NEW_ADVISOR = 2
    CREATE_NEW_CLIENT = 3


class Database():
    class Base(DeclarativeBase):
        pass

    class User(Base):
        __tablename__ = "users"

        id: Mapped[int] = mapped_column(primary_key = True)
        username: Mapped[str] = mapped_column(String(60), unique=True)
        email: Mapped[Optional[bytes]] = mapped_column(LargeBinary)
        user_type: Mapped[UserType] = mapped_column(SQLEnum(UserType))
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
            memory_cost=2 * 1024 * 1024, # 2 Gib
            ad=None,
            secret=pepper,
        )

        password_bytes = kdf.derive(password.encode())

        new_user = self.User(
            username = username,
            user_type = user_type,
            password = password_bytes,
            password_salt = salt
        )

        with Session(self.engine) as session:
            session.add(new_user)
            session.commit()

    def check_if_user_exists(self, username: str):
        with Session(self.engine) as session:
            users = session.execute(Select(self.User)\
                .where(self.User.username.in_([username])))

            if len(users.all()) >= 1:
                return True
            return False

    def validate_user_credentials(self, username: str, password: str) -> bool:
        if self.check_if_user_exists(username) == False:
            return False
        with Session(self.engine) as session:
            user_list = session.execute(Select(
                self.User.password,
                self.User.password_salt
            )\
                .where(self.User.username.in_([username])))
            user = user_list.all()
            password_hash = user[0][0]
            salt = user[0][1]

            pepper = server_HSM.get_pepper()

            kdf = Argon2id(
                salt=salt,
                length=32,
                iterations=1,
                lanes=4,
                memory_cost=2 * 1024 * 1024, # 2 Gib
                ad=None,
                secret=pepper,
            )

            try:
                kdf.verify(
                    key_material = password.encode(),
                    expected_key = password_hash
                )
            except InvalidKey:
                return False
            else:
                return True

    def get_user_type(self, username: str) -> UserType:
        if self.check_if_user_exists(username) == False:
            raise Exception("User doesn't exist!")
        with Session(self.engine) as session:
            user_types_list = session.execute(
                Select(self.User.user_type)\
                .where(self.User.username.in_([username]))
            )
            # See https://docs.sqlalchemy.org/en/20/orm/queryguide/select.html#exists-forms-has-any
            # for why this next line has weird syntax.
            user_type = user_types_list.all()[0][0]
            return user_type

    def get_user_details_string(self, username: str) -> str:
        with Session(self.engine) as session:
            users = session.execute(Select(self.User).where(
                self.User.username.in_([username])
            ))

            table = PrettyTable(
                [
                    "USERNAME",
                    "EMAIL",
                ]
            )
            for user in users.scalars():
                if user.email == None:
                    table.add_row(
                        [
                            user.username,
                            user.email
                        ]
                    )
                else:
                    table.add_row(
                        [
                            user.username,
                            server_HSM.decrypt_and_verify_aes(user.email)\
                            .decode()
                        ]
                    )
            return table.get_string()

    def set_user_email(self, username: str, email: str):
        with Session(self.engine) as session:
            user = session.execute(
                Select(self.User).where(self.User.username.in_([username])
            )).scalar_one()
            user.email = server_HSM.encrypt_aes(email.encode())
            session.commit()

    class AdminLog(Base):
        __tablename__ = "admin_log"

        action_id: Mapped[int] = mapped_column(primary_key = True)
        action_type: Mapped[AdminAction] = mapped_column(SQLEnum(AdminAction))
        action_date: Mapped[datetime.date] = mapped_column(Date)
        action_time: Mapped[datetime.time] = mapped_column(Time)
        admin_username: Mapped[str] = mapped_column(String(60))
        target_user: Mapped[Optional[str]] = mapped_column(String(60))

    def log_admin_login(self, username: str):
        log = self.AdminLog(
            action_date = datetime.datetime.now().date(),
            action_time = datetime.datetime.now().time(),
            action_type = AdminAction.LOGIN,
            admin_username = username
        )

        with Session(self.engine) as session:
            session.add(log)
            session.commit()

    def log_new_admin_creation(self, creating_admin: str, new_admin: str):
        log = self.AdminLog(
            action_date = datetime.datetime.now().date(),
            action_time = datetime.datetime.now().time(),
            action_type = AdminAction.CREATE_NEW_ADMIN,
            admin_username = creating_admin,
            target_user = new_admin
        )

        with Session(self.engine) as session:
            session.add(log)
            session.commit()

    def log_new_advisor_creation(self, creating_admin: str, new_advisor: str):
        log = self.AdminLog(
            action_date = datetime.datetime.now().date(),
            action_time = datetime.datetime.now().time(),
            action_type = AdminAction.CREATE_NEW_ADVISOR,
            admin_username = creating_admin,
            target_user = new_advisor
        )

        with Session(self.engine) as session:
            session.add(log)
            session.commit()

    def get_admin_logs_string(
        self,
        admin : str = ""
    ):
        with Session(self.engine) as session:
            logs = session.execute(Select(self.AdminLog))

            table = PrettyTable(
                [
                    "ID",
                    "ACTION",
                    "DATE",
                    "TIME",
                    "ADMIN",
                    "TARGET USER"
                ]
            )
            if admin == "":
                for log in logs.scalars():
                    table.add_row(
                        [
                        str(log.action_id),
                        # So that it's not prefixed with AdminAction.
                        str(log.action_type).split(".")[1],
                        str(log.action_date),
                        str(log.action_time),
                        log.admin_username,
                        log.target_user
                        ]
                    )
            else:
                for log in logs.scalars():
                    if log.admin_username == admin:
                        table.add_row(
                            [
                            str(log.action_id),
                            # So that it's not prefixed with AdminAction.
                            str(log.action_type).split(".")[1],
                            str(log.action_date),
                            str(log.action_time),
                            log.admin_username,
                            log.target_user
                            ]
                        )


            return(table.get_string())

    class Company(Base):
        __tablename__ = "companies"

        company_code: Mapped[str] = mapped_column(String(4), primary_key = True)
        company_name: Mapped[str] = mapped_column(String(100), unique=True)
        share_price: Mapped[float] = mapped_column(Float)

    def get_companies_string(self) -> str:
        table = PrettyTable(
            [
                "CODE",
                "NAME",
                "SHARE PRICE"
            ]
        )

        with Session(self.engine) as session:
            companies = session.execute(Select(self.Company))

            for company in companies.scalars():
                table.add_row(
                    [
                        company.company_code,
                        company.company_name,
                        "{:.2f}".format(company.share_price)
                    ]
                )

        return table.get_string()

    def add_company(
        self,
        company_code: str,
        company_name: str,
        share_price: float,
    ):
        with Session(self.engine) as session:
            company = self.Company(
                company_code = company_code,
                company_name = company_name,
                share_price = share_price,
            )
            session.add(company)
            session.commit()

    def check_if_company_code_valid(
        self,
        company_code : str
    ):
        with Session(self.engine) as session:
            companies = session.execute(Select(self.Company))
            for company in companies.scalars():
                if company.company_code == company_code:
                    return True
        return False

    # There's some information leakage here, but the quantity of the investment
    # isn't stored in plain text.
    class ClientInvestments(Base):
        __tablename__ = "client_investments"

        username: Mapped[str] = mapped_column(
            ForeignKey("users.username"),
            primary_key = True)
        company_code: Mapped[str] = mapped_column(
            ForeignKey("companies.company_code"),
            primary_key = True
        )
        held_shares: Mapped[bytes] = mapped_column(
            LargeBinary
        )

    def buy_shares(
        self,
        username: str,
        company_code: str,
        shares: int
    ):
        with Session(self.engine) as session:
            try:
                investment = session.scalars(
                    select(self.ClientInvestments)
                    .where(self.ClientInvestments.username.in_([username]))
                    .where(self.ClientInvestments.company_code.in_([company_code]))
                ).one()
            except NoResultFound:
                new_investment = self.ClientInvestments(
                    username = username,
                    company_code = company_code,
                    held_shares = server_HSM.encrypt_aes(shares.to_bytes(10,
                        "big"))
                )
                session.add(new_investment)
                session.commit()
                return shares
            else:
                current_shares = server_HSM\
                .decrypt_and_verify_aes(investment.held_shares)
                new_shares = int.from_bytes(current_shares, "big") + shares
                investment.held_shares = server_HSM\
                .encrypt_aes(new_shares.to_bytes(10, "big"))
                session.commit()
                return new_shares

    def get_portfolio_string(self, username : str):
        with Session(self.engine) as session:
            investments = session.execute(Select(self.ClientInvestments)\
                .where(self.ClientInvestments.username.in_([username])))

            table = PrettyTable(
                [
                    "SHARES",
                    "COMPANY",
                ]
            )

            for investment in investments.scalars():
                table.add_row(
                    [
                        int.from_bytes(
                            server_HSM.decrypt_and_verify_aes(
                                investment.held_shares
                            )
                        ),
                        investment.company_code
                    ]
                )
            return table.get_string()










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
        if self.check_if_user_exists(request.username) == True:
            request.conn.send(RequestResponse.USER_EXISTS)
        else:
            request.conn.send(RequestResponse.USER_DOESNT_EXIST)
        request.conn.close()

    class DBRCreateNewUser(DatabaseRequest):
        def __init__(self,
            process_conn: Connection,
            username: str,
            user_type: UserType,
            password: str,
            admin: str = ""):
                super().__init__(process_conn)
                self.username = username
                self.user_type = user_type
                self.password = password
                self.admin = admin

    def handle_DBRCreateNewUser(self, request: DBRCreateNewUser):
        if self.check_if_user_exists(request.username) == True:
            request.conn.send(RequestResponse.CREATE_USER_USER_EXISTS)
            request.conn.close()
            return
        self.create_new_user(
            username = request.username,
            user_type = request.user_type,
            password = request.password,
            pepper = server_HSM.get_pepper()
        )

        if request.user_type == UserType.SYSTEM_ADMINISTRATOR and \
        request.admin != "":
            self.log_new_admin_creation(
                creating_admin = request.admin,
                new_admin = request.username
            )
        if request.user_type == UserType.FINANCIAL_ADVISOR and \
        request.admin != "":
            self.log_new_advisor_creation(
                creating_admin = request.admin,
                new_advisor = request.username
            )

        request.conn.send(RequestResponse.CREATE_USER_SUCCESSFUL)
        request.conn.close()


    class DBRCheckUserCredentials(DatabaseRequest):
        def __init__(
            self,
            process_conn: Connection,
            username: str,
            password: str
        ):
            super().__init__(process_conn)
            self.username = username
            self.password = password

    def handle_DBRCheckUserCredentials(self, request: DBRCheckUserCredentials):
        if self.validate_user_credentials(
            username = request.username,
            password = request.password
        ):
            user_type = self.get_user_type(request.username)
            if user_type == UserType.CLIENT:
                request.conn.send(RequestResponse.USER_CREDENTIALS_VALID_CLIENT)
                request.conn.close()
                return
            if user_type == UserType.FINANCIAL_ADVISOR:
                request.conn.send(RequestResponse.\
                    USER_CREDENTIALS_VALID_ADVISOR)
                request.conn.close()
                return
            if user_type == UserType.SYSTEM_ADMINISTRATOR:
                request.conn.send(RequestResponse.USER_CREDENTIALS_VALID_ADMIN)
                request.conn.close()
                return

        else:
            request.conn.send(RequestResponse.USER_CREDENTIALS_INVALID)
        request.conn.close()


    class DBRLogAdminLogin(DatabaseRequest):
        def __init__(
            self,
            process_conn: Connection,
            admin_username: str,
        ):
            super().__init__(process_conn)
            self.username = admin_username

    def handle_DBRLogAdminLogin(self, request: DBRLogAdminLogin):
        self.log_admin_login(request.username)
        request.conn.send(RequestResponse.ADMIN_LOGIN_LOGGED_SUCCESSFULLY)
        request.conn.close()

    class DBRGetAllAdminLogs(DatabaseRequest):
        def __init__(
            self,
            process_conn: Connection
        ):
            super().__init__(process_conn)

    # This breaks the convention of sending a RequestResponse object, because
    # it needs to be able to send data, not just status, back to the socket
    # process.
    def handle_DBRGetAllAdminLogs(self, request:DBRGetAllAdminLogs):
        string = self.get_admin_logs_string()
        request.conn.send(string)
        request.conn.close()

    class DBRGetLogsByAdmin(DatabaseRequest):
        def __init__(
            self,
            process_conn: Connection,
            admin_name: str
        ):
            super().__init__(process_conn)
            self.admin_name = admin_name

    def handle_DBRGetLogsByAdmin(self, request : DBRGetLogsByAdmin):
        string = self.get_admin_logs_string(request.admin_name)
        request.conn.send(string)
        request.conn.close()


    class DBRCheckUserType(DatabaseRequest):
        def __init__(
            self,
            process_conn: Connection,
            username: str,
            user_type: UserType
        ):
            super().__init__(process_conn)
            self.username = username
            self.user_type = user_type

    def handle_DBRCheckUserType(self, request: DBRCheckUserType):
        if self.get_user_type(request.username) != request.user_type:
            request.conn.send(RequestResponse.USER_TYPE_INVALID)
        else:
            request.conn.send(RequestResponse.USER_TYPE_VALID)
        request.conn.close()

    class DBRGetClientAccountDetails(DatabaseRequest):
        def __init__(
            self,
            process_conn: Connection,
            username: str
        ):
            super().__init__(process_conn)
            self.username = username

    def handle_DBRGetClientAccountDetails(
        self,
        request: DBRGetClientAccountDetails
    ):
        if self.get_user_type(request.username) != UserType.CLIENT:
            request.conn.send(RequestResponse.USER_TYPE_INVALID)
            request.conn.close()
            return
        request.conn.send(self.get_user_details_string(
            request.username
        ))
        request.conn.close()

    class DBRSetClientEmail(DatabaseRequest):
        def __init__(
            self,
            process_conn: Connection,
            username: str,
            email: str
        ):
            super().__init__(process_conn)
            self.username = username
            self.email = email

    def handle_DBRSetClientEmail(self, request: DBRSetClientEmail):
        self.set_user_email(
            username = request.username,
            email = request.email
        )
        request.conn.send(RequestResponse.USER_EMAIL_SET)
        request.conn.close()
        return

    class DBRGetCompanyString(DatabaseRequest):
        def __init__(self, process_conn : Connection):
            super().__init__(process_conn)

    def handle_DBRGetCompanyString(self, request: DBRGetCompanyString):
        request.conn.send(self.get_companies_string())
        request.conn.close()

    class DBRCheckCompanyCodeValid(DatabaseRequest):
        def __init__(self, process_conn : Connection, company_code : str):
            super().__init__(process_conn)
            self.company_code = company_code

    def handle_DBRCheckCompanyCodeValid(
        self,
        request: DBRCheckCompanyCodeValid
    ):
        if self.check_if_company_code_valid(request.company_code):
            request.conn.send(RequestResponse.COMPANY_CODE_VALID)
        else:
            request.conn.send(RequestResponse.COMPANY_CODE_INVALID)
        request.conn.close()

    class DBRBuyShares(DatabaseRequest):
        def __init__(self, process_conn: Connection,
            username : str,
            company_code: str,
            shares: int
            ):
                super().__init__(process_conn)
                self.username = username
                self.company_code = company_code
                self.shares = shares

    def handle_DBRBuyShares(self, request: DBRBuyShares):
        owned_shares = self.buy_shares(
            request.username,
            request.company_code,
            request.shares
        )
        request.conn.send(owned_shares)
        request.conn.close()

    class DBRGetPortfolio(DatabaseRequest):
        def __init__(self, process_conn: Connection, username: str):
            super().__init__(process_conn)
            self.username = username

    def handle_DBRGetPortfolio(self, request: DBRGetPortfolio):
        request.conn.send(
            self.get_portfolio_string(
                request.username
            )
        )
        request.conn.close()








    def handle_request(self, request: DatabaseRequest):
        if isinstance(request, self.DBRDoesUserExist):
            self.handle_DBRDoesUserExist(request)
            return
        if isinstance(request, self.DBRCreateNewUser):
            self.handle_DBRCreateNewUser(request)
            return
        if isinstance(request, self.DBRCheckUserCredentials):
            self.handle_DBRCheckUserCredentials(request)
            return
        if isinstance(request, self.DBRLogAdminLogin):
            self.handle_DBRLogAdminLogin(request)
            return
        if isinstance(request, self.DBRGetAllAdminLogs):
            self.handle_DBRGetAllAdminLogs(request)
            return
        if isinstance(request, self.DBRCheckUserType):
            self.handle_DBRCheckUserType(request)
            return
        if isinstance(request, self.DBRGetLogsByAdmin):
            self.handle_DBRGetLogsByAdmin(request)
            return
        if isinstance(request, self.DBRGetClientAccountDetails):
            self.handle_DBRGetClientAccountDetails(request)
            return
        if isinstance(request, self.DBRSetClientEmail):
            self.handle_DBRSetClientEmail(request)
            return
        if isinstance(request, self.DBRGetCompanyString):
            self.handle_DBRGetCompanyString(request)
            return
        if isinstance(request, self.DBRCheckCompanyCodeValid):
            self.handle_DBRCheckCompanyCodeValid(request)
            return
        if isinstance(request, self.DBRBuyShares):
            self.handle_DBRBuyShares(request)
            return
        if isinstance(request, self.DBRGetPortfolio):
            self.handle_DBRGetPortfolio(request)
            return

    # A method to populate the database with initial data.
    def populate_database(self):
            print('Populating database...')
            self.create_new_user(
                username = "admin",
                user_type = UserType.SYSTEM_ADMINISTRATOR,
                password = "password123",
                pepper = server_HSM.get_pepper()
            )
            self.create_new_user(
                username = "test_adv",
                user_type = UserType.FINANCIAL_ADVISOR,
                password = "advisor123",
                pepper = server_HSM.get_pepper()
            )
            self.create_new_user(
                username = "dave",
                user_type = UserType.CLIENT,
                password = "daveiscool",
                pepper = server_HSM.get_pepper()
            )
            self.add_company(
                company_code = "WMG",
                company_name = "Warwick Manufacturing Group",
                share_price = 20.10,
            )
            self.add_company(
                company_code = "HRJ",
                company_name = "Harj Enterprises Inc.",
                share_price = 120.12,
            )
            print('Done.')

    @staticmethod
    def start_database(queue: Queue):
        print("DB worker started")
        database = Database(queue = queue)
        database.populate_database()
        while True:
            request = database.queue.get()
            database.handle_request(request)



    def __init__(self, queue: Queue):
        # Using an in-memory database as it's much easier to test with. If
        # I were writing this as a professional project, I'd use PostgreSQL.
        self.engine = sql.create_engine("sqlite+pysqlite:///:memory:", echo=True)
        self.Base.metadata.create_all(self.engine)
        self.queue = queue
