import os
from datetime import datetime
from uuid import uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    ForeignKey,
    String,
    TIMESTAMP,
    create_engine,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
import psycopg2
from psycopg2.errors import DuplicateDatabase
from psycopg2 import OperationalError

def create_database():
    """
    Connects to the default PostgreSQL database and creates a new database
    named 'zenithdrive' if it doesn't already exist.
    """
    
    conn = None
    try:
        conn = psycopg2.connect(#I WILL REPLACE THIS WITH ENVIRONMENT VARIABLES LATER
            dbname="postgres",
            user="postgres",
            password="root1234",
            host="localhost",
            port="5433"
        )

        conn.autocommit = True
        
        cursor = conn.cursor()
        
        sql_command = "CREATE DATABASE zenithdrive;"
        
        print("Attempting to create the database 'zenithdrive'...")
        cursor.execute(sql_command)
        print("Database 'zenithdrive' created successfully!")
        
    except DuplicateDatabase:
        print("Database 'zenithdrive' already exists. No action needed.")
    except Exception as e:
        print(f"An error occurred: {e}")
        print("Please check your username and password in the script.")
    finally:
        if conn:
            conn.close()


def check_db_connection():
    """
    Attempts to connect to the 'zenithdrive' database to verify
    the connection is working.
    """
    conn = None
    try:
        print("Attempting to connect to the 'zenithdrive' database...")
        conn = psycopg2.connect(
            dbname="zenithdrive",
            user="postgres",
            password="root1234",
            host="localhost",
            port="5433"
        )
        print("Database connection successful!")
        
    except OperationalError as e:
        print(f"Connection failed: {e}")
        print("\nPossible reasons for failure:")
        print("1. The database server is not running.")
        print("2. The database 'zenithdrive' does not exist.")
        print("3. The username or password in the script is incorrect.")
        print("Please check your database server status and credentials.")
        
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        
    finally:
        if conn:
            conn.close()
            print("Database connection closed.")

#I WILL ALSO REPLACE THIS WITH ENVIRONMENT VARIABLES LATER
DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://postgres:root1234@localhost:5433/zenithdrive"
)

engine = create_engine(DATABASE_URL)

Base = declarative_base()

class User(Base):
    """
    Represents the 'users' table in the PostgreSQL database.
    This table stores user profile information.
    """

    __tablename__ = "users"

    user_id = Column(
        UUID(as_uuid=True), primary_key=True, default=uuid4, unique=True
    )
    email = Column(String, unique=True, nullable=False)
    created_at = Column(
        TIMESTAMP, default=datetime.utcnow, nullable=False
    )
    cloud_services = relationship(
        "UserCloudService", back_populates="user", cascade="all, delete-orphan"
    )

    def __repr__(self):
        """Provides a user-friendly representation of the object."""
        return f"<User(email='{self.email}')>"


class UserCloudService(Base):
    """
    Represents the 'user_cloud_services' table.
    This table stores encrypted cloud service tokens and space metrics.
    """

    __tablename__ = "user_cloud_services"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, unique=True)
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.user_id"),
        nullable=False,
    )
    service_name = Column(String, nullable=False)
    access_token = Column(String, nullable=False)
    refresh_token = Column(String, nullable=False)
    token_expiry = Column(TIMESTAMP, nullable=False)
    total_space = Column(BigInteger, nullable=False)
    used_space = Column(BigInteger, nullable=False)
    is_active = Column(Boolean, default=True)

    user = relationship("User", back_populates="cloud_services")

    def __repr__(self):
        """Provides a user-friendly representation of the object."""
        return (
            f"<UserCloudService(user_id='{self.user_id}', "
            f"service_name='{self.service_name}')>"
        )


def create_db_tables():
    """
    Creates all tables defined in the Base class within the database.
    This function is useful for initial setup and development.
    """
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully.")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

if __name__ == "__main__":
    create_database()
    check_db_connection() #ONLY FOR NOW FOR CHECKING, WILL REMOVE LATER
    create_db_tables()