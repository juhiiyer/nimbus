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
import psycopg
from psycopg import OperationalError
from psycopg.errors import DuplicateDatabase
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def create_database():
    """
    Optional helper for local dev. Uses env vars only; does NOT hardcode credentials.
    Set DB_HOST, DB_PORT, DB_USER, DB_PASSWORD and DB_NAME before using.
    """
    db_host = os.getenv("DB_HOST")
    db_port = os.getenv("DB_PORT")
    db_user = os.getenv("DB_USER")
    db_password = os.getenv("DB_PASSWORD")
    db_name = os.getenv("DB_NAME")
    if not all([db_host, db_port, db_user, db_password, db_name]):
        print("[create_database] Skipping: DB_* env vars not fully set.")
        return
    conn = None
    try:
        conn = psycopg.connect(dbname="postgres", user=db_user, password=db_password, host=db_host, port=db_port)
        conn.autocommit = True
        with conn.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE {db_name};")
            print(f"Database '{db_name}' created successfully!")
    except DuplicateDatabase:
        print(f"Database '{db_name}' already exists. No action needed.")
    except Exception as e:
        print(f"[create_database] Error: {e}")
    finally:
        if conn:
            conn.close()

def check_db_connection():
    """Optional helper to quickly test DB connectivity using DB_* env vars."""
    db_host = os.getenv("DB_HOST")
    db_port = os.getenv("DB_PORT")
    db_user = os.getenv("DB_USER")
    db_password = os.getenv("DB_PASSWORD")
    db_name = os.getenv("DB_NAME")
    if not all([db_host, db_port, db_user, db_password, db_name]):
        print("[check_db_connection] Skipping: DB_* env vars not fully set.")
        return
    conn = None
    try:
        print(f"Attempting to connect to '{db_name}'...")
        conn = psycopg.connect(dbname=db_name, user=db_user, password=db_password, host=db_host, port=db_port)
        print("Database connection successful!")
    except OperationalError as e:
        print(f"Connection failed: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        if conn:
            conn.close()
            print("Database connection closed.")

# Read DATABASE_URL only from environment (no hardcoded credentials)
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set. Add it to backend/.env")

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
    hashed_password = Column(String, nullable=True)  # Allow null for OAuth users
    created_at = Column(
        TIMESTAMP, default=datetime.utcnow, nullable=False
    )
    cloud_services = relationship(
        "UserCloudService", back_populates="user", cascade="all, delete-orphan"
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

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

if __name__ == "__main__":
    create_database()
    check_db_connection()
    create_db_tables()