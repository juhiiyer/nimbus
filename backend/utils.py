import os
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables from backend/.env
load_dotenv(dotenv_path=Path(__file__).resolve().parent / '.env')

# Security configuration (must come from environment only)
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
FERNET_KEY_ENV = os.getenv("FERNET_KEY")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is not set. Add it to backend/.env")
if not FERNET_KEY_ENV:
    raise RuntimeError("FERNET_KEY is not set. Generate one with Fernet.generate_key() and add to backend/.env")

FERNET_KEY = FERNET_KEY_ENV.encode()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# Fernet cipher for token encryption
cipher_suite = Fernet(FERNET_KEY)

def verify_password(plain_password, hashed_password):
    """Verify a password against a hash"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """Hash a password"""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    """Create a JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def encrypt_token(token: str):
    """Encrypt a cloud service token before storing in database"""
    return cipher_suite.encrypt(token.encode()).decode()

def decrypt_token(encrypted_token: str):
    """Decrypt a cloud service token from database"""
    return cipher_suite.decrypt(encrypted_token.encode()).decode()

def validate_token_expiry(expiry_time):
    """Check if a token is expired"""
    return datetime.utcnow() < expiry_time