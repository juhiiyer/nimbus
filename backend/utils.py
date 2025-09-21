import os
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# shriya: Replace with a strong secret key for JWT
SECRET_KEY = os.getenv("SECRET_KEY", "d10485f77dc22f1c6bcfac290a51297d63a8d2f9f736f6efa02bef33d5ae33cb")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# shriya: Generate a key with Fernet.generate_key() and replace this
FERNET_KEY = os.getenv("FERNET_KEY", "Pv1cUqRu61maqc1cKFOxrBXwok9SRe6IpdCVZmHoKlI=").encode()

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